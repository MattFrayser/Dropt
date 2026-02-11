//! Lock-free transfer progress tracking for TUI snapshots.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::common::{FileProgress, FileStatus, TransferProgress};

struct FileState {
    names: Vec<String>,
    total_chunks: Vec<u64>,
    done_chunks: Vec<AtomicU64>,
    completed: Vec<AtomicBool>,
    errors: Mutex<Vec<(usize, String)>>,
}

/// Lock-free progress tracker using atomics.
/// File metadata is set once via `init_files()` (backed by OnceLock),
/// The TUI calls `snapshot()` on its render tick to build display data.
pub struct ProgressTracker {
    file_state: OnceLock<FileState>,
    files_completed: AtomicU64,
    files_total: AtomicU64,
    total_chunks: AtomicU64,
    completed_chunks: AtomicU64,
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressTracker {
    /// Create an empty progress tracker.
    pub fn new() -> Self {
        Self {
            file_state: OnceLock::new(),
            files_completed: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            total_chunks: AtomicU64::new(0),
            completed_chunks: AtomicU64::new(0),
        }
    }

    /// Initialize per-file names and expected chunk totals.
    /// Must be called before any increment_file/file_complete calls.
    pub fn init_files(&self, names: Vec<String>, chunk_totals: Vec<u64>) {
        let total: u64 = chunk_totals.iter().sum();
        self.files_total
            .store(names.len() as u64, Ordering::Relaxed);
        self.total_chunks.store(total, Ordering::Relaxed);

        let count = chunk_totals.len();
        let done_chunks = (0..count).map(|_| AtomicU64::new(0)).collect();
        let completed = (0..count).map(|_| AtomicBool::new(false)).collect();
        let _ = self.file_state.set(FileState {
            names,
            total_chunks: chunk_totals,
            done_chunks,
            completed,
            errors: Mutex::new(Vec::new()),
        });
    }

    /// Record one completed chunk for a file.
    pub fn increment_file(&self, file_index: usize) {
        if let Some(fs) = self.file_state.get() {
            if file_index < fs.done_chunks.len() {
                self.completed_chunks.fetch_add(1, Ordering::Relaxed);
                fs.done_chunks[file_index].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Called when a file transfer is fully complete.
    /// Idempotent — repeated calls for the same file_index are no-ops.
    pub fn file_complete(&self, file_index: usize) {
        if let Some(fs) = self.file_state.get() {
            if file_index < fs.completed.len()
                && !fs.completed[file_index].swap(true, Ordering::AcqRel)
            {
                self.files_completed.fetch_add(1, Ordering::Relaxed);
                fs.done_chunks[file_index].store(fs.total_chunks[file_index], Ordering::Relaxed);
            }
        }
    }

    /// Mark a file as failed with an error message.
    pub fn file_failed(&self, file_index: usize, error: String) {
        if let Some(fs) = self.file_state.get() {
            if file_index < fs.names.len() {
                let mut errors = fs.errors.lock().unwrap();
                errors.push((file_index, error));
            }
        }
    }

    /// Build a snapshot for TUI rendering.
    pub fn snapshot(&self) -> TransferProgress {
        let Some(fs) = self.file_state.get() else {
            return TransferProgress::default();
        };

        let errors = fs.errors.lock().unwrap();
        let files = fs
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let done = fs.done_chunks[i].load(Ordering::Relaxed);
                let total = fs.total_chunks[i];

                let status = if let Some((_, err)) = errors.iter().find(|(idx, _)| *idx == i) {
                    FileStatus::Failed(err.clone())
                } else if done >= total && total > 0 {
                    FileStatus::Complete
                } else if done > 0 {
                    FileStatus::InProgress((done as f64 / total as f64) * 100.0)
                } else {
                    FileStatus::Waiting
                };

                FileProgress {
                    filename: name.clone(),
                    status,
                }
            })
            .collect();

        TransferProgress {
            files,
            completed: self.files_completed.load(Ordering::Relaxed) as usize,
            total: self.files_total.load(Ordering::Relaxed) as usize,
        }
    }

    pub fn get_progress(&self) -> (u64, u64) {
        let completed = self.completed_chunks.load(Ordering::Relaxed);
        let total = self.total_chunks.load(Ordering::Relaxed);
        (completed, total)
    }
}

#[cfg(test)]
mod tests {
    use super::ProgressTracker;
    use crate::common::FileStatus;

    #[test]
    fn reports_empty_snapshot_before_init() {
        let tracker = ProgressTracker::new();
        let snapshot = tracker.snapshot();

        assert_eq!(snapshot.total, 0);
        assert_eq!(snapshot.completed, 0);
        assert!(snapshot.files.is_empty());
        assert_eq!(tracker.get_progress(), (0, 0));
    }

    #[test]
    fn tracks_progress_and_completion_transitions() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into(), "b.bin".into()], vec![2, 3]);

        let initial = tracker.snapshot();
        assert_eq!(initial.total, 2);
        assert_eq!(initial.completed, 0);
        assert!(matches!(initial.files[0].status, FileStatus::Waiting));
        assert!(matches!(initial.files[1].status, FileStatus::Waiting));

        tracker.increment_file(0);
        tracker.increment_file(1);

        let middle = tracker.snapshot();
        assert!(matches!(middle.files[0].status, FileStatus::InProgress(_)));
        assert!(matches!(middle.files[1].status, FileStatus::InProgress(_)));
        assert_eq!(tracker.get_progress(), (2, 5));

        tracker.file_complete(0);
        tracker.file_complete(0);

        let after_complete = tracker.snapshot();
        assert_eq!(after_complete.completed, 1);
        assert!(matches!(
            after_complete.files[0].status,
            FileStatus::Complete
        ));
        assert!(matches!(
            after_complete.files[1].status,
            FileStatus::InProgress(_)
        ));
    }

    #[test]
    fn failed_status_has_precedence_over_complete() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![1]);

        tracker.file_complete(0);
        tracker.file_failed(0, "disk full".into());

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.completed, 1);
        assert!(matches!(
            snapshot.files[0].status,
            FileStatus::Failed(ref msg) if msg == "disk full"
        ));
    }

    #[test]
    fn ignores_out_of_range_file_indexes() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![2]);

        tracker.increment_file(99);
        tracker.file_complete(99);
        tracker.file_failed(99, "invalid".into());

        let snapshot = tracker.snapshot();
        assert_eq!(tracker.get_progress(), (0, 2));
        assert_eq!(snapshot.completed, 0);
        assert!(matches!(snapshot.files[0].status, FileStatus::Waiting));
    }
}
