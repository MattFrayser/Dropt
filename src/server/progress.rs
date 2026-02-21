//! Lock-free transfer progress tracking for TUI snapshots.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::common::{CollisionOutcome, FileProgress, FileStatus, TransferProgress};

struct FileState {
    names: Vec<String>,
    total_chunks: Vec<u64>,
    done_chunks: Vec<AtomicU64>,
    completed: Vec<AtomicBool>,
    errors: Mutex<Vec<(usize, String)>>,
    outcomes: Mutex<HashMap<usize, CollisionOutcome>>,
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
            outcomes: Mutex::new(HashMap::new()),
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
                let total = fs.total_chunks[file_index];
                let prev = fs.done_chunks[file_index].swap(total, Ordering::Relaxed);
                if prev < total {
                    self.completed_chunks
                        .fetch_add(total - prev, Ordering::Relaxed);
                }
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

    /// Record a collision outcome for a file. Idempotent — first call wins.
    /// `Skipped` marks the file terminal immediately (no chunks will arrive).
    /// `Renamed` and `Overwrote` are stored but non-terminal — chunks still transfer.
    pub fn file_collision_outcome(&self, index: usize, outcome: CollisionOutcome) {
        let Some(fs) = self.file_state.get() else { return };
        if index >= fs.names.len() { return }

        let mut outcomes = fs.outcomes.lock().unwrap();
        outcomes.entry(index).or_insert(outcome);
        let is_skip = matches!(outcomes[&index], CollisionOutcome::Skipped);
        drop(outcomes);

        if is_skip && !fs.completed[index].swap(true, Ordering::AcqRel) {
            self.files_completed.fetch_add(1, Ordering::Relaxed);
            let total = fs.total_chunks[index];
            let prev = fs.done_chunks[index].swap(total, Ordering::Relaxed);
            if prev < total {
                self.completed_chunks.fetch_add(total - prev, Ordering::Relaxed);
            }
        }
    }

    /// Build a snapshot for TUI rendering.
    pub fn snapshot(&self) -> TransferProgress {
        let Some(fs) = self.file_state.get() else {
            return TransferProgress::default();
        };

        let errors = fs.errors.lock().unwrap();
        let outcomes = fs.outcomes.lock().unwrap();

        let files = fs
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let done = fs.done_chunks[i].load(Ordering::Relaxed);
                let total = fs.total_chunks[i];

                // Renamed files show the final on-disk name in the filename column
                let filename = match outcomes.get(&i) {
                    Some(CollisionOutcome::Renamed(new_name)) => new_name.clone(),
                    _ => name.clone(),
                };

                let status = if let Some((_, err)) = errors.iter().find(|(idx, _)| *idx == i) {
                    FileStatus::Failed(err.clone())
                } else if let Some(CollisionOutcome::Skipped) = outcomes.get(&i) {
                    FileStatus::Skipped
                } else if done >= total && total > 0 {
                    match outcomes.get(&i) {
                        Some(CollisionOutcome::Renamed(new_name)) => {
                            FileStatus::Renamed(new_name.clone())
                        }
                        Some(CollisionOutcome::Overwrote) => FileStatus::Overwrote,
                        _ => FileStatus::Complete,
                    }
                } else if done > 0 {
                    FileStatus::InProgress((done as f64 / total as f64) * 100.0)
                } else {
                    FileStatus::Waiting
                };

                FileProgress { filename, status }
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
    use super::*;
    use crate::common::{CollisionOutcome, FileStatus};

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

        tracker.increment_file(0);
        tracker.increment_file(1);

        let mid = tracker.snapshot();
        assert!(matches!(mid.files[0].status, FileStatus::InProgress(_)));
        assert!(matches!(mid.files[1].status, FileStatus::InProgress(_)));

        tracker.file_complete(0);
        tracker.file_complete(0); // idempotent

        let after = tracker.snapshot();
        assert_eq!(after.completed, 1);
        assert!(matches!(after.files[0].status, FileStatus::Complete));
    }

    #[test]
    fn skipped_marks_file_terminal_and_is_idempotent() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![4]);

        tracker.file_collision_outcome(0, CollisionOutcome::Skipped);
        tracker.file_collision_outcome(0, CollisionOutcome::Skipped); // idempotent

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.completed, 1);
        assert!(matches!(snapshot.files[0].status, FileStatus::Skipped));
        assert_eq!(tracker.get_progress(), (4, 4));
    }

    #[test]
    fn renamed_is_not_terminal_shows_renamed_name_on_complete() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![1]);

        tracker.file_collision_outcome(0, CollisionOutcome::Renamed("a (1).bin".into()));

        // Not terminal yet — still waiting for chunks
        let before = tracker.snapshot();
        assert!(matches!(before.files[0].status, FileStatus::Waiting));

        tracker.file_complete(0);

        let after = tracker.snapshot();
        assert!(matches!(
            after.files[0].status,
            FileStatus::Renamed(ref name) if name == "a (1).bin"
        ));
        assert_eq!(after.files[0].filename, "a (1).bin");
    }

    #[test]
    fn overwrote_is_not_terminal_shows_overwrote_on_complete() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![1]);

        tracker.file_collision_outcome(0, CollisionOutcome::Overwrote);

        let before = tracker.snapshot();
        assert!(matches!(before.files[0].status, FileStatus::Waiting));

        tracker.file_complete(0);

        let after = tracker.snapshot();
        assert!(matches!(after.files[0].status, FileStatus::Overwrote));
    }

    #[test]
    fn failed_takes_precedence_over_collision_outcomes() {
        let tracker = ProgressTracker::new();
        tracker.init_files(vec!["a.bin".into()], vec![1]);

        tracker.file_collision_outcome(0, CollisionOutcome::Renamed("a (1).bin".into()));
        tracker.file_failed(0, "disk full".into());

        let snapshot = tracker.snapshot();
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
        tracker.file_collision_outcome(99, CollisionOutcome::Skipped);
        tracker.file_failed(99, "invalid".into());

        let snapshot = tracker.snapshot();
        assert_eq!(tracker.get_progress(), (0, 2));
        assert_eq!(snapshot.completed, 0);
        assert!(matches!(snapshot.files[0].status, FileStatus::Waiting));
    }
}
