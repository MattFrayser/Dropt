/// Status of an individual file transfer.
#[derive(Clone, Debug, PartialEq)]
pub enum FileStatus {
    Waiting,
    InProgress(f64),
    Complete,
    Renamed(String),  // final filename on disk
    Overwrote,
    Skipped,          // was Skipped(String) — reason dropped, always "already exists"
    Failed(String),
}

/// Collision outcome recorded at manifest time. Stored in ProgressTracker,
/// surfaced as FileStatus in TUI snapshots.
/// Skipped is terminal (no chunks will arrive).
/// Renamed and Overwrote are non-terminal — chunks still transfer.
#[derive(Debug, Clone, PartialEq)]
pub enum CollisionOutcome {
    Skipped,
    Renamed(String),  // final filename on disk
    Overwrote,
}

/// Progress information for a single file.
#[derive(Clone, Debug)]
pub struct FileProgress {
    pub filename: String,
    pub status: FileStatus,
}

/// Aggregate transfer progress for runtime and presentation consumers.
#[derive(Clone, Debug, Default)]
pub struct TransferProgress {
    pub files: Vec<FileProgress>,
    pub completed: usize,
    pub total: usize,
}

impl TransferProgress {
    pub fn is_complete(&self) -> bool {
        self.total > 0 && self.completed >= self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_is_unit_variant() {
        let status = FileStatus::Skipped;
        assert!(matches!(status, FileStatus::Skipped));
    }
}
