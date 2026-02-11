/// Status of an individual file transfer.
#[derive(Clone, Debug, PartialEq)]
pub enum FileStatus {
    Waiting,
    InProgress(f64),
    Complete,
    Failed(String),
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
