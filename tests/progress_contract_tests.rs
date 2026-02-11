use archdrop::common::TransferProgress;
use archdrop::server::progress::ProgressTracker;

#[test]
fn progress_tracker_snapshot_uses_shared_transfer_progress_type() {
    let tracker = ProgressTracker::new();
    let snapshot: TransferProgress = tracker.snapshot();

    assert_eq!(snapshot.total, 0);
    assert_eq!(snapshot.completed, 0);
    assert!(snapshot.files.is_empty());
}
