mod common;

use archdrop::receive::ChunkStorage;
use common::setup_temp_dir;

//===============
// Test Helpers
//===============
const CHUNK_1MB: usize = 1024 * 1024;
const CHUNK_3MB: u64 = 3 * 1024 * 1024;

fn create_chunk_data(pattern: u8, size_mb: usize) -> Vec<u8> {
    vec![pattern; size_mb * CHUNK_1MB]
}

//===============
// Data Integrity
//===============
#[tokio::test]
async fn test_store_chunk_in_order() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("test.bin");

    // Storage for 3MB file
    let mut storage = ChunkStorage::new(file_path.clone(), CHUNK_3MB, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    let metadata = tokio::fs::metadata(&file_path)
        .await
        .expect("Failed to get file metadata");
    assert_eq!(metadata.len(), CHUNK_3MB, "File should be preallocated");

    // Store chunks in sequence
    let chunk_data = create_chunk_data(0xAA, 1);
    storage
        .store_chunk(0, &chunk_data)
        .await
        .expect("Failed to store chunk 0");
    storage
        .store_chunk(1, &chunk_data)
        .await
        .expect("Failed to store chunk 1");
    storage
        .store_chunk(2, &chunk_data)
        .await
        .expect("Failed to store chunk 2");

    // Verify all chunks tracked
    assert!(storage.has_chunk(0));
    assert!(storage.has_chunk(1));
    assert!(storage.has_chunk(2));
    assert_eq!(storage.chunk_count(), 3);
}
#[tokio::test]
async fn test_store_chunk_out_of_order() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("test.bin");

    let mut storage = ChunkStorage::new(file_path.clone(), CHUNK_3MB, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    // Create distinct chunk data to verify correct positioning
    let chunk0 = create_chunk_data(0x00, 1);
    let chunk1 = create_chunk_data(0x11, 1);
    let chunk2 = create_chunk_data(0x22, 1);

    // Store out-of-order: 2, 0, 1 (simulates real network conditions)
    storage
        .store_chunk(2, &chunk2)
        .await
        .expect("Failed to store chunk 2");
    storage
        .store_chunk(0, &chunk0)
        .await
        .expect("Failed to store chunk 0");
    storage
        .store_chunk(1, &chunk1)
        .await
        .expect("Failed to store chunk 1");

    let _ = storage
        .finalize()
        .await
        .expect("Failed to finalize storage");

    // Read file back and verify chunk positions
    let contents = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read test file");
    assert_eq!(contents.len(), CHUNK_3MB as usize);

    // Verify chunk 0 is at start
    assert_eq!(&contents[0..10], &[0x00; 10]);
    // Verify chunk 1 is in middle
    assert_eq!(&contents[CHUNK_1MB..CHUNK_1MB + 10], &[0x11; 10]);
    // Verify chunk 2 is at end
    assert_eq!(&contents[2 * CHUNK_1MB..2 * CHUNK_1MB + 10], &[0x22; 10]);
}
//===============
// File Collision
//===============
#[tokio::test]
async fn test_collision_numbers_file() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("test.txt");

    // Create existing file
    tokio::fs::write(&file_path, b"existing content")
        .await
        .expect("Failed to write test file");

    // Try to create new storage with same name
    let storage = ChunkStorage::new(file_path.clone(), 1024, 512)
        .await
        .expect("Failed to create ChunkStorage");

    // Should have created "test (1).txt" instead
    let actual_path = storage.get_path();
    assert_eq!(
        actual_path.file_name().expect("Failed to get filename"),
        "test (1).txt",
        "Should create numbered file"
    );

    // Original file should be untouched
    let original_content = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read original file");
    assert_eq!(original_content, b"existing content");
}

#[tokio::test]
async fn test_collision_increases_numbers_file() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("test (1).txt");

    // Create existing file
    tokio::fs::write(&file_path, b"existing content")
        .await
        .expect("Failed to write test file");

    // Try to create new storage with same name
    let storage = ChunkStorage::new(file_path.clone(), 1024, 512)
        .await
        .expect("Failed to create ChunkStorage");

    // Should have created "test (2).txt" instead
    let actual_path = storage.get_path();
    assert_eq!(
        actual_path.file_name().expect("Failed to get filename"),
        "test (2).txt",
        "Should create numbered file"
    );

    // Original file should be untouched
    let original_content = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read original file");
    assert_eq!(original_content, b"existing content");
}

#[tokio::test]
async fn test_collision_preserves_extension() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("archive.tar.gz");

    tokio::fs::write(&file_path, b"existing")
        .await
        .expect("Failed to write test file");

    let storage = ChunkStorage::new(file_path.clone(), 1024, 512)
        .await
        .expect("Failed to create ChunkStorage");

    // Should preserve compound extension
    let actual_name = storage
        .get_path()
        .file_name()
        .expect("Failed to get filename")
        .to_str()
        .expect("Filename should be valid UTF-8");
    assert_eq!(actual_name, "archive (1).tar.gz");
}

#[tokio::test]
async fn test_collision_with_hidden_file() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join(".gitignore");

    // Create existing hidden file
    tokio::fs::write(&file_path, b"existing")
        .await
        .expect("Failed to write test file");

    // Try to create new storage with same hidden filename
    let storage = ChunkStorage::new(file_path.clone(), 1024, 512)
        .await
        .expect("Failed to create ChunkStorage");

    // Should create ".gitignore (1)" NOT " (1).gitignore"
    let actual_name = storage
        .get_path()
        .file_name()
        .expect("Failed to get filename")
        .to_str()
        .expect("Filename should be valid UTF-8");
    assert_eq!(actual_name, ".gitignore (1)");

    // Ensure no leading space (the bug we fixed)
    assert!(
        !actual_name.starts_with(' '),
        "Filename should not start with space"
    );
}

//==============
// RAII Cleanup
//==============
#[tokio::test]
async fn test_drop_cleanup_incomplete() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("incomplete.bin");

    {
        // Create storage and write partial data
        let mut storage = ChunkStorage::new(file_path.clone(), CHUNK_3MB, CHUNK_1MB as u64)
            .await
            .expect("Failed to create ChunkStorage");
        storage
            .store_chunk(0, &create_chunk_data(0xAA, 1))
            .await
            .expect("Failed to store chunk 0");
        storage
            .store_chunk(1, &create_chunk_data(0xBB, 1))
            .await
            .expect("Failed to store chunk 1");

        // Only 2/3 chunks written
        assert_eq!(storage.chunk_count(), 2);

        // storage drops here
    }

    // File should be auto-deleted because not finalized
    assert!(!file_path.exists(), "Incomplete file should be deleted");
}

#[tokio::test]
async fn test_finalize_disarms_drop() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("complete.bin");

    let hash = {
        let mut storage = ChunkStorage::new(file_path.clone(), CHUNK_1MB as u64, CHUNK_1MB as u64)
            .await
            .expect("Failed to create ChunkStorage");
        storage
            .store_chunk(0, &create_chunk_data(0xFF, 1))
            .await
            .expect("Failed to store chunk 0");

        // Finalize sets disarmed = true
        storage
            .finalize()
            .await
            .expect("Failed to finalize storage")

        // storage drops here
    };

    // File should still exist because finalized
    assert!(file_path.exists(), "Finalized file should be kept");

    // Verify hash was computed correctly
    assert_eq!(hash.len(), 64, "SHA256 hash should be 64 hex chars");
}

#[tokio::test]
async fn test_cleanup_explicit() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("test.bin");

    let mut storage = ChunkStorage::new(file_path.clone(), 1024, 512)
        .await
        .expect("Failed to create ChunkStorage");

    // Explicit cleanup (used when upload cancelled)
    storage.cleanup().await.expect("Failed to cleanup storage");

    assert!(
        !file_path.exists(),
        "File should be deleted after cleanup()"
    );
}

//==================
// Concurrent Writes
//==================
#[tokio::test]
async fn test_concurrent_chunk_writes() {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("concurrent.bin");

    // 6 chunks = 6MB file
    let num_chunks = 6;
    let file_size = num_chunks * CHUNK_1MB as u64;

    let storage = Arc::new(Mutex::new(
        ChunkStorage::new(file_path.clone(), file_size, CHUNK_1MB as u64)
            .await
            .expect("Failed to create ChunkStorage"),
    ));

    // Spawn 6 tasks writing different chunks concurrently
    let mut tasks = vec![];
    for chunk_idx in 0..num_chunks {
        let storage = storage.clone();

        tasks.push(tokio::spawn(async move {
            // Each chunk has distinct pattern for verification
            let pattern = (chunk_idx as u8) + 0x10;
            let chunk_data = create_chunk_data(pattern, 1);

            let mut storage = storage.lock().await;
            storage.store_chunk(chunk_idx as usize, &chunk_data).await
        }));
    }

    // Wait for all writes to complete
    for task in tasks {
        task.await
            .expect("Task panicked")
            .expect("Failed to store chunk");
    }

    // Verify all chunks received
    let storage = storage.lock().await;
    assert_eq!(storage.chunk_count(), num_chunks as usize);

    // Verify no data corruption by checking patterns
    drop(storage);
    let contents = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read test file");

    for chunk_idx in 0..num_chunks {
        let offset = (chunk_idx * CHUNK_1MB as u64) as usize;
        let pattern = (chunk_idx as u8) + 0x10;

        // Check first 100 bytes of each chunk
        for i in 0..100 {
            assert_eq!(
                contents[offset + i],
                pattern,
                "Chunk {} corrupted at offset {}",
                chunk_idx,
                i
            );
        }
    }
}

//==================
// Edge Cases
//==================

#[tokio::test]
async fn test_finalize_incomplete_transfer_fails() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("incomplete.bin");

    // Create storage expecting 10 chunks
    let expected_size = 10 * CHUNK_1MB as u64;
    let mut storage = ChunkStorage::new(file_path.clone(), expected_size, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    // Only store 5 chunks
    for i in 0..5 {
        storage
            .store_chunk(i, &create_chunk_data(0xAA, 1))
            .await
            .expect("Failed to store chunk");
    }

    assert_eq!(storage.chunk_count(), 5);

    // Attempting to finalize incomplete transfer should FAIL
    let result = storage.finalize().await;
    assert!(
        result.is_err(),
        "Should reject finalization when only 5/10 chunks received"
    );

    // Verify error message mentions incomplete transfer
    let error = result.unwrap_err();
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("incomplete") || error_msg.contains("missing"),
        "Error should mention incomplete transfer, got: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_empty_file_storage() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("empty.txt");

    // Create storage for 0-byte file
    let mut storage = ChunkStorage::new(file_path.clone(), 0, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    // Should have 0 chunks
    assert_eq!(storage.chunk_count(), 0);

    // Finalize immediately (no chunks to write)
    let hash = storage
        .finalize()
        .await
        .expect("Failed to finalize empty file");

    // File should exist and be 0 bytes
    assert!(file_path.exists(), "Empty file should exist");

    let metadata = tokio::fs::metadata(&file_path)
        .await
        .expect("Failed to get metadata");
    assert_eq!(metadata.len(), 0, "File should be 0 bytes");

    // Hash should be SHA256 of empty data
    let expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hash, expected_hash, "SHA256 of empty file should match");
}

#[tokio::test]
async fn test_chunk_boundary_exactly_1mb() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("exactly_1mb.bin");

    // Create file exactly 1MB (1 chunk)
    let file_size = CHUNK_1MB as u64;
    let mut storage = ChunkStorage::new(file_path.clone(), file_size, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    // Store single chunk
    let chunk_data = create_chunk_data(0xCC, 1);
    storage
        .store_chunk(0, &chunk_data)
        .await
        .expect("Failed to store chunk");

    assert_eq!(storage.chunk_count(), 1);

    // Finalize
    let _hash = storage
        .finalize()
        .await
        .expect("Failed to finalize storage");

    // Verify file is exactly 1MB
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .expect("Failed to get metadata");
    assert_eq!(
        metadata.len(),
        CHUNK_1MB as u64,
        "File should be exactly 1MB"
    );

    // Verify content
    let contents = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read file");
    assert_eq!(contents.len(), CHUNK_1MB);
    assert!(
        contents.iter().all(|&b| b == 0xCC),
        "All bytes should be 0xCC"
    );
}

#[tokio::test]
async fn test_chunk_boundary_multiple_of_1mb() {
    let temp_dir = setup_temp_dir();
    let file_path = temp_dir.path().join("exactly_3mb.bin");

    // Create file exactly 3MB (3 chunks, no partial chunk)
    let file_size = 3 * CHUNK_1MB as u64;
    let mut storage = ChunkStorage::new(file_path.clone(), file_size, CHUNK_1MB as u64)
        .await
        .expect("Failed to create ChunkStorage");

    // Store 3 chunks with different patterns
    for i in 0..3 {
        let pattern = (i as u8) * 0x10;
        let chunk_data = create_chunk_data(pattern, 1);
        storage
            .store_chunk(i, &chunk_data)
            .await
            .expect("Failed to store chunk");
    }

    assert_eq!(storage.chunk_count(), 3);

    // Finalize
    let _hash = storage
        .finalize()
        .await
        .expect("Failed to finalize storage");

    // Verify file is exactly 3MB (no off-by-one errors)
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .expect("Failed to get metadata");
    assert_eq!(
        metadata.len(),
        3 * CHUNK_1MB as u64,
        "File should be exactly 3MB"
    );

    // Verify each chunk's pattern
    let contents = tokio::fs::read(&file_path)
        .await
        .expect("Failed to read file");

    for chunk_idx in 0..3 {
        let offset = chunk_idx * CHUNK_1MB;
        let expected_pattern = (chunk_idx as u8) * 0x10;

        // Check first and last bytes of each chunk
        assert_eq!(contents[offset], expected_pattern);
        assert_eq!(contents[offset + CHUNK_1MB - 1], expected_pattern);
    }
}
