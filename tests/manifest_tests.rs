use archdrop::server::state::TransferConfig;
use archdrop::transfer::manifest::Manifest;
use base64::Engine;
use tempfile::TempDir;

fn default_config() -> TransferConfig {
    TransferConfig {
        chunk_size: 10 * 1024 * 1024,
        concurrency: 8,
    }
}

#[tokio::test]
async fn test_manifest_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let content = b"Hello, World!";
    std::fs::write(&test_file, content).unwrap();

    let manifest = Manifest::new(vec![test_file.clone()], None, default_config())
        .await
        .expect("Manifest creation should succeed");

    assert_eq!(manifest.files.len(), 1);
    assert_eq!(manifest.files[0].name, "test.txt");
    assert_eq!(manifest.files[0].size, content.len() as u64);
    assert_eq!(manifest.files[0].index, 0);
    assert!(!manifest.files[0].nonce.is_empty());
}

#[tokio::test]
async fn test_manifest_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");

    std::fs::write(&file1, b"content1").unwrap();
    std::fs::write(&file2, b"content2content2").unwrap();
    std::fs::write(&file3, b"c3").unwrap();

    let manifest = Manifest::new(vec![file1, file2, file3], None, default_config())
        .await
        .expect("Manifest creation should succeed");

    assert_eq!(manifest.files.len(), 3);

    // Check indices are sequential
    assert_eq!(manifest.files[0].index, 0);
    assert_eq!(manifest.files[1].index, 1);
    assert_eq!(manifest.files[2].index, 2);

    // Check names
    assert_eq!(manifest.files[0].name, "file1.txt");
    assert_eq!(manifest.files[1].name, "file2.txt");
    assert_eq!(manifest.files[2].name, "file3.txt");

    // Check sizes
    assert_eq!(manifest.files[0].size, 8);
    assert_eq!(manifest.files[1].size, 16);
    assert_eq!(manifest.files[2].size, 2);

    // Each file should have unique nonce
    assert_ne!(manifest.files[0].nonce, manifest.files[1].nonce);
    assert_ne!(manifest.files[1].nonce, manifest.files[2].nonce);
}

#[tokio::test]
async fn test_manifest_with_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let sub_dir = temp_dir.path().join("subdir");
    std::fs::create_dir(&sub_dir).unwrap();

    let file_in_subdir = sub_dir.join("nested.txt");
    std::fs::write(&file_in_subdir, b"nested content").unwrap();

    let manifest = Manifest::new(vec![file_in_subdir.clone()], Some(temp_dir.path()), default_config())
        .await
        .expect("Manifest creation should succeed");

    assert_eq!(manifest.files.len(), 1);
    assert_eq!(manifest.files[0].name, "nested.txt");
    assert!(manifest.files[0].relative_path.contains("subdir"));
}

#[tokio::test]
async fn test_manifest_relative_paths() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("root.txt");
    let sub_dir = temp_dir.path().join("sub");
    std::fs::create_dir(&sub_dir).unwrap();
    let file2 = sub_dir.join("nested.txt");

    std::fs::write(&file1, b"root").unwrap();
    std::fs::write(&file2, b"nested").unwrap();

    let manifest = Manifest::new(vec![file1, file2], Some(temp_dir.path()), default_config())
        .await
        .expect("Manifest creation should succeed");

    assert_eq!(manifest.files.len(), 2);

    // Check relative paths are computed correctly
    assert_eq!(manifest.files[0].relative_path, "root.txt");
    assert!(manifest.files[1].relative_path.ends_with("nested.txt"));
}

#[tokio::test]
async fn test_manifest_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("empty.txt");
    std::fs::write(&empty_file, b"").unwrap();

    let manifest = Manifest::new(vec![empty_file], None, default_config())
        .await
        .expect("Manifest creation should succeed");

    assert_eq!(manifest.files.len(), 1);
    assert_eq!(manifest.files[0].size, 0);
}

#[tokio::test]
async fn test_manifest_nonexistent_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("does_not_exist.txt");

    let result = Manifest::new(vec![nonexistent], None, default_config()).await;
    assert!(result.is_err(), "Should fail for nonexistent file");
}

#[tokio::test]
async fn test_manifest_nonces_are_base64() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, b"test").unwrap();

    let manifest = Manifest::new(vec![test_file], None, default_config())
        .await
        .expect("Manifest creation should succeed");

    let nonce = &manifest.files[0].nonce;

    // Should be valid base64 (won't panic on decode)
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce)
        .expect("Nonce should be valid base64");

    // Nonce should be 7 bytes
    assert_eq!(decoded.len(), 8);
}
