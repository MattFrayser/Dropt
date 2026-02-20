use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Path contains parent directory (..)")]
    ContainsParentDir,

    #[error("File path is absolute")]
    AbsolutePath,

    #[error("File path contains invalid component")]
    InvalidComponent,

    #[error("File path contains null byte")]
    NullByte,

    #[error("File path is empty")]
    Empty,

    #[error("Filename contains directory separator")]
    ContainsDirectorySeparator,

    #[error("Invalid destination root")]
    InvalidRoot,

    #[error("Path escapes destination root")]
    EscapesRoot,

    #[error("Path contains symlink component")]
    SymlinkComponent,
}

// =========
// Hashing
// =========

/// Hash path for safe directory name
pub fn hash_path(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());

    // first 16 chars (64 bits) for shorter directory names
    // 16 still HIGHLY unlikely to collide
    format!("{:x}", hasher.finalize())[..16].to_string()
}

// ==================
// Lexical validation
// ==================

// Core validation logic shared by both validate_path and validate_filename.
// Checks for: empty strings, null bytes, parent directory traversal, absolute paths.
fn validate_path_components(path_str: &str) -> Result<(), ValidationError> {
    if path_str.is_empty() {
        return Err(ValidationError::Empty);
    }

    // null bytes
    // rust uses C-style APIs so \0 can end str early
    if path_str.contains('\0') {
        return Err(ValidationError::NullByte);
    }

    let path = Path::new(path_str);

    // Check for dangerous path components
    for component in path.components() {
        match component {
            Component::Normal(_) => continue,
            Component::ParentDir => return Err(ValidationError::ContainsParentDir),
            Component::RootDir => return Err(ValidationError::AbsolutePath),
            Component::CurDir => continue, // "./" is okay, just redundant
            Component::Prefix(_) => return Err(ValidationError::InvalidComponent), // Windows
        }
    }

    Ok(())
}

// Validate paths are safe to use (used for receiving).
// Reject: parent-dir traversal, absolute paths, null bytes.
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    validate_path_components(path)
}

// Validate proper filename (used for send).
// Reject: directory separators.
pub fn validate_filename(filename: &str) -> Result<(), ValidationError> {
    validate_path_components(filename)?;

    if filename.contains('/') || filename.contains('\\') {
        return Err(ValidationError::ContainsDirectorySeparator);
    }

    Ok(())
}

// =========================
// Receive path confinement
// =========================

/// Resolve a receive relative path under `root` and enforce confinement.
///
/// Rules:
/// - Lexically valid relative path (`validate_path`)
/// - Canonical destination root must exist
/// - Any symlink component in the traversed path is rejected
/// - Final resolved path must remain under canonical root
pub fn confine_receive_path(root: &Path, relative: &str) -> Result<PathBuf, ValidationError> {
    validate_path(relative)?;

    let root_canonical = std::fs::canonicalize(root).map_err(|_| ValidationError::InvalidRoot)?;
    let mut cursor = root_canonical.clone();

    for component in Path::new(relative).components() {
        match component {
            Component::Normal(segment) => {
                cursor.push(segment);

                if let Ok(meta) = std::fs::symlink_metadata(&cursor) {
                    if meta.file_type().is_symlink() {
                        return Err(ValidationError::SymlinkComponent);
                    }
                }

                if !cursor.starts_with(&root_canonical) {
                    return Err(ValidationError::EscapesRoot);
                }
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(ValidationError::ContainsParentDir),
            Component::RootDir => return Err(ValidationError::AbsolutePath),
            Component::Prefix(_) => return Err(ValidationError::InvalidComponent),
        }
    }

    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // Lexical validation tests
    // ========================

    // Tests for validate_filename (used for send mode)
    #[test]
    fn test_validate_filename_parent_directory() {
        // Direct parent directory traversal
        assert!(matches!(
            validate_filename("../etc/passwd"),
            Err(ValidationError::ContainsParentDir)
        ));

        // Nested parent directory traversal
        assert!(matches!(
            validate_filename("dir/../../../etc/passwd"),
            Err(ValidationError::ContainsParentDir)
        ));

        // Multiple parent dirs
        assert!(matches!(
            validate_filename("../../secrets.txt"),
            Err(ValidationError::ContainsParentDir)
        ));
    }

    #[test]
    fn test_validate_filename_absolute_path() {
        // Unix absolute path
        assert!(matches!(
            validate_filename("/etc/passwd"),
            Err(ValidationError::AbsolutePath)
        ));

        // Another Unix absolute path
        assert!(matches!(
            validate_filename("/home/user/file.txt"),
            Err(ValidationError::AbsolutePath)
        ));

        // Root only
        assert!(matches!(
            validate_filename("/"),
            Err(ValidationError::AbsolutePath)
        ));
    }

    #[test]
    fn test_validate_filename_null_byte() {
        // Null byte in middle
        assert!(matches!(
            validate_filename("file\0.txt"),
            Err(ValidationError::NullByte)
        ));

        // Null byte used to hide path traversal
        assert!(matches!(
            validate_filename("normal\0../etc/passwd"),
            Err(ValidationError::NullByte)
        ));

        // Null byte at end
        assert!(matches!(
            validate_filename("file.txt\0"),
            Err(ValidationError::NullByte)
        ));
    }

    #[test]
    fn test_validate_filename_empty() {
        // Empty string should be rejected
        assert!(matches!(validate_filename(""), Err(ValidationError::Empty)));
    }

    #[test]
    fn test_validate_filename_rejects_directory_separators() {
        assert!(matches!(
            validate_filename("dir/file.txt"),
            Err(ValidationError::ContainsDirectorySeparator)
        ));
        assert!(matches!(
            validate_filename("dir/subdir/file.txt"),
            Err(ValidationError::ContainsDirectorySeparator)
        ));
        assert!(matches!(
            validate_filename("./file.txt"),
            Err(ValidationError::ContainsDirectorySeparator)
        ));
        assert!(matches!(
            validate_filename("dir\\file.txt"),
            Err(ValidationError::ContainsDirectorySeparator)
        ));
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("file.txt").is_ok());
        assert!(validate_filename("file-with-dashes_and_underscores.tar.gz").is_ok());
        assert!(validate_filename("my file.txt").is_ok());
        assert!(validate_filename(".gitignore").is_ok());
        assert!(validate_filename("archive.tar.gz.gpg").is_ok());
    }

    #[test]
    fn test_hash_path_deterministic() {
        // Same input should produce same hash
        let hash1 = hash_path("test/path");
        let hash2 = hash_path("test/path");
        assert_eq!(hash1, hash2);

        // Different inputs should produce different hashes
        let hash3 = hash_path("different/path");
        assert_ne!(hash1, hash3);

        // Hash should be 16 characters (as specified in implementation)
        assert_eq!(hash1.len(), 16);
        assert_eq!(hash3.len(), 16);

        // Hash should be hex (lowercase)
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hash3.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_path_various_inputs() {
        // Empty path
        let hash_empty = hash_path("");
        assert_eq!(hash_empty.len(), 16);

        // Path with special characters
        let hash_special = hash_path("path/with/special-chars_123");
        assert_eq!(hash_special.len(), 16);

        // Very long path
        let long_path = "a".repeat(1000);
        let hash_long = hash_path(&long_path);
        assert_eq!(hash_long.len(), 16);

        // All hashes should be different
        assert_ne!(hash_empty, hash_special);
        assert_ne!(hash_special, hash_long);
        assert_ne!(hash_empty, hash_long);
    }

    // Tests for validate_path (used for receive mode - full path validation)
    #[test]
    fn test_validate_path_accepts_valid() {
        // These should all be valid
        assert!(validate_path("file.txt").is_ok());
        assert!(validate_path("dir/file.txt").is_ok());
        assert!(validate_path("./file.txt").is_ok());
        assert!(validate_path("a/b/c/file.txt").is_ok());
    }

    #[test]
    fn test_validate_path_rejects_parent_dir() {
        // These should all fail due to parent directory traversal
        assert!(matches!(
            validate_path("../file.txt"),
            Err(ValidationError::ContainsParentDir)
        ));
        assert!(matches!(
            validate_path("dir/../../file.txt"),
            Err(ValidationError::ContainsParentDir)
        ));
    }

    #[test]
    fn test_validate_path_rejects_absolute() {
        // These should fail due to absolute paths
        assert!(matches!(
            validate_path("/etc/passwd"),
            Err(ValidationError::AbsolutePath)
        ));
        assert!(matches!(
            validate_path("/file.txt"),
            Err(ValidationError::AbsolutePath)
        ));
    }

    #[test]
    fn test_validate_path_rejects_null_byte() {
        // Should fail due to null byte
        assert!(matches!(
            validate_path("file\0.txt"),
            Err(ValidationError::NullByte)
        ));
    }

    #[test]
    fn test_validate_path_rejects_empty() {
        // Should fail due to empty path
        assert!(matches!(validate_path(""), Err(ValidationError::Empty)));
    }

    // ======================
    // Confinement path tests
    // ======================

    #[test]
    fn confine_receive_path_accepts_nested_relative_path() {
        let root = tempfile::tempdir().expect("tempdir");

        let confined = confine_receive_path(root.path(), "nested/file.txt").expect("confined path");

        assert!(confined.starts_with(root.path()));
        assert!(confined.ends_with(Path::new("nested/file.txt")));
    }

    #[test]
    fn confine_receive_path_rejects_invalid_root() {
        let root = std::env::temp_dir().join(format!("dropt-missing-{}", std::process::id()));

        let result = confine_receive_path(&root, "file.txt");

        assert!(matches!(result, Err(ValidationError::InvalidRoot)));
    }

    #[test]
    fn confine_receive_path_keeps_parent_dir_rejection() {
        let root = tempfile::tempdir().expect("tempdir");

        let result = confine_receive_path(root.path(), "../escape.txt");

        assert!(matches!(result, Err(ValidationError::ContainsParentDir)));
    }

    #[cfg(unix)]
    #[test]
    fn confine_receive_path_fails_early_on_symlink_component() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let link = root.path().join("evil");
        symlink(outside.path(), &link).expect("create symlink");

        let result = confine_receive_path(root.path(), "evil/file.txt");

        assert!(matches!(result, Err(ValidationError::SymlinkComponent)));
    }

    #[cfg(unix)]
    #[test]
    fn confine_receive_path_fails_early_on_symlink_leaf() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let outside_file = outside.path().join("real.txt");
        std::fs::write(&outside_file, b"data").expect("write outside file");
        let link = root.path().join("leaf.txt");
        symlink(&outside_file, &link).expect("create file symlink");

        let result = confine_receive_path(root.path(), "leaf.txt");

        assert!(matches!(result, Err(ValidationError::SymlinkComponent)));
    }
}
