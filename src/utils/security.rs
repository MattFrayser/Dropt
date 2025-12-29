use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Component, Path};

//===============
// Path Handling
//===============
#[derive(Debug)]
pub enum PathValidationError {
    ContainsParentDir,
    AbsolutePath,
    InvalidComponent,
    NullByte,
    Empty,
}

impl fmt::Display for PathValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathValidationError::ContainsParentDir => {
                write!(f, "Path contains parent directory (..)")
            }
            PathValidationError::AbsolutePath => write!(f, "Path is absolute"),
            PathValidationError::InvalidComponent => write!(f, "Path contains invalid component"),
            PathValidationError::NullByte => write!(f, "Path contains null byte"),
            PathValidationError::Empty => write!(f, "Path is empty"),
        }
    }
}

impl std::error::Error for PathValidationError {}

// hash path for safe directory name
pub fn hash_path(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());

    // using first 16 chars (64 bits) for shorter directory names
    // with 16 still HIGHLY unlikely to collide
    format!("{:x}", hasher.finalize())[..16].to_string()
}

// Core validation logic shared by both validate_path and validate_filename
// Checks for: empty strings, null bytes, parent directory traversal, absolute paths
fn validate_path_components(path_str: &str) -> Result<(), PathValidationError> {
    if path_str.is_empty() {
        return Err(PathValidationError::Empty);
    }

    // null bytes
    // rust uses C-style APIs so \0 can end str early
    if path_str.contains('\0') {
        return Err(PathValidationError::NullByte);
    }

    let path = Path::new(path_str);

    // Check for dangerous path components
    for component in path.components() {
        match component {
            Component::Normal(_) => continue,
            Component::ParentDir => return Err(PathValidationError::ContainsParentDir),
            Component::RootDir => return Err(PathValidationError::AbsolutePath),
            Component::CurDir => continue, // "./" is okay, just redundant
            Component::Prefix(_) => return Err(PathValidationError::InvalidComponent), // Windows
        }
    }

    Ok(())
}

// Validate paths are safe to use
// Used for receiving.
// Since receive is writing entire path should be checked
// no: parent dir travel, absolute paths, null bytes
pub fn validate_path(path: &str) -> Result<(), PathValidationError> {
    validate_path_components(path)?;

    // Additional check: reject absolute paths upfront
    if Path::new(path).is_absolute() {
        return Err(PathValidationError::AbsolutePath);
    }

    Ok(())
}

// Used for send
// Only sending files so just the name should be valid
pub fn validate_filename(filename: &str) -> Result<(), PathValidationError> {
    validate_path_components(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for validate_filename (used for send mode)
    #[test]
    fn test_validate_filename_parent_directory() {
        // Direct parent directory traversal
        assert!(matches!(
            validate_filename("../etc/passwd"),
            Err(PathValidationError::ContainsParentDir)
        ));

        // Nested parent directory traversal
        assert!(matches!(
            validate_filename("dir/../../../etc/passwd"),
            Err(PathValidationError::ContainsParentDir)
        ));

        // Multiple parent dirs
        assert!(matches!(
            validate_filename("../../secrets.txt"),
            Err(PathValidationError::ContainsParentDir)
        ));
    }

    #[test]
    fn test_validate_filename_absolute_path() {
        // Unix absolute path
        assert!(matches!(
            validate_filename("/etc/passwd"),
            Err(PathValidationError::AbsolutePath)
        ));

        // Another Unix absolute path
        assert!(matches!(
            validate_filename("/home/user/file.txt"),
            Err(PathValidationError::AbsolutePath)
        ));

        // Root only
        assert!(matches!(
            validate_filename("/"),
            Err(PathValidationError::AbsolutePath)
        ));
    }

    #[test]
    fn test_validate_filename_null_byte() {
        // Null byte in middle
        assert!(matches!(
            validate_filename("file\0.txt"),
            Err(PathValidationError::NullByte)
        ));

        // Null byte used to hide path traversal
        assert!(matches!(
            validate_filename("normal\0../etc/passwd"),
            Err(PathValidationError::NullByte)
        ));

        // Null byte at end
        assert!(matches!(
            validate_filename("file.txt\0"),
            Err(PathValidationError::NullByte)
        ));
    }

    #[test]
    fn test_validate_filename_empty() {
        // Empty string should be rejected
        assert!(matches!(
            validate_filename(""),
            Err(PathValidationError::Empty)
        ));
    }

    #[test]
    fn test_validate_filename_valid_paths() {
        // Simple filename
        assert!(validate_filename("file.txt").is_ok());

        // Filename with subdirectory
        assert!(validate_filename("dir/subdir/file.txt").is_ok());

        // Filename with dashes and underscores
        assert!(validate_filename("file-with-dashes_and_underscores.tar.gz").is_ok());

        // Filename with spaces
        assert!(validate_filename("my file.txt").is_ok());

        // Hidden file (starts with dot)
        assert!(validate_filename(".gitignore").is_ok());

        // Current directory (redundant but safe)
        assert!(validate_filename("./file.txt").is_ok());

        // Multiple extensions
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
            Err(PathValidationError::ContainsParentDir)
        ));
        assert!(matches!(
            validate_path("dir/../../file.txt"),
            Err(PathValidationError::ContainsParentDir)
        ));
    }

    #[test]
    fn test_validate_path_rejects_absolute() {
        // These should fail due to absolute paths
        assert!(matches!(
            validate_path("/etc/passwd"),
            Err(PathValidationError::AbsolutePath)
        ));
        assert!(matches!(
            validate_path("/file.txt"),
            Err(PathValidationError::AbsolutePath)
        ));
    }

    #[test]
    fn test_validate_path_rejects_null_byte() {
        // Should fail due to null byte
        assert!(matches!(
            validate_path("file\0.txt"),
            Err(PathValidationError::NullByte)
        ));
    }

    #[test]
    fn test_validate_path_rejects_empty() {
        // Should fail due to empty path
        assert!(matches!(validate_path(""), Err(PathValidationError::Empty)));
    }
}
