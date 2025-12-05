#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_validation() {
        // Valid paths
        assert!(validate_path("file.txt").is_ok());
        assert!(validate_path("dir/file.txt").is_ok());
        assert!(validate_path("./file.txt").is_ok());

        // Invalid paths
        assert!(validate_path("../file.txt").is_err());
        assert!(validate_path("/etc/passwd").is_err());
        assert!(validate_path("dir/../../file.txt").is_err());
        assert!(validate_path("").is_err());
        assert!(validate_path("file\0.txt").is_err());
    }
}
