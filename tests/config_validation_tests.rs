mod common;

use dropt::common::config::{load_config, MAX_TRANSFER_CHUNK_SIZE_BYTES};
use common::config_test_utils::with_config_env;

#[test]
fn rejects_zero_chunk_size() {
    with_config_env(
        r#"
        [local]
        chunk_size = 0
        "#,
        || {
            let err = load_config().expect_err("expected validation failure");
            assert!(err.to_string().contains("chunk_size"));
        },
    );
}

#[test]
fn rejects_zero_concurrency() {
    with_config_env(
        r#"
        [local]
        concurrency = 0
        "#,
        || {
            let err = load_config().expect_err("expected validation failure");
            assert!(err.to_string().contains("concurrency"));
        },
    );
}

#[test]
fn rejects_over_max_chunk_size() {
    with_config_env(
        r#"
        [local]
        chunk_size = 1073741824
        "#,
        || {
            let err = load_config().expect_err("expected validation failure");
            assert!(err.to_string().contains("chunk_size"));
        },
    );
}

#[test]
fn rejects_chunk_size_above_conservative_runtime_limit() {
    let config = format!(
        "\n        [local]\n        chunk_size = {}\n        ",
        MAX_TRANSFER_CHUNK_SIZE_BYTES + 1
    );
    with_config_env(&config, || {
        let err = load_config().expect_err("expected validation failure");
        assert!(err.to_string().contains("chunk_size"));
    });
}

#[test]
fn allows_chunk_size_at_conservative_runtime_limit() {
    let config = format!(
        "\n        [local]\n        chunk_size = {}\n        ",
        MAX_TRANSFER_CHUNK_SIZE_BYTES
    );
    with_config_env(&config, || {
        load_config().expect("expected config to be valid");
    });
}

#[test]
fn rejects_over_max_concurrency() {
    with_config_env(
        r#"
        [local]
        concurrency = 1000
        "#,
        || {
            let err = load_config().expect_err("expected validation failure");
            assert!(err.to_string().contains("concurrency"));
        },
    );
}
