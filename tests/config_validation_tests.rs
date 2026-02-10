mod common;

use archdrop::common::config::{load_config, CliArgs};
use common::config_test_utils::with_config_env;

#[test]
fn rejects_zero_chunk_size() {
    with_config_env(
        r#"
        [local]
        chunk_size = 0
        "#,
        || {
            let err = load_config(&CliArgs::default()).expect_err("expected validation failure");
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
            let err = load_config(&CliArgs::default()).expect_err("expected validation failure");
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
            let err = load_config(&CliArgs::default()).expect_err("expected validation failure");
            assert!(err.to_string().contains("chunk_size"));
        },
    );
}

#[test]
fn rejects_over_max_concurrency() {
    with_config_env(
        r#"
        [local]
        concurrency = 1000
        "#,
        || {
            let err = load_config(&CliArgs::default()).expect_err("expected validation failure");
            assert!(err.to_string().contains("concurrency"));
        },
    );
}
