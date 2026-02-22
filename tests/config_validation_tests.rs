mod common;

use common::config_test_utils::load_test_config;
use dropt::common::config::MAX_TRANSFER_CHUNK_SIZE_BYTES;

#[test]
fn rejects_zero_chunk_size() {
    let err = load_test_config(
        r#"
        [local]
        chunk_size = 0
        "#,
        &[],
    )
    .expect_err("expected validation failure");

    assert!(err.to_string().contains("chunk_size"));
}

#[test]
fn rejects_zero_concurrency() {
    let err = load_test_config(
        r#"
        [local]
        concurrency = 0
        "#,
        &[],
    )
    .expect_err("expected validation failure");

    assert!(err.to_string().contains("concurrency"));
}

#[test]
fn rejects_over_max_chunk_size() {
    let err = load_test_config(
        r#"
        [local]
        chunk_size = 1073741824
        "#,
        &[],
    )
    .expect_err("expected validation failure");

    assert!(err.to_string().contains("chunk_size"));
}

#[test]
fn rejects_chunk_size_above_conservative_runtime_limit() {
    let config = format!(
        "\n        [local]\n        chunk_size = {}\n        ",
        MAX_TRANSFER_CHUNK_SIZE_BYTES + 1
    );
    let err = load_test_config(&config, &[]).expect_err("expected validation failure");
    assert!(err.to_string().contains("chunk_size"));
}

#[test]
fn allows_chunk_size_at_conservative_runtime_limit() {
    let config = format!(
        "\n        [local]\n        chunk_size = {MAX_TRANSFER_CHUNK_SIZE_BYTES}\n        "
    );
    load_test_config(&config, &[]).expect("expected config to be valid");
}

#[test]
fn rejects_over_max_concurrency() {
    let err = load_test_config(
        r#"
        [local]
        concurrency = 1000
        "#,
        &[],
    )
    .expect_err("expected validation failure");

    assert!(err.to_string().contains("concurrency"));
}
