mod common;

use common::config_test_utils::load_test_config;
use dropt::common::config::{ConfigOverrides, Transport, apply_overrides};

#[test]
fn precedence_defaults_file_env_cli() {
    let config = load_test_config(
        r#"
        [local]
        port = 1111
        "#,
        &[("DROPT_LOCAL_PORT", "2222")],
    )
    .expect("load config");

    let overrides = ConfigOverrides {
        transport: Some(Transport::Local),
        port: Some(3333),
    };

    let config = apply_overrides(config, &overrides);
    assert_eq!(config.port(Transport::Local), 3333);
}

#[test]
fn precedence_defaults_file_env_without_cli() {
    let config = load_test_config(
        r#"
        [local]
        port = 1111
        "#,
        &[("DROPT_LOCAL_PORT", "2222")],
    )
    .expect("load config");

    assert_eq!(config.port(Transport::Local), 2222);
}

#[test]
fn zip_defaults_to_false() {
    let config = load_test_config("", &[]).expect("load config");
    assert!(!config.zip);
}

#[test]
fn zip_reads_from_config_file() {
    let config = load_test_config(
        r#"
        zip = true
        "#,
        &[],
    )
    .expect("load config");

    assert!(config.zip);
}

#[test]
fn zip_env_overrides_config_file() {
    let config = load_test_config(
        r#"
        zip = false
        "#,
        &[("DROPT_ZIP", "true")],
    )
    .expect("load config");

    assert!(config.zip);
}

#[test]
fn unknown_env_keys_are_ignored() {
    let config = load_test_config("", &[("DROPT_NOT_A_REAL_KEY", "value")]).expect("load config");

    assert_eq!(config.port(Transport::Local), 0);
}
