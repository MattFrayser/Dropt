mod common;

use archdrop::common::config::{apply_overrides, load_config, ConfigOverrides, Transport};
use common::config_test_utils::with_config_env;

#[test]
fn precedence_defaults_file_env_cli() {
    with_config_env(
        r#"
        [local]
        port = 1111
        "#,
        || {
            std::env::set_var("ARCHDROP_LOCAL_PORT", "2222");

            let overrides = ConfigOverrides {
                transport: Some(Transport::Local),
                port: Some(3333),
            };

            let config = load_config().expect("load config");
            let config = apply_overrides(config, &overrides);
            assert_eq!(config.port(Transport::Local), 3333);
        },
    );
}

#[test]
fn precedence_defaults_file_env_without_cli() {
    with_config_env(
        r#"
        [local]
        port = 1111
        "#,
        || {
            std::env::set_var("ARCHDROP_LOCAL_PORT", "2222");

            let config = load_config().expect("load config");
            assert_eq!(config.port(Transport::Local), 2222);
        },
    );
}

#[test]
fn zip_defaults_to_false() {
    with_config_env("", || {
        let config = load_config().expect("load config");
        assert!(!config.zip);
    });
}

#[test]
fn zip_reads_from_config_file() {
    with_config_env(
        r#"
        zip = true
        "#,
        || {
            let config = load_config().expect("load config");
            assert!(config.zip);
        },
    );
}

#[test]
fn zip_env_overrides_config_file() {
    with_config_env(
        r#"
        zip = false
        "#,
        || {
            std::env::set_var("ARCHDROP_ZIP", "true");
            let config = load_config().expect("load config");
            assert!(config.zip);
        },
    );
}
