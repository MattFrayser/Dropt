mod common;

use archdrop::common::config::{load_config, CliArgs, Transport};
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

            let cli_args = CliArgs {
                via: Some(Transport::Local),
                port: Some(3333),
                ..Default::default()
            };

            let config = load_config(&cli_args).expect("load config");
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

            let config = load_config(&CliArgs::default()).expect("load config");
            assert_eq!(config.port(Transport::Local), 2222);
        },
    );
}
