mod common;

use archdrop::common::config::{load_config, AppConfig, CliArgs, Transport};
use common::config_test_utils::with_config_env;

#[test]
fn default_port_is_zero_for_all_transports() {
    let config = AppConfig::default();
    assert_eq!(config.port(Transport::Local), 0);
    assert_eq!(config.port(Transport::Cloudflare), 0);
    assert_eq!(config.port(Transport::Tailscale), 0);
}

#[test]
fn cli_port_applies_to_effective_transport() {
    with_config_env("", || {
        let cli_args = CliArgs {
            via: Some(Transport::Local),
            port: Some(9999),
            ..Default::default()
        };
        let config = load_config(&cli_args).unwrap();
        assert_eq!(config.port(Transport::Local), 9999);
        assert_eq!(config.port(Transport::Cloudflare), 0);
        assert_eq!(config.port(Transport::Tailscale), 0);
    });
}

#[test]
fn no_cli_port_uses_default() {
    with_config_env("", || {
        let cli_args = CliArgs::default();
        let config = load_config(&cli_args).unwrap();
        assert_eq!(config.port(Transport::Local), 0);
    });
}

#[test]
fn cli_port_applies_only_to_selected_transport() {
    with_config_env(
        r#"
        [local]
        port = 1111

        [cloudflare]
        port = 2222

        [tailscale]
        port = 3333
        "#,
        || {
            let cli_args = CliArgs {
                via: Some(Transport::Cloudflare),
                port: Some(4444),
                ..Default::default()
            };

            let config = load_config(&cli_args).expect("load config");
            assert_eq!(config.port(Transport::Cloudflare), 4444);
            assert_eq!(config.port(Transport::Local), 1111);
            assert_eq!(config.port(Transport::Tailscale), 3333);
        },
    );
}

#[test]
fn cli_port_applies_to_default_transport_when_via_omitted() {
    with_config_env(
        r#"
        default_transport = "tailscale"

        [local]
        port = 1111

        [cloudflare]
        port = 2222

        [tailscale]
        port = 3333
        "#,
        || {
            let cli_args = CliArgs {
                via: None,
                port: Some(4444),
            };

            let config = load_config(&cli_args).expect("load config");
            assert_eq!(config.port(Transport::Tailscale), 4444);
            assert_eq!(config.port(Transport::Local), 1111);
            assert_eq!(config.port(Transport::Cloudflare), 2222);
        },
    );
}
