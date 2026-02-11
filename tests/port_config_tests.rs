mod common;

use archdrop::common::config::{
    apply_overrides, load_config, AppConfig, ConfigOverrides, Transport,
};
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
        let overrides = ConfigOverrides {
            transport: Some(Transport::Local),
            port: Some(9999),
        };
        let config = load_config().unwrap();
        let config = apply_overrides(config, &overrides);
        assert_eq!(config.port(Transport::Local), 9999);
        assert_eq!(config.port(Transport::Cloudflare), 0);
        assert_eq!(config.port(Transport::Tailscale), 0);
    });
}

#[test]
fn no_cli_port_uses_default() {
    with_config_env("", || {
        let config = load_config().unwrap();
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
            let overrides = ConfigOverrides {
                transport: Some(Transport::Cloudflare),
                port: Some(4444),
            };

            let config = load_config().expect("load config");
            let config = apply_overrides(config, &overrides);
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
            let overrides = ConfigOverrides {
                transport: None,
                port: Some(4444),
            };

            let config = load_config().expect("load config");
            let config = apply_overrides(config, &overrides);
            assert_eq!(config.port(Transport::Tailscale), 4444);
            assert_eq!(config.port(Transport::Local), 1111);
            assert_eq!(config.port(Transport::Cloudflare), 2222);
        },
    );
}
