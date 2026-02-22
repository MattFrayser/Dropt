use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvRestore {
    xdg_config_home: Option<std::ffi::OsString>,
    local_port: Option<std::ffi::OsString>,
    cloudflare_port: Option<std::ffi::OsString>,
    tailscale_port: Option<std::ffi::OsString>,
    default_transport: Option<std::ffi::OsString>,
    zip: Option<std::ffi::OsString>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        if let Some(value) = self.xdg_config_home.take() {
            set_env_var("XDG_CONFIG_HOME", value);
        } else {
            remove_env_var("XDG_CONFIG_HOME");
        }

        if let Some(value) = self.local_port.take() {
            set_env_var("DROPT_LOCAL_PORT", value);
        } else {
            remove_env_var("DROPT_LOCAL_PORT");
        }

        if let Some(value) = self.cloudflare_port.take() {
            set_env_var("DROPT_CLOUDFLARE_PORT", value);
        } else {
            remove_env_var("DROPT_CLOUDFLARE_PORT");
        }

        if let Some(value) = self.tailscale_port.take() {
            set_env_var("DROPT_TAILSCALE_PORT", value);
        } else {
            remove_env_var("DROPT_TAILSCALE_PORT");
        }

        if let Some(value) = self.default_transport.take() {
            set_env_var("DROPT_DEFAULT_TRANSPORT", value);
        } else {
            remove_env_var("DROPT_DEFAULT_TRANSPORT");
        }

        if let Some(value) = self.zip.take() {
            set_env_var("DROPT_ZIP", value);
        } else {
            remove_env_var("DROPT_ZIP");
        }
    }
}

fn write_config(temp_dir: &TempDir, contents: &str) {
    let app_config_dir = temp_dir.path().join("dropt");
    std::fs::create_dir_all(&app_config_dir).expect("create config dir");
    std::fs::write(app_config_dir.join("config.toml"), contents).expect("write config");
}

pub fn with_config_env<T>(config_toml: &str, f: impl FnOnce() -> T) -> T {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = TempDir::new().expect("temp dir");

    write_config(&temp_dir, config_toml);

    let restore = EnvRestore {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
        local_port: std::env::var_os("DROPT_LOCAL_PORT"),
        cloudflare_port: std::env::var_os("DROPT_CLOUDFLARE_PORT"),
        tailscale_port: std::env::var_os("DROPT_TAILSCALE_PORT"),
        default_transport: std::env::var_os("DROPT_DEFAULT_TRANSPORT"),
        zip: std::env::var_os("DROPT_ZIP"),
    };

    set_env_var("XDG_CONFIG_HOME", temp_dir.path());
    remove_env_var("DROPT_LOCAL_PORT");
    remove_env_var("DROPT_CLOUDFLARE_PORT");
    remove_env_var("DROPT_TAILSCALE_PORT");
    remove_env_var("DROPT_DEFAULT_TRANSPORT");
    remove_env_var("DROPT_ZIP");

    let result = f();
    drop(restore);
    result
}

pub fn set_env_var<K, V>(key: K, value: V)
where
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    unsafe {
        std::env::set_var(key, value);
    }
}

pub fn remove_env_var<K>(key: K)
where
    K: AsRef<std::ffi::OsStr>,
{
    unsafe {
        std::env::remove_var(key);
    }
}
