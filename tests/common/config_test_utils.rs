use dropt::common::config::{load_config_from_path_and_env_pairs, AppConfig};

fn write_config(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).expect("write config");
}

pub fn load_test_config(
    config_toml: &str,
    env_pairs: &[(&str, &str)],
) -> anyhow::Result<AppConfig> {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let app_config_dir = temp_dir.path().join("dropt");
    std::fs::create_dir_all(&app_config_dir).expect("create config dir");
    let config_path = app_config_dir.join("config.toml");

    write_config(&config_path, config_toml);

    let env_pairs = env_pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect::<Vec<_>>();

    load_config_from_path_and_env_pairs(&config_path, env_pairs)
}
