pub mod mock_client;

/// Helper to start a test server and get its actual port
pub struct TestServer {
    pub base_url: String,
    pub token: String,
    // Note: Server lifecycle is managed internally by the runtime
}

impl TestServer {
    /// Start server in send mode
    pub async fn start_send(
        manifest: archdrop::transfer::manifest::Manifest,
        key: archdrop::crypto::types::EncryptionKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use archdrop::server::{start_send_server_for_test, ServerMode};

        let (port, session) = start_send_server_for_test(manifest, key, ServerMode::Local).await?;
        let token = session.token().to_string();
        let base_url = format!("http://127.0.0.1:{}", port);

        Ok(TestServer { base_url, token })
    }

    /// Start server in receive mode
    pub async fn start_receive(
        output_dir: std::path::PathBuf,
        key: archdrop::crypto::types::EncryptionKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use archdrop::server::{start_receive_server_for_test, ServerMode};

        let (port, session) =
            start_receive_server_for_test(output_dir, key, ServerMode::Local).await?;
        let token = session.token().to_string();
        let base_url = format!("http://127.0.0.1:{}", port);

        Ok(TestServer { base_url, token })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}
