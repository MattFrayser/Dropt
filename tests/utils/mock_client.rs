use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::Result;
use archdrop::crypto::types::EncryptionKey;
use base64::{engine::general_purpose, Engine};
use reqwest::Client;
use sha2::digest::generic_array::GenericArray;

/// Helper to convert base64 string to bytes
fn base64_to_bytes(b64: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::URL_SAFE_NO_PAD.decode(b64)?)
}

/// Helper to generate chunk nonce from file nonce and chunk index
fn generate_chunk_nonce(file_nonce: &[u8], chunk_index: usize) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&file_nonce[..8]);
    nonce[8..12].copy_from_slice(&(chunk_index as u32).to_be_bytes());
    nonce
}

/// Helper to decrypt a chunk
fn decrypt_chunk(encrypted: &[u8], key: &EncryptionKey, chunk_nonce: &[u8; 12]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));
    let nonce_array = GenericArray::from_slice(chunk_nonce);

    cipher
        .decrypt(nonce_array, encrypted)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))
}

/// Helper to encrypt a chunk
fn encrypt_chunk(plaintext: &[u8], key: &EncryptionKey, chunk_nonce: &[u8; 12]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));
    let nonce_array = GenericArray::from_slice(chunk_nonce);

    cipher
        .encrypt(nonce_array, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))
}

/// Mock client that mimics the JavaScript download behavior
pub struct MockDownloadClient {
    client: Client,
    key: EncryptionKey,
}

impl MockDownloadClient {
    pub fn new(key: EncryptionKey) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();

        Self { client, key }
    }

    /// Download a complete file from send server
    pub async fn download_file(
        &self,
        base_url: &str,
        token: &str,
        file_index: usize,
    ) -> Result<Vec<u8>> {
        // 1. Fetch manifest
        let manifest_url = format!("{}/send/{}/manifest", base_url, token);
        let manifest_response = self.client.get(&manifest_url).send().await?;
        let manifest: serde_json::Value = manifest_response.json().await?;

        let file_info = &manifest["files"][file_index];
        let total_chunks = file_info["totalChunks"].as_u64().unwrap() as usize;
        let nonce_base64 = file_info["nonce"].as_str().unwrap();
        let nonce_bytes = base64_to_bytes(nonce_base64)?;

        // 2. Download chunks concurrently (like download.js does)
        let mut chunk_handles = vec![];

        for chunk_index in 0..total_chunks {
            let url = format!(
                "{}/send/{}/{}/chunk/{}",
                base_url, token, file_index, chunk_index
            );
            let client = self.client.clone();

            let handle = tokio::spawn(async move {
                let response = client.get(&url).send().await?;
                let bytes = response.bytes().await?;
                Ok::<_, anyhow::Error>((chunk_index, bytes.to_vec()))
            });

            chunk_handles.push(handle);
        }

        // 3. Collect chunks
        let mut chunks = vec![vec![]; total_chunks];
        for handle in chunk_handles {
            let (index, data) = handle.await??;
            chunks[index] = data;
        }

        // 4. Decrypt chunks
        let mut decrypted_data = Vec::new();
        for (chunk_index, encrypted_chunk) in chunks.iter().enumerate() {
            let chunk_nonce = generate_chunk_nonce(&nonce_bytes, chunk_index);
            let decrypted = decrypt_chunk(encrypted_chunk, &self.key, &chunk_nonce)?;
            decrypted_data.extend_from_slice(&decrypted);
        }

        Ok(decrypted_data)
    }

    /// Verify file hash
    pub async fn verify_hash(
        &self,
        base_url: &str,
        token: &str,
        file_index: usize,
        downloaded_data: &[u8],
    ) -> Result<bool> {
        use sha2::{Digest, Sha256};

        // Get hash from server
        let hash_url = format!("{}/send/{}/{}/hash", base_url, token, file_index);
        let response = self.client.get(&hash_url).send().await?;
        let hash_json: serde_json::Value = response.json().await?;
        let server_hash = hash_json["hash"].as_str().unwrap();

        // Calculate our hash
        let mut hasher = Sha256::new();
        hasher.update(downloaded_data);
        let our_hash = format!("{:x}", hasher.finalize());

        Ok(our_hash == server_hash)
    }
}

/// Mock client that mimics JavaScript upload behavior
pub struct MockUploadClient {
    client: Client,
    key: EncryptionKey,
    client_id: String,
}

impl MockUploadClient {
    pub fn new(key: EncryptionKey) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();

        let client_id = uuid::Uuid::new_v4().to_string();

        Self {
            client,
            key,
            client_id,
        }
    }

    /// Upload a complete file to receive server
    pub async fn upload_file(
        &self,
        base_url: &str,
        token: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<()> {
        use rand::RngCore;

        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

        let total_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

        // Generate file nonce
        let mut file_nonce = vec![0u8; 7];
        rand::thread_rng().fill_bytes(&mut file_nonce);
        let nonce_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&file_nonce);

        // Upload chunks
        for chunk_index in 0..total_chunks {
            let start = chunk_index * CHUNK_SIZE;
            let end = std::cmp::min(start + CHUNK_SIZE, data.len());
            let chunk_data = &data[start..end];

            // Encrypt
            let chunk_nonce = generate_chunk_nonce(&file_nonce, chunk_index);
            let encrypted = encrypt_chunk(chunk_data, &self.key, &chunk_nonce)?;

            // Build form
            let mut form = reqwest::multipart::Form::new()
                .part("chunk", reqwest::multipart::Part::bytes(encrypted))
                .text("relativePath", filename.to_string())
                .text("fileName", filename.to_string())
                .text("chunkIndex", chunk_index.to_string())
                .text("totalChunks", total_chunks.to_string())
                .text("fileSize", data.len().to_string())
                .text("clientId", self.client_id.clone());

            if chunk_index == 0 {
                form = form.text("nonce", nonce_base64.clone());
            }

            // Upload
            let url = format!(
                "{}/receive/{}/chunk?clientId={}",
                base_url, token, self.client_id
            );
            self.client.post(&url).multipart(form).send().await?;
        }

        // Finalize
        let finalize_url = format!(
            "{}/receive/{}/finalize?clientId={}",
            base_url, token, self.client_id
        );
        let form = reqwest::multipart::Form::new().text("relativePath", filename.to_string());
        self.client
            .post(&finalize_url)
            .multipart(form)
            .send()
            .await?;

        Ok(())
    }
}
