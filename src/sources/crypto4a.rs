use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::config::Crypto4aConfig;
use super::EntropySource;

pub struct Crypto4aSource {
    client: Client,
    endpoint: String,
    weight: f64,
}

impl Crypto4aSource {
    pub fn new(config: &Crypto4aConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;

        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            weight: config.weight,
        })
    }
}

#[async_trait]
impl EntropySource for Crypto4aSource {
    async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Call Crypto4A HSM API
        let url = format!("{}?size={}", self.endpoint, num_bytes);
        
        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Crypto4A API error: {}", response.status());
        }

        // Crypto4A returns raw bytes
        let entropy = response.bytes().await?;
        
        if entropy.len() != num_bytes {
            anyhow::bail!("Received {} bytes, expected {}", entropy.len(), num_bytes);
        }

        Ok(entropy.to_vec())
    }

    async fn is_healthy(&self) -> bool {
        // Simple health check - try to get 1 byte
        match self.get_entropy(1).await {
            Ok(_) => true,
            Err(e) => {
                log::debug!("Crypto4A health check failed: {}", e);
                false
            }
        }
    }

    fn name(&self) -> &str {
        "crypto4a"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}