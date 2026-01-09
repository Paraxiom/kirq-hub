use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;

use crate::sources::SourceManager;

#[derive(Serialize)]
struct EntropyPush {
    entropy: String,  // Hex encoded
    sources: Vec<String>,
    timestamp: DateTime<Utc>,
    signature: Option<String>,  // Falcon signature if enabled
    proof: Option<serde_json::Value>,  // STARK proof if enabled
}

#[derive(Deserialize)]
struct PushResponse {
    accepted: bool,
    message: String,
}

pub struct PushClient {
    client: Client,
    target_url: String,
    api_token: String,
    source_manager: std::sync::Arc<SourceManager>,
}

impl PushClient {
    pub fn new(
        target_url: String,
        api_token: String,
        source_manager: std::sync::Arc<SourceManager>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            target_url,
            api_token,
            source_manager,
        })
    }

    pub async fn start_push_loop(&self, push_interval_secs: u64, entropy_bytes: usize) {
        let mut interval = interval(Duration::from_secs(push_interval_secs));

        loop {
            interval.tick().await;
            
            match self.push_entropy(entropy_bytes).await {
                Ok(_) => log::info!("Successfully pushed {} bytes of entropy", entropy_bytes),
                Err(e) => log::error!("Failed to push entropy: {}", e),
            }
        }
    }

    async fn push_entropy(&self, num_bytes: usize) -> Result<()> {
        // Get fresh entropy from available sources
        let sources = vec!["quantum_vault".to_string(), "crypto4a".to_string(), "qrng".to_string()];
        
        // Try to get mixed entropy
        let entropy = match self.source_manager.get_mixed_entropy(num_bytes, sources.clone()).await {
            Ok(e) => e,
            Err(_) => {
                // Fallback to any available source
                log::warn!("Mixed entropy failed, trying individual sources");
                self.get_any_available_entropy(num_bytes).await?
            }
        };

        // Create push payload
        let push_data = EntropyPush {
            entropy: hex::encode(&entropy),
            sources: self.get_active_sources().await,
            timestamp: Utc::now(),
            signature: None,  // TODO: Add Falcon signature
            proof: None,      // TODO: Add STARK proof
        };

        // Push to droplet
        let response = self.client
            .post(&self.target_url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("X-Kirk-Network", "true")
            .json(&push_data)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Push failed with status: {}", response.status());
        }

        let push_response: PushResponse = response.json().await?;
        
        if !push_response.accepted {
            anyhow::bail!("Entropy rejected: {}", push_response.message);
        }

        Ok(())
    }

    async fn get_any_available_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Try each source until one works
        for source in &["quantum_vault", "crypto4a", "qrng"] {
            match self.source_manager.get_entropy_from_source(source, num_bytes).await {
                Ok(entropy) => return Ok(entropy),
                Err(e) => log::debug!("Source {} failed: {}", source, e),
            }
        }
        
        anyhow::bail!("No entropy sources available")
    }

    async fn get_active_sources(&self) -> Vec<String> {
        self.source_manager
            .get_health_status()
            .await
            .into_iter()
            .filter_map(|(name, healthy)| if healthy { Some(name) } else { None })
            .collect()
    }
}

/// Configuration for push client
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PushConfig {
    pub enabled: bool,
    pub target_url: String,
    pub api_token: String,
    pub push_interval_secs: u64,
    pub entropy_bytes_per_push: usize,
}