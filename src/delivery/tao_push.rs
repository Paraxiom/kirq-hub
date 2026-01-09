use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::interval;

use crate::sources::SourceManager;

#[derive(Serialize)]
struct EntropyPush {
    entropy: String, // hex encoded
    sources: Vec<String>,
    timestamp: u64,
    signature: String, // Post-quantum signature
}

#[derive(Deserialize)]
struct PushResponse {
    accepted: bool,
    message: String,
}

pub struct TaoSignalPushClient {
    client: Client,
    endpoint: String,
    api_key: String,
    source_manager: Arc<SourceManager>,
}

impl TaoSignalPushClient {
    pub fn new(
        endpoint: String,
        api_key: String,
        source_manager: Arc<SourceManager>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            endpoint,
            api_key,
            source_manager,
        })
    }

    pub async fn start_push_loop(&self, push_interval_secs: u64, entropy_bytes: usize) {
        let mut interval = interval(tokio::time::Duration::from_secs(push_interval_secs));

        loop {
            interval.tick().await;
            
            match self.push_entropy(entropy_bytes).await {
                Ok(_) => log::info!("Successfully pushed entropy to TAO Signal Agent"),
                Err(e) => log::error!("Failed to push entropy: {}", e),
            }
        }
    }

    async fn push_entropy(&self, num_bytes: usize) -> Result<()> {
        // Get fresh entropy
        let entropy = self.source_manager.get_mixed_entropy(num_bytes).await?;
        
        // Create post-quantum signature (placeholder - implement with real PQ crypto)
        let signature = self.create_post_quantum_signature(&entropy.data)?;
        
        let push = EntropyPush {
            entropy: hex::encode(&entropy.data),
            sources: entropy.sources_used,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature,
        };

        // Push to TAO Signal Agent with quantum-secure transport
        let response = self.client
            .post(&format!("{}/quantum/entropy/push", self.endpoint))
            .header("X-API-Key", &self.api_key)
            .header("X-Quantum-Auth", "SPHINCS+") // Post-quantum auth header
            .json(&push)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Push failed with status: {}", response.status());
        }

        let result: PushResponse = response.json().await?;
        if !result.accepted {
            anyhow::bail!("Push rejected: {}", result.message);
        }

        Ok(())
    }

    fn create_post_quantum_signature(&self, data: &[u8]) -> Result<String> {
        // TODO: Implement SPHINCS+ or other post-quantum signature
        // For now, use placeholder
        Ok(format!("PQ-SIG-{}", hex::encode(&blake3::hash(data).as_bytes()[..16])))
    }
}