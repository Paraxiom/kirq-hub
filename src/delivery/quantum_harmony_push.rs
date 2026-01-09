use anyhow::Result;
use chrono::{DateTime, Utc};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;

use crate::sources::SourceManager;
pub use crate::config::QuantumHarmonyPushConfig;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct QRNGEvent {
    id: u64,
    data: String,  // Hex encoded entropy
    timestamp: u64,
    block_height: u64,
    sources: Vec<String>,
    signature: Option<String>,
}

#[derive(Serialize)]
struct EventWithPriority {
    event: QRNGEvent,
    priority: i32,
}

pub struct QuantumHarmonyPushClient {
    client: HttpClient,
    source_manager: std::sync::Arc<SourceManager>,
    next_event_id: std::sync::atomic::AtomicU64,
}

impl QuantumHarmonyPushClient {
    pub fn new(
        rpc_endpoint: String,
        source_manager: std::sync::Arc<SourceManager>,
    ) -> Result<Self> {
        let client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(30))
            .build(&rpc_endpoint)?;

        Ok(Self {
            client,
            source_manager,
            next_event_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    pub async fn start_push_loop(&self, push_interval_secs: u64, entropy_bytes: usize) {
        let mut interval = interval(Duration::from_secs(push_interval_secs));

        loop {
            interval.tick().await;
            
            match self.push_entropy_to_priority_queue(entropy_bytes).await {
                Ok(_) => log::info!("Successfully pushed {} bytes of entropy to Quantum Harmony", entropy_bytes),
                Err(e) => log::error!("Failed to push entropy: {}", e),
            }
        }
    }

    async fn push_entropy_to_priority_queue(&self, num_bytes: usize) -> Result<()> {
        // Get fresh entropy from available sources
        let sources = vec!["quantum_vault".to_string(), "crypto4a".to_string(), "qrng".to_string()];
        
        // Try to get mixed entropy
        let (entropy, active_sources) = match self.source_manager.get_mixed_entropy(num_bytes, sources.clone()).await {
            Ok(e) => (e, sources),
            Err(_) => {
                // Fallback to any available source
                log::warn!("Mixed entropy failed, trying individual sources");
                let entropy = self.get_any_available_entropy(num_bytes).await?;
                let active_sources = self.get_active_sources().await;
                (entropy, active_sources)
            }
        };

        // Create QRNG event
        let event = QRNGEvent {
            id: self.next_event_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            data: hex::encode(&entropy),
            timestamp: Utc::now().timestamp() as u64,
            block_height: 0,  // Will be set by the blockchain
            sources: active_sources,
            signature: None,  // TODO: Add Falcon signature
        };

        // High priority for quantum entropy
        let priority = 100;

        // Submit to priority queue via RPC
        // The priority queue expects: submit_quantum_event(event_type, data, source, qber)
        let response: u64 = self.client
            .request("submit_quantum_event", rpc_params![
                "QuantumEntropy",  // event_type
                hex::encode(&entropy),  // data
                "KirqHub",  // source
                serde_json::Value::Null  // qber (not applicable for entropy)
            ])
            .await?;

        log::info!("Quantum Harmony response: {}", response);

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

    // Check if events are being processed
    pub async fn check_queue_status(&self) -> Result<String> {
        let response: String = self.client
            .request("get_event_count", rpc_params![])
            .await?;
        
        Ok(response)
    }

    // List all pending events
    pub async fn list_pending_events(&self) -> Result<String> {
        let response: String = self.client
            .request("list_all_events", rpc_params![])
            .await?;
        
        Ok(response)
    }
}