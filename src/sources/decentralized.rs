use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;

use crate::config::DecentralizedConfig;
use super::EntropySource;

pub struct DecentralizedSource {
    client: Client,
    nodes: Vec<String>,
    min_nodes: usize,
    timeout: Duration,
    weight: f64,
}

impl DecentralizedSource {
    pub fn new(config: &DecentralizedConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;

        Ok(Self {
            client,
            nodes: config.nodes.clone(),
            min_nodes: config.min_nodes,
            timeout: Duration::from_millis(config.timeout_ms),
            weight: config.weight,
        })
    }

}

#[async_trait]
impl EntropySource for DecentralizedSource {
    async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Collect entropy from multiple nodes
        let mut tasks = Vec::new();
        
        for node in &self.nodes {
            let node_url = node.clone();
            let client = self.client.clone();
            let timeout_duration = self.timeout;
            
            tasks.push(async move {
                let request_future = async {
                    let url = format!("{}/entropy?bytes={}", node_url, num_bytes);
                    let response = client.get(&url).send().await?;
                    
                    if !response.status().is_success() {
                        anyhow::bail!("Node {} returned error: {}", node_url, response.status());
                    }
                    
                    let entropy = response.bytes().await?;
                    
                    if entropy.len() != num_bytes {
                        anyhow::bail!("Node {} returned {} bytes, expected {}", 
                                     node_url, entropy.len(), num_bytes);
                    }
                    
                    Ok(entropy.to_vec())
                };
                
                timeout(timeout_duration, request_future).await
            });
        }

        // Wait for responses
        let results = futures::future::join_all(tasks).await;
        
        // Collect successful responses
        let mut entropy_parts = Vec::new();
        for result in results {
            match result {
                Ok(Ok(entropy)) => entropy_parts.push(entropy),
                Ok(Err(e)) => log::warn!("Node error: {}", e),
                Err(_) => log::warn!("Node timeout"),
            }
        }

        if entropy_parts.len() < self.min_nodes {
            anyhow::bail!(
                "Only {} nodes responded, minimum {} required",
                entropy_parts.len(),
                self.min_nodes
            );
        }

        // XOR all entropy parts together
        let mut mixed = vec![0u8; num_bytes];
        for entropy in &entropy_parts {
            for (i, byte) in entropy.iter().enumerate() {
                mixed[i] ^= byte;
            }
        }

        Ok(mixed)
    }

    async fn is_healthy(&self) -> bool {
        // Check if minimum nodes are responsive
        let mut healthy_nodes = 0;
        
        for node in &self.nodes {
            let health_url = format!("{}/health", node);
            
            match timeout(
                Duration::from_secs(2),
                self.client.get(&health_url).send()
            ).await {
                Ok(Ok(response)) if response.status().is_success() => {
                    healthy_nodes += 1;
                }
                _ => {}
            }
        }

        healthy_nodes >= self.min_nodes
    }

    fn name(&self) -> &str {
        "decentralized"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}