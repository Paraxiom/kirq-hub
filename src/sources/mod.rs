use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod crypto4a;
pub mod decentralized;
pub mod qrng;
pub mod quantum_vault;

use crate::config::{Config, QuantumVaultConfig};

#[async_trait]
pub trait EntropySource: Send + Sync {
    async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>>;
    async fn is_healthy(&self) -> bool;
    fn name(&self) -> &str;
    fn weight(&self) -> f64;
}

pub struct SourceManager {
    sources: Vec<Arc<dyn EntropySource>>,
    health_status: Arc<RwLock<Vec<(String, bool)>>>,
}

impl SourceManager {
    pub async fn new(config: Config) -> Result<Self> {
        let mut sources: Vec<Arc<dyn EntropySource>> = Vec::new();

        // Initialize Crypto4A source
        if config.sources.crypto4a.enabled {
            let crypto4a = Arc::new(crypto4a::Crypto4aSource::new(&config.sources.crypto4a)?);
            sources.push(crypto4a);
        }

        // Initialize QRNG source
        if config.sources.qrng.enabled {
            let qrng = Arc::new(qrng::QrngSource::new(&config.sources.qrng)?);
            sources.push(qrng);
        }

        // Initialize decentralized source
        if config.sources.decentralized.enabled {
            let decentralized = Arc::new(
                decentralized::DecentralizedSource::new(&config.sources.decentralized)?
            );
            sources.push(decentralized);
        }

        // Initialize quantum vault
        if let Some(vault_config) = &config.sources.quantum_vault {
            if vault_config.enabled {
                let vault = Arc::new(quantum_vault::QuantumVault::new(vault_config)?);
                sources.push(vault);
            }
        }

        if sources.is_empty() {
            anyhow::bail!("No entropy sources enabled");
        }

        let health_status = Arc::new(RwLock::new(Vec::new()));

        Ok(Self {
            sources,
            health_status,
        })
    }

    pub async fn get_entropy_from_source(&self, source_name: &str, num_bytes: usize) -> Result<Vec<u8>> {
        for source in &self.sources {
            if source.name() == source_name {
                return source.get_entropy(num_bytes).await;
            }
        }
        anyhow::bail!("Source {} not found", source_name)
    }

    pub async fn get_mixed_entropy(&self, num_bytes: usize, sources: Vec<String>) -> Result<Vec<u8>> {
        let mut entropy_parts = Vec::new();
        let mut weights = Vec::new();

        for source_name in sources {
            for source in &self.sources {
                if source.name() == source_name && source.is_healthy().await {
                    match source.get_entropy(num_bytes).await {
                        Ok(entropy) => {
                            entropy_parts.push(entropy);
                            weights.push(source.weight());
                        }
                        Err(e) => {
                            log::warn!("Source {} failed: {}", source_name, e);
                        }
                    }
                }
            }
        }

        if entropy_parts.is_empty() {
            anyhow::bail!("No healthy sources available");
        }

        // Mix entropy using weighted XOR
        let mut mixed = vec![0u8; num_bytes];
        for (entropy, weight) in entropy_parts.iter().zip(weights.iter()) {
            for (i, byte) in entropy.iter().enumerate() {
                mixed[i] ^= (((*byte as f64) * weight) as u8);
            }
        }

        Ok(mixed)
    }

    pub async fn check_sources_health(&self) {
        let mut health = Vec::new();
        
        for source in &self.sources {
            let is_healthy = source.is_healthy().await;
            health.push((source.name().to_string(), is_healthy));
            
            if !is_healthy {
                log::warn!("Source {} is unhealthy", source.name());
            }
        }

        *self.health_status.write().await = health;
    }

    pub async fn get_health_status(&self) -> Vec<(String, bool)> {
        self.health_status.read().await.clone()
    }
}