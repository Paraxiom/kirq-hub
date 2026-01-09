use anyhow::Result;
use async_trait::async_trait;

use crate::config::QrngConfig;
use super::EntropySource;

#[cfg(feature = "qkd")]
use qkd_client::{QkdClient, QkdConfig};

pub struct QrngSource {
    #[cfg(feature = "qkd")]
    qkd_client: QkdClient,
    #[cfg(not(feature = "qkd"))]
    endpoint: String,
    weight: f64,
}

impl QrngSource {
    pub fn new(config: &QrngConfig) -> Result<Self> {
        #[cfg(feature = "qkd")]
        {
            // Initialize QKD client to get quantum random keys
            let qkd_config = QkdConfig {
                server_url: config.endpoint.clone(),
                api_key: config.api_key.clone(),
                timeout_ms: config.timeout_ms,
            };
            
            let qkd_client = QkdClient::new(qkd_config)?;
            
            Ok(Self {
                qkd_client,
                weight: config.weight,
            })
        }
        
        #[cfg(not(feature = "qkd"))]
        {
            Ok(Self {
                endpoint: config.endpoint.clone(),
                weight: config.weight,
            })
        }
    }
}

#[async_trait]
impl EntropySource for QrngSource {
    async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        #[cfg(feature = "qkd")]
        {
            // Get quantum random keys from QKD system
            // These keys are true quantum random numbers from the QKD process
            let qkd_key = self.qkd_client.get_key(num_bytes).await?;
            
            // The QKD key IS our quantum random entropy
            if qkd_key.len() != num_bytes {
                anyhow::bail!("QKD returned {} bytes, expected {}", qkd_key.len(), num_bytes);
            }
            
            log::info!("Retrieved {} bytes of quantum entropy from QKD", num_bytes);
            Ok(qkd_key)
        }
        
        #[cfg(not(feature = "qkd"))]
        {
            anyhow::bail!("QKD feature not enabled. Compile with --features qkd")
        }
    }

    async fn is_healthy(&self) -> bool {
        #[cfg(feature = "qkd")]
        {
            // Check if QKD system is operational
            match self.qkd_client.check_status().await {
                Ok(status) => {
                    log::debug!("QKD status: {:?}", status);
                    status.is_operational
                },
                Err(e) => {
                    log::warn!("QKD health check failed: {}", e);
                    false
                }
            }
        }
        
        #[cfg(not(feature = "qkd"))]
        {
            false
        }
    }

    fn name(&self) -> &str {
        "qrng"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}