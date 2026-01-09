use anyhow::Result;
use std::path::PathBuf;

// Import the ETSI QKD client from qkd_client crate
use qkd_client::qkd::etsi_api::{ETSIClient, DeviceType, Side};

/// Adapter to use the real ETSI QKD client with quantum-rng-kirq-hub
pub struct QkdAdapter {
    etsi_client: ETSIClient,
}

impl QkdAdapter {
    pub fn new(endpoint: String, api_key: Option<String>, timeout_ms: u64) -> Result<Self> {
        // Parse the endpoint to determine which device and side to use
        let (device_type, side) = if endpoint.contains("toshiba") || endpoint.contains("192.168.0") {
            (DeviceType::Toshiba, Side::Alice)
        } else if endpoint.contains("idq") {
            (DeviceType::IDQ, Side::Alice)
        } else if endpoint.contains("basejump") {
            (DeviceType::Basejump, Side::Alice)
        } else if endpoint.contains("simulated") || endpoint.contains("localhost") {
            (DeviceType::Simulated, Side::Alice)
        } else {
            // Default to Toshiba for Kirq network
            (DeviceType::Toshiba, Side::Alice)
        };

        // Get certificate paths from environment or use defaults
        let cert_path = std::env::var("TOSHIBA_CERT_PATH")
            .unwrap_or_else(|_| "/etc/quantum/certs/toshiba.pem".to_string());
        let root_cert_path = std::env::var("TOSHIBA_ROOT_CERT_PATH").ok();

        // Create the ETSI client
        let etsi_client = ETSIClient::new(
            device_type,
            side,
            &PathBuf::from(cert_path),
            root_cert_path.as_ref().map(|p| PathBuf::from(p).as_path()),
            api_key,
        )?;

        Ok(Self { etsi_client })
    }

    /// Get quantum random bytes from the QKD system
    pub async fn get_key(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Request a key from the QKD system
        let qkd_key = self.etsi_client
            .get_key_alice(num_bytes, "kirq-hub", Some("entropy-generation"))
            .await?;
        
        // Return the quantum random bytes
        Ok(qkd_key.key_bytes)
    }

    /// Check if the QKD system is operational
    pub async fn check_status(&self) -> Result<QkdStatus> {
        // Try to get available key size as a health check
        match self.etsi_client.get_available_key_size().await {
            Ok(available) => {
                Ok(QkdStatus {
                    is_operational: available > 0,
                    available_bytes: available,
                })
            }
            Err(_) => {
                Ok(QkdStatus {
                    is_operational: false,
                    available_bytes: 0,
                })
            }
        }
    }
}

pub struct QkdStatus {
    pub is_operational: bool,
    pub available_bytes: usize,
}

// Implement the expected interface for backward compatibility
pub struct QkdClient {
    adapter: QkdAdapter,
}

impl QkdClient {
    pub fn new(config: QkdConfig) -> Result<Self> {
        let adapter = QkdAdapter::new(
            config.server_url,
            config.api_key,
            config.timeout_ms,
        )?;
        Ok(Self { adapter })
    }

    pub async fn get_key(&self, num_bytes: usize) -> Result<Vec<u8>> {
        self.adapter.get_key(num_bytes).await
    }

    pub async fn check_status(&self) -> Result<QkdStatus> {
        self.adapter.check_status().await
    }
}

pub struct QkdConfig {
    pub server_url: String,
    pub api_key: Option<String>,
    pub timeout_ms: u64,
}