use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub sources: Sources,
    pub mixing: MixingConfig,
    pub delivery: DeliveryConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Sources {
    pub qrng: QrngConfig,
    pub crypto4a: Crypto4aConfig,
    pub decentralized: DecentralizedConfig,
    #[serde(default)]
    pub quantum_vault: Option<QuantumVaultConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuantumVaultConfig {
    pub enabled: bool,
    pub weight: f64,
    #[serde(default = "default_measurement_rounds")]
    pub measurement_rounds: usize,
}

fn default_measurement_rounds() -> usize {
    3
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QrngConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub api_key: String,
    pub timeout_ms: u64,
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Crypto4aConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub timeout_ms: u64,
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecentralizedConfig {
    pub enabled: bool,
    pub nodes: Vec<String>,
    pub min_nodes: usize,
    pub timeout_ms: u64,
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MixingConfig {
    pub algorithm: String,
    pub salt: String,
    pub info: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeliveryConfig {
    pub max_entropy_age_seconds: u64,
    pub require_proof: bool,
    pub enable_metrics: bool,
    #[serde(default)]
    pub quantum_harmony_push: Option<QuantumHarmonyPushConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuantumHarmonyPushConfig {
    pub enabled: bool,
    pub rpc_endpoint: String,
    pub push_interval_secs: u64,
    pub entropy_bytes_per_push: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub enable_falcon_signatures: bool,
    pub enable_stark_proofs: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}