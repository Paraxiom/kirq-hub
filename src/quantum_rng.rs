use reqwest::blocking::Client;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
pub enum RngSource {
    Hsm,
    Qkd,
    Hybrid,
}

pub struct QuantumRngBridge {
    hsm_client: Client,
    qkd_client: Option<Client>,
}

impl QuantumRngBridge {
    pub fn initialize() {
        println!("Initializing Quantum RNG Bridge");
    }
    
    pub fn new() -> Self {
        let hsm_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HSM client");
            
        let qkd_client = if std::env::var("QKD_API_URL").is_ok() {
            Some(
                Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("Failed to create QKD client")
            )
        } else {
            None
        };
        
        Self {
            hsm_client,
            qkd_client,
        }
    }
    
    // Synchronous entropy fetch - blocks until complete
    pub fn fetch_entropy(&self, num_bytes: usize, source: RngSource) -> Result<Vec<u8>, String> {
        match source {
            RngSource::Hsm => self.fetch_hsm_entropy(num_bytes),
            RngSource::Qkd => self.fetch_qkd_entropy(num_bytes),
            RngSource::Hybrid => self.fetch_hybrid_entropy(num_bytes),
        }
    }
    
    fn fetch_hsm_entropy(&self, num_bytes: usize) -> Result<Vec<u8>, String> {
        // Direct synchronous call to HSM
        let url = format!("http://localhost:8106/v1/random?size={}", num_bytes);
        
        match self.hsm_client.get(&url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    response.bytes()
                        .map(|b| b.to_vec())
                        .map_err(|e| format!("Failed to read HSM response: {}", e))
                } else {
                    Err(format!("HSM returned error: {}", response.status()))
                }
            }
            Err(e) => Err(format!("HSM connection failed: {}", e)),
        }
    }
    
    fn fetch_qkd_entropy(&self, num_bytes: usize) -> Result<Vec<u8>, String> {
        let qkd_client = self.qkd_client.as_ref()
            .ok_or_else(|| "QKD not configured".to_string())?;
            
        let api_url = std::env::var("QKD_API_URL")
            .map_err(|_| "QKD_API_URL not set".to_string())?;
        let auth_token = std::env::var("QKD_AUTH_TOKEN")
            .map_err(|_| "QKD_AUTH_TOKEN not set".to_string())?;
        
        // Synchronous QKD fetch
        match qkd_client
            .get(&api_url)
            .header("Authorization", format!("Bearer {}", auth_token))
            .send() 
        {
            Ok(response) => {
                if response.status().is_success() {
                    // Parse QKD response and extract keys
                    let qkd_data: serde_json::Value = response.json()
                        .map_err(|e| format!("Failed to parse QKD response: {}", e))?;
                    
                    // Extract and combine keys
                    let keys = qkd_data["keys"].as_array()
                        .ok_or_else(|| "Invalid QKD response format".to_string())?;
                    
                    let mut combined = Vec::new();
                    for key in keys {
                        if let Some(key_str) = key["key"].as_str() {
                            // Decode base64 key
                            let key_bytes = base64::decode(key_str)
                                .map_err(|e| format!("Failed to decode QKD key: {}", e))?;
                            combined.extend_from_slice(&key_bytes);
                        }
                    }
                    
                    // Use SHAKE256 to get exact bytes needed
                    let mut hasher = Sha256::new();
                    hasher.update(&combined);
                    let hash = hasher.finalize();
                    
                    // If we need more bytes, expand using HKDF-like construction
                    if num_bytes <= 32 {
                        Ok(hash[..num_bytes].to_vec())
                    } else {
                        self.expand_entropy(&hash, num_bytes)
                    }
                } else {
                    Err(format!("QKD returned error: {}", response.status()))
                }
            }
            Err(e) => Err(format!("QKD connection failed: {}", e)),
        }
    }
    
    fn fetch_hybrid_entropy(&self, num_bytes: usize) -> Result<Vec<u8>, String> {
        // Fetch both sources
        let hsm_entropy = self.fetch_hsm_entropy(num_bytes)?;
        
        // Try QKD, but don't fail if unavailable
        let qkd_entropy = match self.fetch_qkd_entropy(num_bytes) {
            Ok(entropy) => entropy,
            Err(_) => {
                // If QKD fails, return HSM only
                return Ok(hsm_entropy);
            }
        };
        
        // XOR combine for maximum entropy
        let mut hybrid = Vec::with_capacity(num_bytes);
        for i in 0..num_bytes {
            hybrid.push(hsm_entropy[i] ^ qkd_entropy[i]);
        }
        
        // Additional mixing with HMAC
        let mut mac = HmacSha256::new_from_slice(b"quantum-bridge-v1")
            .expect("HMAC creation failed");
        mac.update(&hybrid);
        let result = mac.finalize();
        
        if num_bytes <= 32 {
            Ok(result.into_bytes()[..num_bytes].to_vec())
        } else {
            self.expand_entropy(&result.into_bytes(), num_bytes)
        }
    }
    
    fn expand_entropy(&self, seed: &[u8], num_bytes: usize) -> Result<Vec<u8>, String> {
        let mut output = Vec::with_capacity(num_bytes);
        let mut counter = 1u8;
        
        while output.len() < num_bytes {
            let mut mac = HmacSha256::new_from_slice(seed)
                .expect("HMAC creation failed");
            mac.update(&output);
            mac.update(&[counter]);
            let chunk = mac.finalize();
            output.extend_from_slice(&chunk.into_bytes());
            counter += 1;
        }
        
        output.truncate(num_bytes);
        Ok(output)
    }
    
    pub fn check_sources(&self) -> (bool, bool) {
        // Check HSM
        let hsm_ok = self.fetch_hsm_entropy(8).is_ok();
        
        // Check QKD
        let qkd_ok = self.qkd_client.is_some() && self.fetch_qkd_entropy(8).is_ok();
        
        (hsm_ok, qkd_ok)
    }
}