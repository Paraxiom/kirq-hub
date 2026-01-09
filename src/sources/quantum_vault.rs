use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;

use crate::config::QuantumVaultConfig;
use crate::quantum_state::{QuantumState, QuantumRegister};
use super::EntropySource;

/// Quantum-secure vault that generates entropy through quantum measurement
/// No storage - each request triggers a fresh quantum measurement
pub struct QuantumVault {
    #[cfg(feature = "qkd")]
    qkd_entropy: Option<Vec<u8>>,
    weight: f64,
    measurement_rounds: usize,
}

impl QuantumVault {
    pub fn new(config: &QuantumVaultConfig) -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "qkd")]
            qkd_entropy: None,
            weight: config.weight,
            measurement_rounds: config.measurement_rounds,
        })
    }
    
    /// Generate quantum entropy through measurement collapse
    /// Each measurement irreversibly consumes quantum state
    fn measure_quantum_state(&self, num_bytes: usize) -> Vec<u8> {
        let mut entropy = Vec::with_capacity(num_bytes);
        let bits_needed = num_bytes * 8;
        let mut bits_collected = 0;
        
        // Create fresh quantum states and measure them
        while bits_collected < bits_needed {
            // Create a quantum register with multiple qubits
            let register_size = std::cmp::min(8, bits_needed - bits_collected);
            let register = QuantumRegister::new(register_size);
            
            // Measure all qubits
            match register.measure_all() {
                Ok(measurements) => {
                    // Convert bool measurements to bits
                    let mut byte = 0u8;
                    let mut bit_position = 0;
                    
                    for measurement in measurements {
                        if measurement {
                            byte |= 1 << bit_position;
                        }
                        bit_position += 1;
                        bits_collected += 1;
                        
                        if bit_position == 8 {
                            entropy.push(byte);
                            byte = 0;
                            bit_position = 0;
                        }
                    }
                    
                    // Push remaining bits if any
                    if bit_position > 0 && entropy.len() < num_bytes {
                        entropy.push(byte);
                    }
                }
                Err(e) => {
                    log::warn!("Quantum measurement failed: {}, using fallback", e);
                    // Fallback to hardware RNG
                    let mut fallback = vec![0u8; num_bytes - entropy.len()];
                    if let Err(e) = getrandom::getrandom(&mut fallback) {
                        log::error!("Hardware RNG also failed: {:?}", e);
                    }
                    entropy.extend_from_slice(&fallback);
                    break;
                }
            }
        }
        
        entropy.truncate(num_bytes);
        
        // Apply post-processing for uniform distribution
        self.post_process_measurements(entropy)
    }
    
    fn post_process_measurements(&self, raw_measurements: Vec<u8>) -> Vec<u8> {
        // Apply quantum-safe extraction for uniformity
        if raw_measurements.is_empty() {
            return raw_measurements;
        }
        
        // Multiple rounds of mixing for better entropy quality
        let mut output = raw_measurements;
        
        for round in 0..self.measurement_rounds {
            // Mix with Blake3
            let hash = blake3::hash(&output);
            let extended = blake3::Hasher::new()
                .update(&output)
                .update(hash.as_bytes())
                .update(&round.to_le_bytes())
                .finalize();
            
            // XOR with hash output
            output = output.iter()
                .zip(extended.as_bytes().iter().cycle())
                .map(|(a, b)| a ^ b)
                .collect();
        }
        
        output
    }
}

#[async_trait]
impl EntropySource for QuantumVault {
    async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Generate fresh quantum entropy - no caching
        let quantum_entropy = self.measure_quantum_state(num_bytes);
        
        #[cfg(feature = "qkd")]
        {
            // If QKD is available, XOR with QKD entropy for additional security
            if let Ok(qkd_keys) = self.get_qkd_entropy(num_bytes).await {
                return Ok(quantum_entropy
                    .iter()
                    .zip(qkd_keys.iter())
                    .map(|(q, k)| q ^ k)
                    .collect());
            }
        }
        
        Ok(quantum_entropy)
    }

    async fn is_healthy(&self) -> bool {
        // Quantum vault is always ready - no external dependencies
        true
    }

    fn name(&self) -> &str {
        "quantum_vault"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

#[cfg(feature = "qkd")]
impl QuantumVault {
    async fn get_qkd_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // This would integrate with QKD system
        // For now, return error to fall back to pure quantum measurement
        anyhow::bail!("QKD integration not yet implemented for quantum vault")
    }
}

