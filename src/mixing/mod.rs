use anyhow::Result;
use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::config::MixingConfig;

pub struct EntropyMixer {
    salt: Vec<u8>,
    info: Vec<u8>,
}

impl EntropyMixer {
    pub fn new(config: &MixingConfig) -> Self {
        Self {
            salt: config.salt.as_bytes().to_vec(),
            info: config.info.as_bytes().to_vec(),
        }
    }

    pub fn mix_entropy(&self, entropy_parts: Vec<Vec<u8>>, num_bytes: usize) -> Result<Vec<u8>> {
        if entropy_parts.is_empty() {
            anyhow::bail!("No entropy parts to mix");
        }

        // Step 1: XOR all parts together
        let mut xor_mixed = vec![0u8; num_bytes];
        for entropy in &entropy_parts {
            if entropy.len() != num_bytes {
                anyhow::bail!("Entropy part has wrong size");
            }
            for (i, byte) in entropy.iter().enumerate() {
                xor_mixed[i] ^= byte;
            }
        }

        // Step 2: Hash all parts with Blake3
        let mut hasher = Hasher::new();
        for entropy in &entropy_parts {
            hasher.update(entropy);
        }
        let blake3_hash = hasher.finalize();

        // Step 3: Use HKDF to derive final entropy
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), &xor_mixed);
        let mut output = vec![0u8; num_bytes];
        
        hk.expand(&self.info, &mut output)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

        // Step 4: Final mix with Blake3 hash
        for (i, byte) in output.iter_mut().enumerate() {
            *byte ^= blake3_hash.as_bytes()[i % blake3_hash.as_bytes().len()];
        }

        Ok(output)
    }

    pub fn generate_mixing_proof(&self, inputs: &[Vec<u8>], output: &[u8]) -> MixingProof {
        // Generate a simple proof of mixing
        let mut input_hashes = Vec::new();
        
        for input in inputs {
            let hash = blake3::hash(input);
            input_hashes.push(hash.to_hex().to_string());
        }

        let output_hash = blake3::hash(output);

        MixingProof {
            algorithm: "hybrid_xor_hkdf".to_string(),
            input_hashes,
            output_hash: output_hash.to_hex().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

#[derive(serde::Serialize)]
pub struct MixingProof {
    pub algorithm: String,
    pub input_hashes: Vec<String>,
    pub output_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}