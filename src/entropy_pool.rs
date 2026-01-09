use crate::quantum_rng::{QuantumRngBridge, RngSource};
use std::collections::VecDeque;

// Entropy pool that consumes entropy on use (no cloning/reuse)
pub struct EntropyPool {
    pool: VecDeque<u8>,
    bridge: QuantumRngBridge,
    max_pool_size: usize,
}

impl EntropyPool {
    pub fn new() -> Self {
        let mut pool = Self {
            pool: VecDeque::new(),
            bridge: QuantumRngBridge::new(),
            max_pool_size: 4096, // 4KB max pool
        };
        
        // Pre-fill with some HSM entropy
        let _ = pool.refill_pool(1024, RngSource::Hsm);
        
        pool
    }
    
    // Consume entropy - once consumed, it's gone forever
    pub fn consume_entropy(&mut self, num_bytes: usize, source: RngSource) -> Result<Vec<u8>, String> {
        // For QKD and Hybrid, always fetch fresh (no pooling)
        if matches!(source, RngSource::Qkd | RngSource::Hybrid) {
            return self.bridge.fetch_entropy(num_bytes, source);
        }
        
        // For HSM, use pool for efficiency
        if self.pool.len() < num_bytes {
            // Refill pool
            let needed = (num_bytes - self.pool.len()).max(256);
            self.refill_pool(needed, source)?;
        }
        
        // Consume from pool - these bytes will never be reused
        let mut consumed = Vec::with_capacity(num_bytes);
        for _ in 0..num_bytes {
            if let Some(byte) = self.pool.pop_front() {
                consumed.push(byte);
            } else {
                return Err("Entropy pool exhausted".to_string());
            }
        }
        
        Ok(consumed)
    }
    
    fn refill_pool(&mut self, min_bytes: usize, source: RngSource) -> Result<(), String> {
        // Calculate how much to fetch
        let fetch_size = min_bytes.max(256).min(self.max_pool_size - self.pool.len());
        
        if fetch_size == 0 {
            return Ok(()); // Pool is full
        }
        
        // Fetch fresh entropy
        let fresh_entropy = self.bridge.fetch_entropy(fetch_size, source)?;
        
        // Add to pool
        for byte in fresh_entropy {
            self.pool.push_back(byte);
        }
        
        Ok(())
    }
    
    pub fn available_entropy(&self) -> usize {
        self.pool.len()
    }
    
    pub fn check_sources(&self) -> (bool, bool) {
        self.bridge.check_sources()
    }
    
    // Explicitly prevent cloning
    pub fn clear_pool(&mut self) {
        // Securely clear the pool
        for byte in self.pool.iter_mut() {
            *byte = 0;
        }
        self.pool.clear();
    }
}

// Implement Drop to ensure entropy is cleared
impl Drop for EntropyPool {
    fn drop(&mut self) {
        self.clear_pool();
    }
}