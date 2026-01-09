# Quantum-Safe Transmission Analysis

## Current Vulnerability

The RNG endpoints implement quantum principles at the application level, but the transmission is vulnerable:

1. **Plain HTTP/HTTPS transmission** - Even with HTTPS, the data can be:
   - Intercepted by MITM attacks
   - Logged by proxies/CDNs
   - Cached by browsers
   - Subject to replay attacks at network level

2. **No quantum channel** - Classical transmission allows:
   - Perfect copying of the entropy
   - Storage and later analysis
   - No detection of eavesdropping

## Required: True Quantum-Safe Transmission

### Option 1: One-Time Pad (OTP) Encryption
```python
# Pre-shared quantum key required
def quantum_safe_transmit(entropy_bytes, pre_shared_key):
    # XOR with one-time pad
    encrypted = bytes(a ^ b for a, b in zip(entropy_bytes, pre_shared_key))
    # Key is consumed after use (quantum no-cloning)
    return encrypted
```

### Option 2: Quantum Key Distribution (QKD) Channel
- Requires physical quantum channel (fiber optic with photon transmission)
- Detects any eavesdropping attempts
- Not possible over classical internet

### Option 3: Post-Quantum Cryptography
- Use quantum-resistant algorithms (Kyber, Dilithium)
- Still classical transmission but resistant to quantum attacks
- Can be implemented over standard networks

### Option 4: Hybrid Approach (Practical)
1. **Key Agreement**: Post-quantum key exchange (Kyber)
2. **Encryption**: AES-256-GCM with ephemeral keys
3. **Authentication**: Dilithium signatures
4. **Forward Secrecy**: New keys for each request

## Implementation Plan

### Immediate Solution: Encrypted Payload with Ephemeral Keys
```python
@router.post("/api/rng/hsm/secure")
async def generate_secure_hsm_random(request: SecureRNGRequest):
    # 1. Generate ephemeral key pair
    ephemeral_key = generate_kyber_keypair()
    
    # 2. Client provides their public key
    shared_secret = kyber_decapsulate(request.client_public_key, ephemeral_key.private)
    
    # 3. Generate entropy
    entropy = await get_hsm_random(request.num_bytes)
    
    # 4. Encrypt with shared secret
    encrypted_entropy = aes_gcm_encrypt(entropy, shared_secret)
    
    # 5. Sign response
    signature = dilithium_sign(encrypted_entropy, server_private_key)
    
    # 6. Destroy keys (quantum no-cloning)
    ephemeral_key.destroy()
    shared_secret.destroy()
    
    return {
        "encrypted_entropy": encrypted_entropy,
        "ephemeral_public_key": ephemeral_key.public,
        "signature": signature,
        "algorithm": "kyber-aes-dilithium"
    }
```

### Client-Side Decryption
```python
def receive_quantum_safe_entropy(response):
    # 1. Verify signature
    if not dilithium_verify(response.signature, response.encrypted_entropy):
        raise SecurityError("Invalid signature")
    
    # 2. Derive shared secret
    shared_secret = kyber_encapsulate(response.ephemeral_public_key, client_private_key)
    
    # 3. Decrypt entropy
    entropy = aes_gcm_decrypt(response.encrypted_entropy, shared_secret)
    
    # 4. Destroy keys immediately
    shared_secret.destroy()
    
    return entropy
```

## Current Status: NOT Quantum-Safe in Transit

Without implementing one of these solutions, the entropy can be:
- Copied infinite times during transmission
- Stored and analyzed later
- Intercepted without detection

The quantum properties are only enforced at the API level, not during transmission.