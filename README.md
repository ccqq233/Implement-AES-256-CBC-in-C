# Implement-AES-256-CBC-in-C
This program will generate a 256 bit key and use AES-256-CBC to encrypt and decrypt the specified file.

### Important Note
> When encrypting/decrypting files, the output filename must be different from the input filename. Otherwise, encryption/decryption will fail and corrupt the original file.

### Before Use
1. Confirm OpenSSL development libraries are properly installed  
2. Ensure header file paths are correctly configured  

---

### Program Security Guarantees

#### 🔒 Secure Key Generation & Management
1. **Unpredictable Key Generation**  
   Uses OpenSSL's `RAND_priv_bytes()` CSPRNG:  
   - Dedicated interface for sensitive data (isolated from general RNG)  
   - Guarantees unpredictability and zero statistical bias  
   - Prevents side-channel attacks from resource contention  

2. **Entropy Assurance**  
   Verifies sufficient cryptographic entropy before key generation  

3. **Secure Memory Wiping**  
   Safely overwrites key storage memory upon program exit  

#### 🛡️ Core AES-256 Algorithm Security
1. **Mathematical Foundation & Attack Resistance**  
   - Based on rigorous finite field arithmetic  
   - Withstood 20+ years of global cryptanalysis  
   - Highly resistant to differential/linear cryptanalysis, integral attacks, etc.  

2. **Key Space Strength**  
   - 256-bit keyspace ≈ 1.1579 × 10⁷⁷ possible combinations  
   - Brute-force time exceeds universe's age  

3. **Round Structure Advantage**  
   14 encryption rounds significantly increase attack complexity  

#### 🔄 CBC Mode Critical Advantages
1. **Semantic Security**  
   - Random unique IVs ensure identical plaintext → different ciphertext  
   - Hides statistical patterns and repetitive structures  

2. **Avalanche Diffusion Effect**  
   - Single-bit plaintext/IV change unpredictably alters all subsequent blocks  
   - Effectively thwarts ciphertext tampering attacks  

3. **IV's Vital Role**  
   Same message + different IV = completely different ciphertext  

> **PS: CBC Necessity**  
> Without CBC, identical plaintext blocks produce identical ciphertext blocks, leading to:  
> - Data pattern leakage (e.g., similar color areas in images remain recognizable)  
> - Significantly reduced security
