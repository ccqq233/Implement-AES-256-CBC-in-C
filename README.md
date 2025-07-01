# Implement-AES-256-CBC-in-C
This program will generate a 256 bit key and use AES-256-CBC to encrypt and decrypt the specified file.

### Important Note
When encrypting/decrypting files, the output filename must be different from the input filename. Otherwise, encryption/decryption will fail and corrupt the original file.

### Before Use
1. Confirm OpenSSL development libraries are properly installed  
2. Ensure header file paths are correctly configured  

---

### Program Security Guarantees

#### Secure Key Generation & Management
1. This program generates unpredictable random bytes as keys using OpenSSL's cryptographic secure pseudo-random number generator (CSPRNG), meeting the requirements of unpredictability and no statistical bias. The RAND_priv-bytes() function in the code is dedicated to generating sensitive data and is isolated from the ordinary random number interface RAND-bytes() to avoid side channel attacks caused by resource competition.

2.  Before generating the key, the program will ensure that the random number generator has sufficient entropy to generate cryptographic secure random numbers.

3. When exiting the program, the memory area where the key is stored will be securely overwritten to ensure that the key does not remain in memory for recovery or theft.


#### The security of AES-256 algorithm
1. After nearly 20 years of public analysis and attack attempts by top cryptographers around the world, the AES algorithm has yet to discover any effective mathematical vulnerabilities that can significantly outperform brute force cracking. Its design is based on a solid mathematical foundation (operations on finite fields).
   
2. The key space of this algorithm is quite large, with a 256 bit key meaning there are approximately 1.1579 x 10 ^ 77 possible keys. Even with the most powerful supercomputers currently available for brute force cracking, the time required far exceeds the age of the universe.
   
3. AES has strong resistance to various known cryptanalysis attacks, such as differential cryptanalysis, linear cryptanalysis, integral attacks, etc., especially when the number of rounds is sufficient (AES-256 has 14 rounds). The complexity of these attacks is still much higher than brute force cracking.


#### CBC mode XORing the previous ciphertext block with the current plaintext block before encrypting, which brings key benefits:
1. Semantic security: Even if identical plaintext blocks appear in different positions of the message (or even in different messages), as long as the initialization vector IV is random and unique, and the previous ciphertext block is different, they will be encrypted into completely different ciphertext blocks, which hides the statistical patterns and repetitive structures of the plaintext. In other words, assuming there is no CBC mode, the same plaintext block will be encrypted into the same ciphertext block, which will expose the pattern of the data (for example, large areas of the same color in an image still have similar features after encryption, with low security).

2. Diffusion: A change in one plaintext or IV bit during the encryption process can cause unpredictable changes to all subsequent ciphertext blocks (avalanche effect), making it difficult for attackers to intentionally tamper with the ciphertext or predict the result.

3. Random and unique IV is the key to the safety of CBC: even if the same message is encrypted multiple times, as long as the IV is different, the resulting ciphertext is completely different, preventing attackers from inferring the similarity or content of plaintext by comparing ciphertexts.
