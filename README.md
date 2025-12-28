Bardo Quant Encryption

A powerful post-quantum cryptography encryption library combining CRYSTALS-Kyber768 with multi-layer symmetric encryption.

Originally developed for Bardo Notes for People, available on Google Play, and released in Bardo 1.1 Beta.

License: MIT

Kotlin: 1.9.20

Security: Post-Quantum

Features

Post-Quantum Cryptography
- CRYSTALS-Kyber768 KEM, NIST Post-Quantum Cryptography standard
- Security Level 3, 192-bit equivalent
- Quantum-computer resistant protection
- Forward secrecy through ephemeral Kyber keys

Multi-Layer Encryption
- AES-256-GCM, first layer
- ChaCha20, second layer
- Dynamic obfuscation

Advanced Key Derivation
- HKDF-Extract with Kyber shared secret
- Multi-round hashing, 3-5 rounds
- PBKDF2 with 300,000 iterations
- Independent keys for each encryption layer

Additional Security Features
- Noise injection, 10-15% of data size
- Enhanced entropy from system parameters
- Timing attack protection, constant-time comparison
- HMAC-SHA512 checksums
- Multiple key systems
- Decoy checksums for stealth

Backward Compatibility
- v2.0 current: CRYSTALS-Kyber768 + Enhanced protection
- v1.1 legacy: Optimized quantum layer
- v1.0 legacy: Full power mode

Quick Start

Installation: Add the implementation dependency for io.github.bardoquant:bardoquant version 2.0.0 to your build.gradle.kts.

Basic Usage: Import BardoQuantEncryption and QuantumCleanResult. Encrypt a string, decrypt it handling Decrypted, NotEncrypted, or Error results, and check if data is encrypted.

Configuration: Import BardoQuantConfig and ConsoleLogger. Enable debug logging, set custom logger, adjust PBKDF2 iterations to 300000.

Custom Logger: Implement BardoQuantLogger with debug, info, warn, and error methods, then set it in config.

Architecture

Encryption Flow: Original data to noise injection 10-15%, Kyber768 keypair generation, KEM encapsulation to shared secret, HKDF key derivation for AES and ChaCha20 keys, PBKDF2 enhancement 300k iterations, AES-256-GCM encryption, ChaCha20 encryption, dynamic obfuscation, HMAC-SHA512 checksum, to encrypted JSON output.

Decryption Flow: Encrypted JSON to version detection v2.0 v1.1 v1.0, Kyber private key restoration, KEM decapsulation to shared secret, key derivation HKDF + PBKDF2, checksum verification timing-safe, deobfuscation, ChaCha20 decryption, AES-256-GCM decryption, noise removal, to original data.

Security

Cryptographic Primitives
Component | Algorithm | Key Size | Security Level
Post-Quantum KEM | CRYSTALS-Kyber768 | N/A | NIST Level 3 (192-bit)
Symmetric Layer 1 | AES-256-GCM | 256 bits | 256-bit
Symmetric Layer 2 | ChaCha20 | 256 bits | 256-bit
Key Derivation | HKDF-SHA512 | N/A | 512-bit
Key Enhancement | PBKDF2-HMAC-SHA256 | 256 bits | 300k iterations
Checksum | HMAC-SHA512 | 512 bits | 512-bit

Threat Model
Protected Against: Quantum computer attacks (Shor's algorithm), brute-force attacks, timing attacks (constant-time comparison), side-channel attacks, known-plaintext attacks, chosen-plaintext attacks, man-in-the-middle attacks (forward secrecy).

Assumptions: Secure key storage (user's responsibility), secure random number generation (system entropy), no malicious code execution environment.

About Bardo Notes for People

BardoQuant was originally developed for Bardo Notes for People, a secure note-taking application available on Google Play.

App Features: Post-quantum encryption for notes, secure local storage, privacy-focused design, no data collection.

Download: Bardo Notes for People on Google Play.

Version History: Bardo 1.1 Beta - BardoQuant v2.0 with Kyber768 released. Bardo 1.0 - Initial release with multi-layer encryption.

Testing: Run Gradle test task.

Example test: JUnit test for encryption-decryption round trip, asserting encrypted check, decrypted result, and equality to original.

Dependencies
- Kotlin 1.9.20+
- Bouncy Castle 1.77+ PQC provider
- Gson 2.10.1+ for JSON serialization
- Kotlinx Coroutines 1.7.3+ optional for async operations

Contributing

We welcome contributions. For development setup, see SETUP.md.

Development Setup: Clone the GitHub repo, change to directory, run Gradle build.

License

This project is licensed under the MIT License.

Documentation

API Reference

Main Functions: encrypt(data: String) returns String, decrypt(encryptedData: String) returns QuantumCleanResult, isEncrypted(data: String) returns Boolean.

Result Types: Sealed class QuantumCleanResult with Decrypted(data: String), NotEncrypted(data: String), Error(message: String).

Resources
- NIST Post-Quantum Cryptography
- CRYSTALS-Kyber
- Bouncy Castle

Important Notes
1. Key Management: Always store encryption keys securely.
2. Production Use: Test thoroughly before production deployment.
3. Backward Compatibility: v2.0 can decrypt v1.0 and v1.1 encrypted data.
4. Performance: Quantum-resistant encryption is computationally intensive.
5. Updates: Keep dependencies updated for security patches.

Performance

Typical on modern hardware:
Operation | Time approx. | Notes
Key Generation | 10-50ms | Kyber768 keypair
Encryption 1KB | 50-150ms | Full multi-layer
Decryption 1KB | 50-150ms | Full verification
Encryption 1MB | 500ms-2s | Scales with data size

Roadmap
- Add support for stream encryption
- Implement key rotation mechanisms
- Add support for additional PQC algorithms
- Performance optimizations
- Hardware security module HSM integration
- Mobile-specific optimizations

FAQ

Q: Is this library production-ready? A: Yes, used in production in Bardo Notes for People app.

Q: What is the performance impact? A: More intensive than traditional, expect 2-5x overhead vs AES-only.

Q: Can I use this with Android? A: Yes, designed for Android, ensure Bouncy Castle configured.

Q: How do I migrate from v1.x? A: v2.0 detects and decrypts v1.0 and v1.1, decrypt old and re-encrypt with v2.0.

Q: Is the encrypted data portable? A: Yes, JSON-formatted, transferable between systems.

Acknowledgments
- NIST for standardizing post-quantum cryptography
- Bouncy Castle team for excellent cryptographic library
- CRYSTALS-Kyber team for the KEM algorithm
- All contributors and users of Bardo Notes for People

## Contact

- General: support@bardotypexai.com
- Legal: legal@bardotypexai.com  
- DMCA: dmca@bardotypexai.com
- Partnerships: partners@bardotypexai.com

Made by the TypexAI, TypexEx.

