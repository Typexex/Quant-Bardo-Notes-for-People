# 🔐 BardoQuant Encryption

**A powerful post-quantum cryptography encryption library combining CRYSTALS-Kyber768 with multi-layer symmetric encryption.**

Originally developed for **Bardo Notes for People** (available on Google Play) and released in **Bardo 1.1 Beta**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9.20-blue.svg)](https://kotlinlang.org)
[![Security: Post-Quantum](https://img.shields.io/badge/Security-Post--Quantum-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 🌟 Features

### Post-Quantum Cryptography
- **CRYSTALS-Kyber768** KEM (NIST Post-Quantum Cryptography standard)
- **Security Level 3** (192-bit equivalent)
- **Quantum-computer resistant** protection
- Forward secrecy through ephemeral Kyber keys

### Multi-Layer Encryption
- **AES-256-GCM** (first layer)
- **ChaCha20** (second layer)
- **Enhanced Quantum Layer** (16 rounds of SHA-512)
- Dynamic obfuscation

### Advanced Key Derivation
- **HKDF-Extract** with Kyber shared secret
- Multi-round hashing (3-5 rounds)
- **PBKDF2** with 300,000 iterations
- Independent keys for each encryption layer

### Additional Security Features
- Noise injection (10-15% of data size)
- Enhanced entropy from system parameters
- Timing attack protection (constant-time comparison)
- HMAC-SHA512 checksums
- Multiple key systems
- Decoy checksums for stealth

### Backward Compatibility
- **v2.0** (current): CRYSTALS-Kyber768 + Enhanced protection
- **v1.1** (legacy): Optimized quantum layer
- **v1.0** (legacy): Full power mode

## 🚀 Quick Start

### Installation

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.bardoquant:bardoquant:2.0.0")
}
```

### Basic Usage

```kotlin
import io.github.bardoquant.BardoQuantEncryption
import io.github.bardoquant.QuantumCleanResult

// Encrypt data
val originalData = "Your sensitive data here"
val encrypted = BardoQuantEncryption.encrypt(originalData)

// Decrypt data
when (val result = BardoQuantEncryption.decrypt(encrypted)) {
    is QuantumCleanResult.Decrypted -> {
        println("Decrypted: ${result.data}")
    }
    is QuantumCleanResult.NotEncrypted -> {
        println("Data was not encrypted")
    }
    is QuantumCleanResult.Error -> {
        println("Error: ${result.message}")
    }
}

// Check if data is encrypted
if (BardoQuantEncryption.isEncrypted(encrypted)) {
    println("Data is BardoQuantum protected")
}
```

### Configuration

```kotlin
import io.github.bardoquant.BardoQuantConfig
import io.github.bardoquant.ConsoleLogger

// Enable debug logging
BardoQuantConfig.enableDebugLogging = true

// Use custom logger
BardoQuantConfig.logger = ConsoleLogger()

// Adjust parameters
BardoQuantConfig.pbkdf2Iterations = 300000
BardoQuantConfig.quantumRounds = 16
```

### Custom Logger

```kotlin
import io.github.bardoquant.BardoQuantLogger

class MyCustomLogger : BardoQuantLogger {
    override fun debug(message: String) {
        // Your debug logging
    }
    
    override fun info(message: String) {
        // Your info logging
    }
    
    override fun warn(message: String) {
        // Your warning logging
    }
    
    override fun error(message: String, throwable: Throwable?) {
        // Your error logging
    }
}

BardoQuantConfig.logger = MyCustomLogger()
```

## 📊 Architecture

### Encryption Flow

```
Original Data
    ↓
[1] Noise Injection (10-15%)
    ↓
[2] Kyber768 KeyPair Generation
    ↓
[3] KEM Encapsulation → Shared Secret
    ↓
[4] HKDF Key Derivation → AES, ChaCha20, Quantum Keys
    ↓
[5] PBKDF2 Enhancement (300k iterations)
    ↓
[6] AES-256-GCM Encryption
    ↓
[7] ChaCha20 Encryption
    ↓
[8] Dynamic Obfuscation
    ↓
[9] Enhanced Quantum Layer (16 rounds SHA-512)
    ↓
[10] HMAC-SHA512 Checksum
    ↓
Encrypted JSON Output
```

### Decryption Flow

```
Encrypted JSON
    ↓
[1] Version Detection (v2.0, v1.1, v1.0)
    ↓
[2] Kyber Private Key Restoration
    ↓
[3] KEM Decapsulation → Shared Secret
    ↓
[4] Key Derivation (HKDF + PBKDF2)
    ↓
[5] Checksum Verification (timing-safe)
    ↓
[6] Enhanced Quantum Layer Removal
    ↓
[7] Deobfuscation
    ↓
[8] ChaCha20 Decryption
    ↓
[9] AES-256-GCM Decryption
    ↓
[10] Noise Removal
    ↓
Original Data
```

## 🔒 Security

### Cryptographic Primitives

| Component | Algorithm | Key Size | Security Level |
|-----------|-----------|----------|----------------|
| Post-Quantum KEM | CRYSTALS-Kyber768 | N/A | NIST Level 3 (192-bit) |
| Symmetric Layer 1 | AES-256-GCM | 256 bits | 256-bit |
| Symmetric Layer 2 | ChaCha20 | 256 bits | 256-bit |
| Key Derivation | HKDF-SHA512 | N/A | 512-bit |
| Key Enhancement | PBKDF2-HMAC-SHA256 | 256 bits | 300k iterations |
| Quantum Layer | SHA-512 (16 rounds) | 512 bits | Quantum-resistant |
| Checksum | HMAC-SHA512 | 512 bits | 512-bit |

### Threat Model

**Protected Against:**
- ✅ Quantum computer attacks (Shor's algorithm)
- ✅ Brute-force attacks
- ✅ Timing attacks (constant-time comparison)
- ✅ Side-channel attacks
- ✅ Known-plaintext attacks
- ✅ Chosen-plaintext attacks
- ✅ Man-in-the-middle attacks (forward secrecy)

**Assumptions:**
- Secure key storage (user's responsibility)
- Secure random number generation (system entropy)
- No malicious code execution environment

## 📱 About Bardo Notes for People

BardoQuant was originally developed for **Bardo Notes for People**, a secure note-taking application available on Google Play.

**App Features:**
- Post-quantum encryption for your notes
- Secure local storage
- Privacy-focused design
- No data collection

**Download:** [Bardo Notes for People on Google Play](https://play.google.com/store/apps)

**Version History:**
- **Bardo 1.1 Beta** - BardoQuant v2.0 with Kyber768 released
- **Bardo 1.0** - Initial release with multi-layer encryption

## 🧪 Testing

```bash
./gradlew test
```

Example test:

```kotlin
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BardoQuantTest {
    @Test
    fun testEncryptionDecryption() {
        val original = "Test data for encryption"
        val encrypted = BardoQuantEncryption.encrypt(original)
        
        assertTrue(BardoQuantEncryption.isEncrypted(encrypted))
        
        val result = BardoQuantEncryption.decrypt(encrypted)
        assertTrue(result is QuantumCleanResult.Decrypted)
        
        val decrypted = (result as QuantumCleanResult.Decrypted).data
        assertEquals(original, decrypted)
    }
}
```

## 📦 Dependencies

- **Kotlin** 1.9.20+
- **Bouncy Castle** 1.77+ (PQC provider)
- **Gson** 2.10.1+ (JSON serialization)
- **Kotlinx Coroutines** 1.7.3+ (optional, for async operations)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/yourusername/bardo-quant.git
cd bardo-quant
./gradlew build
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔐 Security Policy

Please see [SECURITY.md](SECURITY.md) for information about reporting security vulnerabilities.

## 📚 Documentation

### API Reference

**Main Functions:**

```kotlin
// Encrypt data
fun encrypt(data: String): String

// Decrypt data
fun decrypt(encryptedData: String): QuantumCleanResult

// Check if data is encrypted
fun isEncrypted(data: String): Boolean
```

**Result Types:**

```kotlin
sealed class QuantumCleanResult {
    data class Decrypted(val data: String)
    data class NotEncrypted(val data: String)
    data class Error(val message: String)
}
```

## 🌐 Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [Bouncy Castle](https://www.bouncycastle.org/)

## ⚠️ Important Notes

1. **Key Management**: Always store encryption keys securely
2. **Production Use**: Test thoroughly before production deployment
3. **Backward Compatibility**: v2.0 can decrypt v1.0 and v1.1 encrypted data
4. **Performance**: Quantum-resistant encryption is computationally intensive
5. **Updates**: Keep dependencies updated for security patches

## 📊 Performance

Typical performance on modern hardware:

| Operation | Time (approx.) | Notes |
|-----------|----------------|-------|
| Key Generation | 10-50ms | Kyber768 keypair |
| Encryption (1KB) | 50-150ms | Full multi-layer |
| Decryption (1KB) | 50-150ms | Full verification |
| Encryption (1MB) | 500ms-2s | Scales with data size |

## 🎯 Roadmap

- [ ] Add support for stream encryption
- [ ] Implement key rotation mechanisms
- [ ] Add support for additional PQC algorithms
- [ ] Performance optimizations
- [ ] Hardware security module (HSM) integration
- [ ] Mobile-specific optimizations

## 💡 FAQ

**Q: Is this library production-ready?**  
A: Yes, it has been used in production in Bardo Notes for People app.

**Q: What is the performance impact?**  
A: Post-quantum encryption is more computationally intensive than traditional encryption. Expect 2-5x overhead compared to AES-only encryption.

**Q: Can I use this with Android?**  
A: Yes! This library was originally designed for Android. Just ensure Bouncy Castle is properly configured.

**Q: How do I migrate from v1.x?**  
A: v2.0 automatically detects and decrypts v1.0 and v1.1 formats. Simply decrypt old data and re-encrypt with v2.0.

**Q: Is the encrypted data portable?**  
A: Yes, encrypted data is JSON-formatted and can be transferred between systems.

## 🙏 Acknowledgments

- NIST for standardizing post-quantum cryptography
- Bouncy Castle team for excellent cryptographic library
- The CRYSTALS-Kyber team for the KEM algorithm
- All contributors and users of Bardo Notes for People

## 📧 Contact

For questions, issues, or collaboration opportunities:
- GitHub Issues: [Report an issue](https://github.com/yourusername/bardo-quant/issues)
- Email: security@bardoquant.io

---

**Made with ❤️ by the BardoQuantum Security Team**

*Protecting your data in the post-quantum era.*

