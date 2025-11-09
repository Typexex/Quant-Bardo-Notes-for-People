# BardoQuant Examples

This directory contains practical examples demonstrating how to use BardoQuant Encryption in various scenarios.

## Examples

### 1. BasicUsageExample.kt

Demonstrates the fundamental operations:
- Basic encryption and decryption
- Checking if data is encrypted
- Handling different result types
- Error handling

**Run:**
```bash
kotlinc BasicUsageExample.kt -include-runtime -d basic.jar && java -jar basic.jar
```

### 2. AdvancedConfigurationExample.kt

Shows advanced configuration options:
- Custom logger implementation
- Performance tuning (PBKDF2 iterations, quantum rounds)
- Benchmarking encryption performance
- Configuration best practices

**Run:**
```bash
kotlinc AdvancedConfigurationExample.kt -include-runtime -d advanced.jar && java -jar advanced.jar
```

### 3. RealWorldExample.kt

Demonstrates a real-world use case:
- Secure note storage system
- CRUD operations on encrypted data
- Import/export functionality
- Data validation and security checks

**Run:**
```bash
kotlinc RealWorldExample.kt -include-runtime -d realworld.jar && java -jar realworld.jar
```

## Quick Start

### As Gradle Project

Add BardoQuant to your dependencies:

```kotlin
dependencies {
    implementation("io.github.bardoquant:bardoquant:2.0.0")
}
```

### Standalone Compilation

1. Download BardoQuant JAR
2. Compile with dependencies:

```bash
kotlinc -cp bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar YourExample.kt -include-runtime -d output.jar
java -cp output.jar:bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar YourExampleKt
```

## Common Patterns

### Pattern 1: Simple Encryption

```kotlin
val encrypted = BardoQuantEncryption.encrypt("my data")
```

### Pattern 2: Safe Decryption

```kotlin
when (val result = BardoQuantEncryption.decrypt(data)) {
    is QuantumCleanResult.Decrypted -> println("Success: ${result.data}")
    is QuantumCleanResult.NotEncrypted -> println("Not encrypted: ${result.data}")
    is QuantumCleanResult.Error -> println("Error: ${result.message}")
}
```

### Pattern 3: Configuration

```kotlin
BardoQuantConfig.apply {
    enableDebugLogging = true
    pbkdf2Iterations = 300000
    logger = CustomLogger()
}
```

## Performance Tips

1. **Adjust iterations for your use case:**
   - High security: 300,000+ iterations
   - Balanced: 200,000 iterations
   - Fast: 100,000 iterations

2. **Disable debug logging in production:**
   ```kotlin
   BardoQuantConfig.enableDebugLogging = false
   ```

3. **Use NoOpLogger for maximum performance:**
   ```kotlin
   BardoQuantConfig.logger = NoOpLogger()
   ```

## Security Notes

- Always store keys securely
- Use HTTPS for transmitting encrypted data
- Implement proper error handling
- Test thoroughly before production use
- Keep dependencies updated

## Need Help?

- Check the main [README.md](../README.md)
- Review [SECURITY.md](../SECURITY.md)
- Open an issue on GitHub
- Email: support@bardoquant.io

