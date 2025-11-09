# Quick Setup Guide

This guide will help you set up the BardoQuant project for development or publishing.

## 🚀 Quick Start (For Users)

If you just want to use BardoQuant in your project:

```kotlin
// Add to build.gradle.kts
dependencies {
    implementation("io.github.bardoquant:bardoquant:2.0.0")
}
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

## 🔧 Developer Setup

### 1. Prerequisites

```bash
# Check your environment
java -version   # Should be 17+
git --version   # Any recent version
```

### 2. Clone Repository

```bash
git clone https://github.com/yourusername/bardo-quant.git
cd bardo-quant
```

### 3. Generate Gradle Wrapper (if not present)

The Gradle wrapper allows building without installing Gradle globally.

```bash
# If you have Gradle installed:
gradle wrapper --gradle-version 8.5

# This creates:
# - gradlew (Unix)
# - gradlew.bat (Windows)
# - gradle/wrapper/gradle-wrapper.jar
# - gradle/wrapper/gradle-wrapper.properties
```

**Alternative**: Download wrapper files from an existing project or use these commands:

```bash
# On Unix/Mac
mkdir -p gradle/wrapper
curl -L https://services.gradle.org/distributions/gradle-8.5-bin.zip -o gradle-wrapper.zip

# On Windows (PowerShell)
mkdir -Force gradle\wrapper
Invoke-WebRequest -Uri "https://services.gradle.org/distributions/gradle-8.5-bin.zip" -OutFile gradle-wrapper.zip
```

### 4. Make Gradle Wrapper Executable (Unix/Mac only)

```bash
chmod +x gradlew
```

### 5. Build the Project

```bash
# Unix/Mac
./gradlew build

# Windows
gradlew.bat build
```

Expected output:
```
BUILD SUCCESSFUL in 15s
8 actionable tasks: 8 executed
```

### 6. Run Tests

```bash
./gradlew test

# With coverage report
./gradlew test jacocoTestReport
```

### 7. Run Examples

```bash
# Navigate to examples
cd examples

# Compile and run (requires dependencies in classpath)
kotlinc -cp ../build/libs/bardoquant-2.0.0.jar BasicUsageExample.kt -include-runtime -d basic.jar
java -cp basic.jar:../build/libs/bardoquant-2.0.0.jar BasicUsageExampleKt
```

## 📦 Publishing (For Maintainers)

### Local Testing

```bash
# Publish to local Maven repository
./gradlew publishToMavenLocal

# Artifacts will be in:
# ~/.m2/repository/io/github/bardoquant/bardoquant/2.0.0/
```

### Publishing to Maven Central

1. **Configure credentials** in `~/.gradle/gradle.properties`:

```properties
sonatypeUsername=your-username
sonatypePassword=your-password
signing.keyId=your-key-id
signing.password=your-key-password
signing.secretKeyRingFile=/path/to/secring.gpg
```

2. **Publish**:

```bash
./gradlew publish
```

3. **Release**:

```bash
./gradlew closeAndReleaseRepository
```

## 🎯 Project Structure

```
bardo-quant/
├── src/main/kotlin/          # Source code
├── src/test/kotlin/          # Tests
├── examples/                 # Usage examples
├── build.gradle.kts          # Build configuration
└── README.md                 # Documentation
```

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed structure.

## 🔍 Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Edit files in `src/main/kotlin/io/github/bardoquant/`

### 3. Run Tests

```bash
./gradlew test
```

### 4. Check Code Style

```bash
./gradlew ktlintCheck

# Auto-fix issues
./gradlew ktlintFormat
```

### 5. Build

```bash
./gradlew build
```

### 6. Commit and Push

```bash
git add .
git commit -m "feat: add new feature"
git push origin feature/my-feature
```

### 7. Create Pull Request

Open PR on GitHub

## 🧪 Testing

### Run All Tests

```bash
./gradlew test
```

### Run Specific Test

```bash
./gradlew test --tests BardoQuantEncryptionTest
```

### Run with Coverage

```bash
./gradlew test jacocoTestReport

# View report:
# open build/reports/jacoco/test/html/index.html
```

### Run Examples as Tests

```bash
cd examples
kotlinc -cp ../build/libs/* *.kt -include-runtime -d test.jar
java -cp test.jar:../build/libs/* BasicUsageExampleKt
```

## 🐛 Troubleshooting

### Gradle Wrapper Not Found

If `gradlew` doesn't exist, generate it:

```bash
gradle wrapper --gradle-version 8.5
```

Or download from: https://gradle.org/install/

### Permission Denied (Unix/Mac)

```bash
chmod +x gradlew
```

### OutOfMemoryError

Increase heap size in `gradle.properties`:

```properties
org.gradle.jvmargs=-Xmx4096m
```

### Dependency Resolution Failed

Clear cache:

```bash
./gradlew clean --refresh-dependencies
```

### IDE Not Recognizing Code

Reimport project:

- **IntelliJ**: File → Invalidate Caches → Restart
- **VS Code**: Reload Window

## 📚 Additional Resources

- [INSTALL.md](INSTALL.md) - Installation guide for users
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](SECURITY.md) - Security policy
- [CHANGELOG.md](CHANGELOG.md) - Version history

## 🆘 Getting Help

- **Documentation**: [README.md](README.md)
- **Issues**: https://github.com/yourusername/bardo-quant/issues
- **Email**: support@bardoquant.io

## ✅ Checklist

Before submitting a PR, ensure:

- [ ] Code compiles without errors
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] No new warnings

## 🎉 Ready!

You're all set! Start developing with:

```bash
./gradlew build && ./gradlew test
```

---

**Happy Coding!** 🚀🔐

