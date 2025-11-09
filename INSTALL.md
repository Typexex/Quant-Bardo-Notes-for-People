# Installation Guide

This guide will help you install and set up BardoQuant Encryption in your project.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Gradle Setup](#gradle-setup)
- [Maven Setup](#maven-setup)
- [Manual Installation](#manual-installation)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required
- **JDK 17 or higher**
- **Kotlin 1.9.20 or higher**

### Recommended
- Gradle 8.0+ or Maven 3.8+
- IDE with Kotlin support (IntelliJ IDEA, Android Studio, VS Code)

### Check Your Environment

```bash
# Check Java version
java -version

# Check Kotlin version
kotlinc -version

# Check Gradle version
./gradlew --version
```

## Installation Methods

### Method 1: Gradle (Kotlin DSL) - Recommended

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.bardoquant:bardoquant:2.0.0")
}
```

Full `build.gradle.kts` example:

```kotlin
plugins {
    kotlin("jvm") version "1.9.20"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.github.bardoquant:bardoquant:2.0.0")
    
    // These dependencies are included transitively
    // implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    // implementation("com.google.code.gson:gson:2.10.1")
}

kotlin {
    jvmToolchain(17)
}
```

### Method 2: Gradle (Groovy DSL)

Add to your `build.gradle`:

```groovy
dependencies {
    implementation 'io.github.bardoquant:bardoquant:2.0.0'
}
```

### Method 3: Maven

Add to your `pom.xml`:

```xml
<dependencies>
    <dependency>
        <groupId>io.github.bardoquant</groupId>
        <artifactId>bardoquant</artifactId>
        <version>2.0.0</version>
    </dependency>
</dependencies>
```

### Method 4: Manual Installation

1. **Download the JAR files:**
   - `bardoquant-2.0.0.jar`
   - `bcprov-jdk18on-1.77.jar`
   - `bcpkix-jdk18on-1.77.jar`
   - `gson-2.10.1.jar`

2. **Add to your classpath:**

```bash
# Compile
kotlinc -cp "bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar:gson-2.10.1.jar" \
    YourApp.kt -include-runtime -d your-app.jar

# Run
java -cp "your-app.jar:bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar:gson-2.10.1.jar" \
    YourAppKt
```

## Gradle Setup

### Initialize Gradle Wrapper

If you're starting from scratch:

```bash
# Create new Kotlin project
mkdir my-secure-app
cd my-secure-app

# Initialize Gradle
gradle init --type kotlin-application

# Or manually create structure:
mkdir -p src/main/kotlin
mkdir -p src/test/kotlin
```

### Generate Gradle Wrapper

```bash
# Generate wrapper files
gradle wrapper --gradle-version 8.5

# This creates:
# - gradlew (Unix script)
# - gradlew.bat (Windows script)
# - gradle/wrapper/gradle-wrapper.jar
# - gradle/wrapper/gradle-wrapper.properties
```

### Project Structure

```
my-secure-app/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── gradlew
├── gradlew.bat
├── gradle/
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
└── src/
    ├── main/
    │   └── kotlin/
    │       └── com/example/
    │           └── MyApp.kt
    └── test/
        └── kotlin/
            └── com/example/
                └── MyAppTest.kt
```

## Maven Setup

### Create `pom.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>my-secure-app</artifactId>
    <version>1.0.0</version>

    <properties>
        <kotlin.version>1.9.20</kotlin.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.jetbrains.kotlin</groupId>
            <artifactId>kotlin-stdlib</artifactId>
            <version>${kotlin.version}</version>
        </dependency>
        
        <dependency>
            <groupId>io.github.bardoquant</groupId>
            <artifactId>bardoquant</artifactId>
            <version>2.0.0</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.jetbrains.kotlin</groupId>
                <artifactId>kotlin-maven-plugin</artifactId>
                <version>${kotlin.version}</version>
                <executions>
                    <execution>
                        <id>compile</id>
                        <phase>compile</phase>
                        <goals>
                            <goal>compile</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

## Verification

### 1. Create a Test File

Create `src/main/kotlin/Test.kt`:

```kotlin
import io.github.bardoquant.BardoQuantEncryption
import io.github.bardoquant.QuantumCleanResult

fun main() {
    println("Testing BardoQuant Installation...")
    
    val original = "Hello, BardoQuant!"
    val encrypted = BardoQuantEncryption.encrypt(original)
    
    println("✅ Encryption successful")
    
    when (val result = BardoQuantEncryption.decrypt(encrypted)) {
        is QuantumCleanResult.Decrypted -> {
            if (result.data == original) {
                println("✅ Decryption successful")
                println("✅ Installation verified!")
            }
        }
        else -> println("❌ Decryption failed")
    }
}
```

### 2. Run the Test

```bash
# With Gradle
./gradlew run

# With Maven
mvn exec:java -Dexec.mainClass="TestKt"

# Manual
kotlinc -cp bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar Test.kt -include-runtime -d test.jar
java -cp test.jar:bardoquant-2.0.0.jar:bcprov-jdk18on-1.77.jar TestKt
```

Expected output:
```
Testing BardoQuant Installation...
✅ Encryption successful
✅ Decryption successful
✅ Installation verified!
```

## Android Integration

### Add to `build.gradle` (app module)

```groovy
dependencies {
    implementation 'io.github.bardoquant:bardoquant:2.0.0'
    
    // If you get "Duplicate class" errors, add:
    configurations.all {
        exclude group: 'org.bouncycastle', module: 'bcprov-jdk15on'
    }
}
```

### ProGuard Rules

Add to `proguard-rules.pro`:

```proguard
# BardoQuant
-keep class io.github.bardoquant.** { *; }

# Bouncy Castle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Gson
-keep class com.google.gson.** { *; }
-keepattributes Signature
-keepattributes *Annotation*
```

### Permissions

No special permissions required! BardoQuant works entirely offline.

## Troubleshooting

### Issue: "Could not find io.github.bardoquant:bardoquant:2.0.0"

**Solution 1:** Ensure Maven Central is in your repositories:

```kotlin
repositories {
    mavenCentral()
}
```

**Solution 2:** For local development, publish locally:

```bash
./gradlew publishToMavenLocal
```

Then use:

```kotlin
repositories {
    mavenLocal()
}
```

### Issue: "Duplicate class" errors with Bouncy Castle

**Solution:** Exclude conflicting versions:

```kotlin
configurations.all {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
}
```

### Issue: "SecurityException: Kyber KeyPair generation failed"

**Solution:** Ensure Bouncy Castle PQC provider is available:

```kotlin
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

fun ensureProviders() {
    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())
}
```

### Issue: "OutOfMemoryError" during encryption

**Solution:** Increase JVM heap size:

```bash
# Gradle
org.gradle.jvmargs=-Xmx2048m

# Java
java -Xmx2048m -jar your-app.jar
```

### Issue: Slow performance

**Solution:** Adjust PBKDF2 iterations:

```kotlin
import io.github.bardoquant.BardoQuantConfig

BardoQuantConfig.pbkdf2Iterations = 150000  // Faster, less secure
```

### Issue: "NoClassDefFoundError: com/google/gson/Gson"

**Solution:** Add Gson dependency explicitly:

```kotlin
dependencies {
    implementation("com.google.code.gson:gson:2.10.1")
}
```

### Issue: ClassLoader issues in OSGi/modular environments

**Solution:** Ensure proper module configuration:

```kotlin
// module-info.java
module your.module {
    requires io.github.bardoquant;
    requires org.bouncycastle.provider;
    requires com.google.gson;
}
```

## Build from Source

### Clone the Repository

```bash
git clone https://github.com/yourusername/bardo-quant.git
cd bardo-quant
```

### Build

```bash
# Build JAR
./gradlew build

# Run tests
./gradlew test

# Publish to local Maven repository
./gradlew publishToMavenLocal
```

### Artifacts Location

```
build/libs/
├── bardoquant-2.0.0.jar          # Main JAR
├── bardoquant-2.0.0-sources.jar  # Sources
└── bardoquant-2.0.0-javadoc.jar  # Documentation
```

## IDE Setup

### IntelliJ IDEA

1. **File → New → Project from Existing Sources**
2. Select `build.gradle.kts`
3. Click **OK**
4. Wait for Gradle sync

### Android Studio

1. **File → New → Import Project**
2. Select project directory
3. Choose "Gradle" as external model
4. Click **Finish**

### VS Code

1. Install **Kotlin Language** extension
2. Install **Gradle for Java** extension
3. Open project folder
4. Run Gradle tasks from sidebar

## Dependencies Overview

### Required Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Kotlin Stdlib | 1.9.20+ | Kotlin runtime |
| Bouncy Castle Provider | 1.77 | Cryptographic operations |
| Bouncy Castle PQC | 1.77 | Post-quantum cryptography |
| Gson | 2.10.1 | JSON serialization |

### Optional Dependencies

| Dependency | Purpose |
|------------|---------|
| Kotlinx Coroutines | Async operations |
| SLF4J | Custom logging |
| JUnit 5 | Testing |

## Next Steps

1. ✅ Installation complete
2. 📖 Read the [README.md](README.md) for usage examples
3. 🔐 Review [SECURITY.md](SECURITY.md) for best practices
4. 💡 Check [examples/](examples/) for code samples
5. 🤝 See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

## Support

- 📖 Documentation: [README.md](README.md)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/bardo-quant/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/bardo-quant/discussions)
- 📧 Email: support@bardoquant.io

---

**Having trouble?** Open an issue on GitHub with:
- Your environment (OS, JDK version, Kotlin version)
- Error messages (full stack trace)
- Build configuration (build.gradle.kts or pom.xml)

