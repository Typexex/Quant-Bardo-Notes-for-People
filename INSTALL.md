Installation Guide

This guide helps you install and set up BardoQuant Encryption in your project.

Table of Contents
- Prerequisites
- Installation Methods
- Gradle Setup
- Maven Setup
- Manual Installation
- Verification
- Troubleshooting

Prerequisites

Required: JDK 17 or higher, Kotlin 1.9.20 or higher.

Recommended: Gradle 8.0+ or Maven 3.8+, IDE with Kotlin support like IntelliJ IDEA, Android Studio, or VS Code.

Check your environment by running commands to verify Java, Kotlin, and Gradle versions.

Installation Methods

Method 1: Gradle with Kotlin DSL, recommended. Add the implementation dependency for io.github.bardoquant:bardoquant version 2.0.0 to your build.gradle.kts file.

For a full example, apply the Kotlin JVM plugin version 1.9.20, add mavenCentral to repositories, include the BardoQuant dependency, and set JVM toolchain to 17. Transitive dependencies like Bouncy Castle and Gson are included automatically.

Method 2: Gradle with Groovy DSL. Add the implementation dependency for io.github.bardoquant:bardoquant:2.0.0 to your build.gradle file.

Method 3: Maven. Add a dependency in your pom.xml for group io.github.bardoquant, artifact bardoquant, version 2.0.0.

Method 4: Manual. Download JAR files: bardoquant-2.0.0, bcprov-jdk18on-1.77, bcpkix-jdk18on-1.77, gson-2.10.1. Then compile and run your app by including them in the classpath.

Gradle Setup

If starting from scratch, create a directory for your project, initialize Gradle with a Kotlin application type, or manually set up source directories for main and test Kotlin code.

Generate the Gradle wrapper by specifying version 8.5, which creates the necessary scripts and properties files.

The project structure includes build.gradle.kts, settings.gradle.kts, gradle.properties, wrapper files, and source folders under src/main/kotlin and src/test/kotlin with package directories.

Maven Setup

Create a pom.xml with model version 4.0.0, your group and artifact IDs, version, properties for Kotlin 1.9.20 and Java 17 source/target. Add dependencies for Kotlin stdlib and BardoQuant. Include the Kotlin Maven plugin for compilation.

Verification

Create a test Kotlin file that imports BardoQuantEncryption and QuantumCleanResult, then in main, encrypt and decrypt a sample string like "Hello, BardoQuant!" and print success messages if it works.

Run the test using Gradle run task, Maven exec java with main class TestKt, or manual compile and java run with JARs in classpath.

Expected output confirms testing, encryption, decryption, and verification success.

Android Integration

In your app module build.gradle, add the BardoQuant implementation dependency. If duplicate class errors occur, exclude older Bouncy Castle modules in configurations.

For ProGuard, keep classes for BardoQuant, Bouncy Castle, and Gson, with attributes for signatures and annotations.

No special permissions needed, as it works offline.

Troubleshooting

If dependency not found, ensure mavenCentral in repositories or publish locally and use mavenLocal.

For duplicate Bouncy Castle classes, exclude conflicting versions.

If Kyber key generation fails, add Bouncy Castle providers in code.

For out of memory during encryption, increase JVM heap size in Gradle or Java options.

For slow performance, reduce PBKDF2 iterations in BardoQuantConfig for faster but less secure operation.

If Gson class not found, add it explicitly as a dependency.

For classloader issues in modular setups, require the modules in module-info.java.

Build from Source

Clone the repository from GitHub, then build the JAR, run tests, or publish to local Maven using Gradle tasks.

Artifacts are in build/libs: main JAR, sources, and javadoc.

IDE Setup

In IntelliJ IDEA, open project from existing sources selecting build.gradle.kts and sync.

In Android Studio, import project with Gradle model.

In VS Code, install Kotlin and Gradle extensions, open folder, and run tasks from sidebar.

Dependencies Overview

Required: Kotlin stdlib 1.9.20+ for runtime, Bouncy Castle Provider and PQC 1.77 for crypto, Gson 2.10.1 for JSON.

Optional: Kotlinx Coroutines for async, SLF4J for logging, JUnit 5 for testing.

Next Steps

Installation complete. Read README.md for usage, check examples folder for samples, see SETUP.md for dev setup.

Support

Documentation in README.md, issues and discussions on GitHub, email typexai@proton.me

If trouble, open GitHub issue with environment details, error messages, and build config.