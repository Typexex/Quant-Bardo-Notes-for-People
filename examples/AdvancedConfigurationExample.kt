package examples

import io.github.bardoquant.BardoQuantEncryption
import io.github.bardoquant.BardoQuantConfig
import io.github.bardoquant.BardoQuantLogger
import io.github.bardoquant.QuantumCleanResult

class CustomLogger : BardoQuantLogger {
    override fun debug(message: String) {
        println("[🔍 DEBUG] $message")
    }
    
    override fun info(message: String) {
        println("[ℹ️  INFO] $message")
    }
    
    override fun warn(message: String) {
        println("[⚠️  WARN] $message")
    }
    
    override fun error(message: String, throwable: Throwable?) {
        println("[❌ ERROR] $message")
        throwable?.let {
            println("  Exception: ${it.javaClass.simpleName}")
            println("  Message: ${it.message}")
        }
    }
}

fun main() {
    println("=== BardoQuant Encryption - Advanced Configuration ===\n")
    
    customLoggingExample()
    println()
    
    performanceTuningExample()
    println()
    
    benchmarkExample()
}

fun customLoggingExample() {
    println("1. Custom Logger Configuration")
    println("-" * 40)
    
    BardoQuantConfig.logger = CustomLogger()
    BardoQuantConfig.enableDebugLogging = true
    
    val data = "Test data with custom logger"
    val encrypted = BardoQuantEncryption.encrypt(data)
    
    val result = BardoQuantEncryption.decrypt(encrypted)
    if (result is QuantumCleanResult.Decrypted) {
        println("\n✅ Encryption/Decryption with custom logger successful!")
    }
}

fun performanceTuningExample() {
    println("2. Performance Tuning")
    println("-" * 40)
    
    println("Default configuration:")
    println("  - PBKDF2 Iterations: ${BardoQuantConfig.pbkdf2Iterations}")
    println("  - Quantum Rounds: ${BardoQuantConfig.quantumRounds}")
    println("  - Noise Range: ${BardoQuantConfig.noisePercentageMin}-${BardoQuantConfig.noisePercentageMax}")
    
    BardoQuantConfig.pbkdf2Iterations = 200000
    BardoQuantConfig.quantumRounds = 12
    
    println("\nAdjusted for better performance:")
    println("  - PBKDF2 Iterations: ${BardoQuantConfig.pbkdf2Iterations}")
    println("  - Quantum Rounds: ${BardoQuantConfig.quantumRounds}")
    
    val data = "Performance test data"
    val startTime = System.currentTimeMillis()
    val encrypted = BardoQuantEncryption.encrypt(data)
    val encryptTime = System.currentTimeMillis() - startTime
    
    val decryptStart = System.currentTimeMillis()
    val result = BardoQuantEncryption.decrypt(encrypted)
    val decryptTime = System.currentTimeMillis() - decryptStart
    
    println("\n⏱️  Timings:")
    println("  - Encryption: ${encryptTime}ms")
    println("  - Decryption: ${decryptTime}ms")
    println("  - Total: ${encryptTime + decryptTime}ms")
    
    BardoQuantConfig.pbkdf2Iterations = 300000
    BardoQuantConfig.quantumRounds = 16
}

fun benchmarkExample() {
    println("3. Encryption Benchmark")
    println("-" * 40)
    
    BardoQuantConfig.enableDebugLogging = false
    
    val dataSizes = listOf(
        100 to "100 bytes",
        1024 to "1 KB",
        10240 to "10 KB",
        102400 to "100 KB"
    )
    
    println("\nSize        | Encrypt | Decrypt | Total")
    println("-" * 45)
    
    for ((size, label) in dataSizes) {
        val testData = "x".repeat(size)
        
        val encryptStart = System.currentTimeMillis()
        val encrypted = BardoQuantEncryption.encrypt(testData)
        val encryptTime = System.currentTimeMillis() - encryptStart
        
        val decryptStart = System.currentTimeMillis()
        BardoQuantEncryption.decrypt(encrypted)
        val decryptTime = System.currentTimeMillis() - decryptStart
        
        val total = encryptTime + decryptTime
        
        println("%-11s | %6dms | %6dms | %6dms".format(label, encryptTime, decryptTime, total))
    }
    
    println("\nNote: Times may vary based on system performance")
}

operator fun String.times(n: Int): String = repeat(n)

