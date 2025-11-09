package examples

import io.github.bardoquant.BardoQuantEncryption
import io.github.bardoquant.BardoQuantConfig
import io.github.bardoquant.QuantumCleanResult

fun main() {
    println("=== BardoQuant Encryption - Basic Usage Example ===\n")
    
    BardoQuantConfig.enableDebugLogging = true
    
    basicEncryptionDecryption()
    println()
    
    checkingEncryptedData()
    println()
    
    handlingResults()
    println()
    
    errorHandling()
}

fun basicEncryptionDecryption() {
    println("1. Basic Encryption & Decryption")
    println("-" * 40)
    
    val originalData = "Hello, this is my secret message!"
    println("Original: $originalData")
    
    val encrypted = BardoQuantEncryption.encrypt(originalData)
    println("Encrypted (first 100 chars): ${encrypted.take(100)}...")
    
    when (val result = BardoQuantEncryption.decrypt(encrypted)) {
        is QuantumCleanResult.Decrypted -> {
            println("Decrypted: ${result.data}")
            println("✅ Match: ${result.data == originalData}")
        }
        is QuantumCleanResult.NotEncrypted -> {
            println("Data was not encrypted")
        }
        is QuantumCleanResult.Error -> {
            println("Error: ${result.message}")
        }
    }
}

fun checkingEncryptedData() {
    println("2. Checking if Data is Encrypted")
    println("-" * 40)
    
    val plainText = """{"key": "value"}"""
    val encryptedText = BardoQuantEncryption.encrypt("secret")
    
    println("Plain JSON is encrypted: ${BardoQuantEncryption.isEncrypted(plainText)}")
    println("Encrypted data is encrypted: ${BardoQuantEncryption.isEncrypted(encryptedText)}")
}

fun handlingResults() {
    println("3. Handling Different Result Types")
    println("-" * 40)
    
    fun processData(data: String) {
        val result = BardoQuantEncryption.decrypt(data)
        
        when (result) {
            is QuantumCleanResult.Decrypted -> {
                println("✅ Decrypted successfully: ${result.data.take(20)}...")
            }
            is QuantumCleanResult.NotEncrypted -> {
                println("ℹ️  Data is not encrypted, using as-is: ${result.data.take(20)}...")
            }
            is QuantumCleanResult.Error -> {
                println("❌ Error occurred: ${result.message}")
            }
        }
    }
    
    val encrypted = BardoQuantEncryption.encrypt("test data")
    processData(encrypted)
    processData("""{"plain": "json"}""")
}

fun errorHandling() {
    println("4. Error Handling")
    println("-" * 40)
    
    try {
        val encrypted = BardoQuantEncryption.encrypt("sensitive information")
        println("✅ Encryption successful")
        
        when (val result = BardoQuantEncryption.decrypt(encrypted)) {
            is QuantumCleanResult.Decrypted -> {
                println("✅ Decryption successful")
            }
            is QuantumCleanResult.Error -> {
                println("❌ Decryption failed: ${result.message}")
            }
            else -> {}
        }
    } catch (e: SecurityException) {
        println("❌ Security exception: ${e.message}")
    } catch (e: Exception) {
        println("❌ Unexpected error: ${e.message}")
    }
}

operator fun String.times(n: Int): String = repeat(n)

