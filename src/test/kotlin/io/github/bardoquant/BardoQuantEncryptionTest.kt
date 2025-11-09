package io.github.bardoquant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class BardoQuantEncryptionTest {
    
    @BeforeEach
    fun setup() {
        BardoQuantConfig.enableDebugLogging = false
        BardoQuantConfig.logger = NoOpLogger()
    }
    
    @Test
    fun `encrypt should produce valid encrypted output`() {
        val plaintext = "test data"
        val encrypted = BardoQuantEncryption.encrypt(plaintext)
        
        assertTrue(BardoQuantEncryption.isEncrypted(encrypted))
        assertTrue(encrypted.contains("bardo_quantum_version"))
        assertTrue(encrypted.contains("kyber_public_key"))
    }
    
    @Test
    fun `decrypt should recover original data`() {
        val original = "test data for encryption"
        val encrypted = BardoQuantEncryption.encrypt(original)
        
        val result = BardoQuantEncryption.decrypt(encrypted)
        assertTrue(result is QuantumCleanResult.Decrypted)
        
        val decrypted = (result as QuantumCleanResult.Decrypted).data
        assertEquals(original, decrypted)
    }
    
    @Test
    fun `isEncrypted should return false for plain text`() {
        val plainJson = """{"key": "value"}"""
        assertFalse(BardoQuantEncryption.isEncrypted(plainJson))
    }
    
    @Test
    fun `isEncrypted should return true for encrypted data`() {
        val encrypted = BardoQuantEncryption.encrypt("test")
        assertTrue(BardoQuantEncryption.isEncrypted(encrypted))
    }
    
    @Test
    fun `decrypt should return NotEncrypted for plain text`() {
        val plainText = "plain text data"
        val result = BardoQuantEncryption.decrypt(plainText)
        
        assertTrue(result is QuantumCleanResult.NotEncrypted)
        assertEquals(plainText, (result as QuantumCleanResult.NotEncrypted).data)
    }
    
    @Test
    fun `encrypt and decrypt large data`() {
        val largeData = "x".repeat(10000)
        val encrypted = BardoQuantEncryption.encrypt(largeData)
        
        val result = BardoQuantEncryption.decrypt(encrypted)
        assertTrue(result is QuantumCleanResult.Decrypted)
        assertEquals(largeData, (result as QuantumCleanResult.Decrypted).data)
    }
    
    @Test
    fun `encrypt should produce different outputs for same input`() {
        val data = "same input"
        val encrypted1 = BardoQuantEncryption.encrypt(data)
        val encrypted2 = BardoQuantEncryption.encrypt(data)
        
        assertTrue(encrypted1 != encrypted2)
    }
    
    @Test
    fun `encrypted data should not contain plaintext`() {
        val secret = "my secret password"
        val encrypted = BardoQuantEncryption.encrypt(secret)
        
        assertFalse(encrypted.contains(secret))
    }
    
    @Test
    fun `decrypt should handle unicode characters`() {
        val unicode = "Hello 世界 🔐 مرحبا"
        val encrypted = BardoQuantEncryption.encrypt(unicode)
        
        val result = BardoQuantEncryption.decrypt(encrypted)
        assertTrue(result is QuantumCleanResult.Decrypted)
        assertEquals(unicode, (result as QuantumCleanResult.Decrypted).data)
    }
    
    @Test
    fun `decrypt should handle empty string`() {
        val empty = ""
        val encrypted = BardoQuantEncryption.encrypt(empty)
        
        val result = BardoQuantEncryption.decrypt(encrypted)
        assertTrue(result is QuantumCleanResult.Decrypted)
        assertEquals(empty, (result as QuantumCleanResult.Decrypted).data)
    }
}

