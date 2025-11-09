package io.github.bardoquant

sealed class QuantumCleanResult {
    data class Decrypted(val data: String) : QuantumCleanResult()
    
    data class NotEncrypted(val data: String) : QuantumCleanResult()
    
    data class Error(val message: String) : QuantumCleanResult()
}

