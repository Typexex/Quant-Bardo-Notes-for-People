package io.github.bardoquant

object BardoQuantConfig {
    var logger: BardoQuantLogger = ConsoleLogger()
    
    var enableDebugLogging: Boolean = false
    
    var pbkdf2Iterations: Int = 300000
    
    var quantumRounds: Int = 16
    
    var noisePercentageMin: Double = 0.10
    
    var noisePercentageMax: Double = 0.15
}

