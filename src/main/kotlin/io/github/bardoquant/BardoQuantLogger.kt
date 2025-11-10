package io.github.bardoquant

interface BardoQuantLogger {
    fun debug(message: String)
    fun info(message: String)
    fun warn(message: String)
    fun error(message: String, throwable: Throwable? = null)
}

class ConsoleLogger : BardoQuantLogger {
    override fun debug(message: String) {
        if (BardoQuantConfig.enableDebugLogging) {
            println("[DEBUG] $message")
        }
    }
    
    override fun info(message: String) {
        println("[INFO] $message")
    }
    
    override fun warn(message: String) {
        println("[WARN] $message")
    }
    
    override fun error(message: String, throwable: Throwable?) {
        println("[ERROR] $message")
        throwable?.printStackTrace()
    }
}

class NoOpLogger : BardoQuantLogger {
    override fun debug(message: String) {}
    override fun info(message: String) {}
    override fun warn(message: String) {}
    override fun error(message: String, throwable: Throwable?) {}
}

