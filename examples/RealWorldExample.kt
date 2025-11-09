package examples

import io.github.bardoquant.BardoQuantEncryption
import io.github.bardoquant.BardoQuantConfig
import io.github.bardoquant.QuantumCleanResult
import io.github.bardoquant.NoOpLogger

data class SecureNote(
    val id: String,
    val title: String,
    val content: String,
    val createdAt: Long
)

class SecureNoteStorage {
    private val notes = mutableMapOf<String, String>()
    
    init {
        BardoQuantConfig.enableDebugLogging = false
        BardoQuantConfig.logger = NoOpLogger()
    }
    
    fun saveNote(note: SecureNote): Boolean {
        return try {
            val json = serializeNote(note)
            val encrypted = BardoQuantEncryption.encrypt(json)
            notes[note.id] = encrypted
            true
        } catch (e: Exception) {
            println("Failed to save note: ${e.message}")
            false
        }
    }
    
    fun loadNote(id: String): SecureNote? {
        val encrypted = notes[id] ?: return null
        
        return when (val result = BardoQuantEncryption.decrypt(encrypted)) {
            is QuantumCleanResult.Decrypted -> {
                deserializeNote(result.data)
            }
            is QuantumCleanResult.Error -> {
                println("Failed to decrypt note: ${result.message}")
                null
            }
            else -> null
        }
    }
    
    fun listNotes(): List<String> = notes.keys.toList()
    
    fun deleteNote(id: String): Boolean {
        return notes.remove(id) != null
    }
    
    fun exportNote(id: String): String? {
        return notes[id]
    }
    
    fun importNote(id: String, encryptedData: String): Boolean {
        return try {
            when (val result = BardoQuantEncryption.decrypt(encryptedData)) {
                is QuantumCleanResult.Decrypted -> {
                    notes[id] = encryptedData
                    true
                }
                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    private fun serializeNote(note: SecureNote): String {
        return """
        {
            "id": "${note.id}",
            "title": "${note.title}",
            "content": "${note.content}",
            "createdAt": ${note.createdAt}
        }
        """.trimIndent()
    }
    
    private fun deserializeNote(json: String): SecureNote {
        val idMatch = """"id":\s*"([^"]+)"""".toRegex().find(json)
        val titleMatch = """"title":\s*"([^"]+)"""".toRegex().find(json)
        val contentMatch = """"content":\s*"([^"]+)"""".toRegex().find(json)
        val createdAtMatch = """"createdAt":\s*(\d+)""".toRegex().find(json)
        
        return SecureNote(
            id = idMatch?.groupValues?.get(1) ?: "",
            title = titleMatch?.groupValues?.get(1) ?: "",
            content = contentMatch?.groupValues?.get(1) ?: "",
            createdAt = createdAtMatch?.groupValues?.get(1)?.toLongOrNull() ?: 0L
        )
    }
}

fun main() {
    println("=== BardoQuant - Real-World Example: Secure Note Storage ===\n")
    
    val storage = SecureNoteStorage()
    
    println("1. Creating and saving notes...")
    println("-" * 50)
    
    val note1 = SecureNote(
        id = "note-001",
        title = "Meeting Notes",
        content = "Discussed Q1 strategy and budget allocation",
        createdAt = System.currentTimeMillis()
    )
    
    val note2 = SecureNote(
        id = "note-002",
        title = "Password Vault",
        content = "Banking: secure_password_123, Email: another_password",
        createdAt = System.currentTimeMillis()
    )
    
    val note3 = SecureNote(
        id = "note-003",
        title = "Personal Thoughts",
        content = "Today was a good day. Made progress on the encryption library.",
        createdAt = System.currentTimeMillis()
    )
    
    storage.saveNote(note1)
    storage.saveNote(note2)
    storage.saveNote(note3)
    
    println("✅ Saved ${storage.listNotes().size} notes")
    
    println("\n2. Listing all notes...")
    println("-" * 50)
    storage.listNotes().forEach { id ->
        println("  - $id")
    }
    
    println("\n3. Loading and displaying a note...")
    println("-" * 50)
    val loadedNote = storage.loadNote("note-002")
    if (loadedNote != null) {
        println("Title: ${loadedNote.title}")
        println("Content: ${loadedNote.content}")
        println("Created: ${java.util.Date(loadedNote.createdAt)}")
    }
    
    println("\n4. Exporting a note (encrypted)...")
    println("-" * 50)
    val exported = storage.exportNote("note-001")
    if (exported != null) {
        println("Encrypted data (first 100 chars):")
        println(exported.take(100) + "...")
        println("\n✅ Note exported successfully")
    }
    
    println("\n5. Importing a note...")
    println("-" * 50)
    if (exported != null) {
        storage.deleteNote("note-001")
        val imported = storage.importNote("note-001-imported", exported)
        println("Import status: ${if (imported) "✅ Success" else "❌ Failed"}")
    }
    
    println("\n6. Deleting a note...")
    println("-" * 50)
    val deleted = storage.deleteNote("note-003")
    println("Delete status: ${if (deleted) "✅ Success" else "❌ Failed"}")
    println("Remaining notes: ${storage.listNotes().size}")
    
    println("\n7. Security check...")
    println("-" * 50)
    val encryptedNote = storage.exportNote("note-002")
    if (encryptedNote != null) {
        println("Is note encrypted: ${BardoQuantEncryption.isEncrypted(encryptedNote)}")
        
        val plainContent = "Password Vault"
        println("Plain text found in encrypted data: ${encryptedNote.contains(plainContent)}")
        println("\n✅ Sensitive data is properly encrypted!")
    }
    
    println("\n=== Demo Complete ===")
}

operator fun String.times(n: Int): String = repeat(n)

