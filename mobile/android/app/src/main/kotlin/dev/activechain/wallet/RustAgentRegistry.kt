package dev.activechain.wallet

import java.io.File

class RustAgentRegistry(private val snapshotFile: File) {
    var agents: List<AgentDelegation> = emptyList()
        private set

    private var snapshot = if (snapshotFile.isFile) snapshotFile.readBytes() else ByteArray(0)

    init {
        if (snapshot.isEmpty()) {
            snapshot = nativeRegister(snapshot, 0x31, 0x41, "Research agent", 1, 50, 240_000)
            snapshot = nativeRegister(snapshot, 0x32, 0x42, "Travel planner", 2, 10, 210_000)
            persist()
        }
        refresh()
    }

    fun pause(id: String) = replace(nativeSetPaused(snapshot, principal(id), true))

    fun resume(id: String) = replace(nativeSetPaused(snapshot, principal(id), false))

    fun revoke(id: String) = replace(nativeRevoke(snapshot, principal(id), 0))

    fun finalizeRevocation(id: String, height: Long) {
        require(height > 0) { "finalized height must be positive" }
        replace(nativeRevoke(snapshot, principal(id), height))
    }

    private fun replace(next: ByteArray) {
        snapshot = next
        persist()
        refresh()
    }

    private fun persist() {
        snapshotFile.parentFile?.mkdirs()
        val temporary = File(snapshotFile.parentFile, "${snapshotFile.name}.tmp")
        temporary.writeBytes(snapshot)
        check(temporary.renameTo(snapshotFile)) { "failed to atomically replace agent snapshot" }
    }

    private fun refresh() {
        agents = (0 until nativeCount(snapshot)).map { parseSummary(nativeSummary(snapshot, it)) }
    }

    companion object {
        init {
            System.loadLibrary("activechain_wallet_ffi")
        }

        @JvmStatic private external fun nativeRegister(
            snapshot: ByteArray,
            principalByte: Int,
            capabilityByte: Int,
            label: String,
            connection: Int,
            budget: Long,
            expiresAt: Long,
        ): ByteArray

        @JvmStatic private external fun nativeSetPaused(
            snapshot: ByteArray,
            principal: ByteArray,
            paused: Boolean,
        ): ByteArray

        @JvmStatic private external fun nativeRevoke(
            snapshot: ByteArray,
            principal: ByteArray,
            finalizedHeight: Long,
        ): ByteArray

        @JvmStatic private external fun nativeCount(snapshot: ByteArray): Int

        @JvmStatic private external fun nativeSummary(snapshot: ByteArray, index: Int): String

        internal fun parseSummary(encoded: String): AgentDelegation {
            val fields = encoded.split('\t')
            require(fields.size == 9) { "malformed native agent summary" }
            val lifecycle = when (fields[3].toInt()) {
                0 -> AgentLifecycle.Active
                1 -> AgentLifecycle.Paused
                2 -> AgentLifecycle.RevocationPending
                3 -> AgentLifecycle.Revoked(fields[8].toLong())
                else -> error("unknown native agent lifecycle")
            }
            return AgentDelegation(
                id = fields[0],
                label = fields[1],
                capabilities = listOf("${fields[4]} scoped capability"),
                dailyLimit = fields[5].toLong(),
                expiresAt = fields[7].toLong(),
                connection = AgentConnection.entries[fields[2].toInt()],
                spentToday = fields[6].toLong(),
                lifecycle = lifecycle,
            )
        }

        private fun principal(id: String): ByteArray {
            require(id.length == 96) { "agent principal must be a 48-byte hex digest" }
            return ByteArray(48) { index ->
                id.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
