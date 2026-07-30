package dev.activechain.wallet

import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CanonicalApprovalIntegrationTest {
    @Test
    fun reviewedRequestAuthenticatesSignsAndCannotBeReplayed() {
        val testContext = InstrumentationRegistry.getInstrumentation().context
        val vector = testContext.assets.open("wallet-canonical-approval-v1.txt").bufferedReader()
            .readLines().filter { it.isNotBlank() && !it.startsWith('#') }
            .associate { it.substringBefore('=') to it.substringAfter('=') }
        val request = vector.getValue("request_hex").decodeHexVector()
        val approval = CanonicalWalletApproval.review(request)
        val store = MemoryRecordStore()
        val hardware = AuthenticatedMemoryWrapping()
        val custody = AndroidNativeCustodyProvider(store, hardware, BouncyCastleMLDSA44Engine())
        val recoveryKey = ByteArray(32) { 0x71 }
        val publicKey = custody.provision(
            "wallet-primary", 1, 20, recoveryKey, preferStrongBox = false,
        )

        val session = CanonicalWalletApprovalSession(approval)
        val authorized = session.sign(custody, "wallet-primary", 1, 20)
        assertEquals(1, hardware.unwrapCount)
        assertContentEquals(publicKey, custody.publicKey("wallet-primary"))
        check(authorized.isNotEmpty())
        assertContentEquals(
            authorized,
            NativeCanonicalApproval.verifyForSubmission(authorized, publicKey),
        )

        assertFailsWith<IllegalStateException> {
            session.sign(custody, "wallet-primary", 1, 20)
        }
        assertEquals(1, hardware.unwrapCount)

        val substituted = approval.copy(recipient = "ff".repeat(48))
        assertFailsWith<IllegalArgumentException> {
            CanonicalWalletApprovalSession(substituted).sign(custody, "wallet-primary", 1, 20)
        }
        assertEquals(1, hardware.unwrapCount)

        assertFailsWith<IllegalArgumentException> {
            CanonicalWalletApproval.review(request + 0)
        }
    }
}

private class MemoryRecordStore : AndroidCustodyRecordStore {
    private val records = ConcurrentHashMap<String, ByteArray>()
    override fun load(slotID: String): ByteArray? = records[slotID]?.copyOf()
    override fun save(slotID: String, record: ByteArray) { records[slotID] = record.copyOf() }
    override fun delete(slotID: String) { records.remove(slotID) }
}

private class AuthenticatedMemoryWrapping : AndroidHardwareWrapping {
    private val records = ConcurrentHashMap<String, ByteArray>()
    var unwrapCount = 0
        private set

    override fun createAndWrap(
        secret: ByteArray, alias: String, preferStrongBox: Boolean, reason: String,
    ): AndroidWrappedSeed {
        val encrypted = secret.map { (it.toInt() xor 0x5a).toByte() }.toByteArray()
        records[alias] = encrypted
        return AndroidWrappedSeed(
            alias, encrypted, ByteArray(12) { 1 }, AndroidCustodyCapability.TEE_WRAPPED_ML_DSA_44,
        )
    }

    override fun unwrap(wrapped: AndroidWrappedSeed, reason: String): ByteArray {
        unwrapCount += 1
        require(records[wrapped.alias]?.contentEquals(wrapped.ciphertext) == true)
        return wrapped.ciphertext.map { (it.toInt() xor 0x5a).toByte() }.toByteArray()
    }

    override fun deleteWrappingKey(alias: String) { records.remove(alias) }
}

private fun String.decodeHexVector(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
