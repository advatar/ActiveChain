package dev.activechain.wallet

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

class NativeWalletCustodyTest {
    @Test
    fun bouncyCastleEngineProducesWireLengthAndVerifiableMLDSA44() {
        val engine = BouncyCastleMLDSA44Engine()
        val seed = engine.generateSeed()
        val payload = "ACTIVECHAIN-ANDROID-CUSTODY-INTEROP-V1".encodeToByteArray()
        val publicKey = engine.publicKey(seed)
        val signature = engine.sign(payload, seed)

        assertEquals(32, seed.size)
        assertEquals(1_312, publicKey.size)
        assertEquals(2_420, signature.size)
        val verifier = MLDSASigner()
        verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, publicKey))
        verifier.update(payload, 0, payload.size)
        assertTrue(verifier.verifySignature(signature))
        payload[0] = (payload[0].toInt() xor 1).toByte()
        val tamperedVerifier = MLDSASigner()
        tamperedVerifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, publicKey))
        tamperedVerifier.update(payload, 0, payload.size)
        assertFalse(tamperedVerifier.verifySignature(signature))
    }

    @Test
    fun provisionAndSignRequireCurrentAnchorsAndZeroizePlaintext() {
        val fixture = Fixture()
        val recoveryKey = ByteArray(32) { 9 }
        val publicKey = fixture.provider.provision("primary", 1, 10, recoveryKey)

        assertEquals(1_312, publicKey.size)
        assertEquals(2_420, fixture.provider.sign("primary", byteArrayOf(7), 1, 10, "Approve").size)
        assertTrue(fixture.hardware.lastPlaintext!!.all { it == 0.toByte() })
        assertFailure(AndroidCustodyFailure.ROLLBACK) {
            fixture.provider.sign("primary", byteArrayOf(7), 2, 10, "Approve")
        }
        assertFailure(AndroidCustodyFailure.ROLLBACK) {
            fixture.provider.sign("primary", byteArrayOf(7), 1, 11, "Approve")
        }
    }

    @Test
    fun authenticationCancellationAndLockedDeviceFailClosed() {
        val fixture = Fixture()
        fixture.provider.provision("primary", 1, 10, ByteArray(32) { 4 })
        fixture.hardware.failure = AndroidCustodyFailure.AUTHENTICATION_CANCELLED
        assertFailure(AndroidCustodyFailure.AUTHENTICATION_CANCELLED) {
            fixture.provider.sign("primary", byteArrayOf(1), 1, 10, "Approve")
        }
        fixture.hardware.failure = AndroidCustodyFailure.DEVICE_LOCKED
        assertFailure(AndroidCustodyFailure.DEVICE_LOCKED) {
            fixture.provider.sign("primary", byteArrayOf(1), 1, 10, "Approve")
        }
    }

    @Test
    fun wrongHardwareKeyAndRevokedKeyNeverSign() {
        val fixture = Fixture()
        fixture.provider.provision("primary", 1, 10, ByteArray(32) { 4 })
        fixture.hardware.substitutePlaintext = ByteArray(32) { 99 }
        assertFailure(AndroidCustodyFailure.WRONG_KEY) {
            fixture.provider.sign("primary", byteArrayOf(1), 1, 10, "Approve")
        }
        fixture.hardware.substitutePlaintext = null
        fixture.provider.revoke("primary")
        assertFailure(AndroidCustodyFailure.REVOKED) {
            fixture.provider.sign("primary", byteArrayOf(1), 1, 10, "Approve")
        }
        assertFailure(AndroidCustodyFailure.REVOKED) {
            fixture.provider.exportRecoveryEnvelope("primary")
        }
    }

    @Test
    fun rotationPersistsReplacementBeforeDeletingOldKey() {
        val fixture = Fixture()
        fixture.provider.provision("primary", 1, 10, ByteArray(32) { 4 })
        val oldAlias = fixture.hardware.aliases.single()
        fixture.store.failNextSave = true

        assertFailure(AndroidCustodyFailure.STORAGE_FAILURE) {
            fixture.provider.rotate("primary", 2, 11, ByteArray(32) { 5 })
        }
        assertTrue(oldAlias in fixture.hardware.aliases)
        assertEquals(1, fixture.hardware.aliases.size)
        assertEquals(2_420, fixture.provider.sign("primary", byteArrayOf(1), 1, 10, "Approve").size)

        fixture.provider.rotate("primary", 2, 11, ByteArray(32) { 5 })
        assertTrue(oldAlias !in fixture.hardware.aliases)
        assertFailure(AndroidCustodyFailure.ROLLBACK) {
            fixture.provider.rotate("primary", 2, 12, ByteArray(32) { 5 })
        }
    }

    @Test
    fun recoveryIsBoundToPublicKeyVersionAndAuthenticatedMetadata() {
        val fixture = Fixture()
        val recoveryKey = ByteArray(32) { 4 }
        val publicKey = fixture.provider.provision("primary", 1, 10, recoveryKey)
        val envelope = fixture.provider.exportRecoveryEnvelope("primary")
        fixture.provider.revoke("primary")

        val replacement = Fixture()
        assertContentEquals(
            publicKey,
            replacement.provider.recover(envelope, publicKey, 2, 11, recoveryKey),
        )
        assertEquals(2_420, replacement.provider.sign("primary", byteArrayOf(2), 2, 11, "Approve").size)

        assertFailure(AndroidCustodyFailure.WRONG_KEY) {
            Fixture().provider.recover(envelope, ByteArray(1_312), 2, 11, recoveryKey)
        }
        assertFailure(AndroidCustodyFailure.CRYPTOGRAPHIC_FAILURE) {
            Fixture().provider.recover(envelope, publicKey, 2, 11, ByteArray(32) { 8 })
        }
        assertFailure(AndroidCustodyFailure.UNSUPPORTED_RECORD) {
            Fixture().provider.recover(byteArrayOf(1, 2, 3), publicKey, 2, 11, recoveryKey)
        }
    }

    private class Fixture {
        val store = MemoryStore()
        val hardware = FakeHardware()
        val provider = AndroidNativeCustodyProvider(store, hardware, FakeEngine())
    }

    private class MemoryStore : AndroidCustodyRecordStore {
        private val records = mutableMapOf<String, ByteArray>()
        var failNextSave = false

        override fun load(slotID: String) = records[slotID]?.copyOf()

        override fun save(slotID: String, record: ByteArray) {
            if (failNextSave) {
                failNextSave = false
                throw AndroidCustodyException(AndroidCustodyFailure.STORAGE_FAILURE)
            }
            records[slotID] = record.copyOf()
        }

        override fun delete(slotID: String) {
            records.remove(slotID)
        }
    }

    private class FakeHardware : AndroidHardwareWrapping {
        val aliases = mutableSetOf<String>()
        var lastPlaintext: ByteArray? = null
        var substitutePlaintext: ByteArray? = null
        var failure: AndroidCustodyFailure? = null

        override fun createAndWrap(
            secret: ByteArray,
            alias: String,
            preferStrongBox: Boolean,
            reason: String,
        ): AndroidWrappedSeed {
            aliases += alias
            return AndroidWrappedSeed(
                alias,
                secret.map { (it.toInt() xor 0x5a).toByte() }.toByteArray(),
                ByteArray(12) { 3 },
                if (preferStrongBox) AndroidCustodyCapability.STRONGBOX_WRAPPED_ML_DSA_44
                else AndroidCustodyCapability.TEE_WRAPPED_ML_DSA_44,
            )
        }

        override fun unwrap(wrapped: AndroidWrappedSeed, reason: String): ByteArray {
            failure?.let { throw AndroidCustodyException(it) }
            if (wrapped.alias !in aliases) throw AndroidCustodyException(AndroidCustodyFailure.MISSING_SLOT)
            return (substitutePlaintext?.copyOf()
                ?: wrapped.ciphertext.map { (it.toInt() xor 0x5a).toByte() }.toByteArray())
                .also { lastPlaintext = it }
        }

        override fun deleteWrappingKey(alias: String) {
            aliases.remove(alias)
        }
    }

    private class FakeEngine : AndroidMLDSA44Engine {
        private var next = 1

        override fun generateSeed() = ByteArray(32) { next.toByte() }.also { next += 1 }

        override fun publicKey(seed: ByteArray) = ByteArray(1_312) { index ->
            (seed[index % seed.size].toInt() xor index).toByte()
        }

        override fun sign(payload: ByteArray, seed: ByteArray) = ByteArray(2_420) { index ->
            (seed[index % seed.size].toInt() xor payload[index % payload.size].toInt()).toByte()
        }
    }

    private fun assertFailure(expected: AndroidCustodyFailure, operation: () -> Unit) {
        val error = assertFailsWith<AndroidCustodyException>(block = operation)
        assertEquals(expected, error.failure)
    }
}
