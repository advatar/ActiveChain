package dev.activechain.wallet

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

enum class AndroidCustodyCapability {
    STRONGBOX_WRAPPED_ML_DSA_44,
    TEE_WRAPPED_ML_DSA_44,
}

enum class AndroidCustodyFailure {
    INVALID_SLOT,
    INVALID_RECOVERY_KEY,
    UNSUPPORTED_RECORD,
    MISSING_SLOT,
    REVOKED,
    ROLLBACK,
    USER_PRESENCE_REQUIRED,
    AUTHENTICATION_CANCELLED,
    DEVICE_LOCKED,
    HARDWARE_UNAVAILABLE,
    WRONG_KEY,
    INVALID_KEY_MATERIAL,
    INVALID_SIGNATURE,
    STORAGE_FAILURE,
    CRYPTOGRAPHIC_FAILURE,
}

class AndroidCustodyException(val failure: AndroidCustodyFailure) : Exception(failure.name)

interface AndroidMLDSA44Engine {
    /** Generates a fresh ML-DSA-44 seed inside the native custody provider. */
    fun generateSeed(): ByteArray
    fun publicKey(seed: ByteArray): ByteArray
    fun sign(payload: ByteArray, seed: ByteArray): ByteArray
}

/** Wire-compatible FIPS 204 ML-DSA-44 implementation that remains inside the Kotlin provider. */
class BouncyCastleMLDSA44Engine(
    private val random: SecureRandom = SecureRandom(),
) : AndroidMLDSA44Engine {
    override fun generateSeed(): ByteArray = ByteArray(32).also(random::nextBytes)

    override fun publicKey(seed: ByteArray): ByteArray = privateKey(seed).publicKey

    override fun sign(payload: ByteArray, seed: ByteArray): ByteArray {
        val signer = MLDSASigner()
        signer.init(true, privateKey(seed))
        signer.update(payload, 0, payload.size)
        return signer.generateSignature()
    }

    private fun privateKey(seed: ByteArray): MLDSAPrivateKeyParameters {
        if (seed.size != 32) {
            throw AndroidCustodyException(AndroidCustodyFailure.INVALID_KEY_MATERIAL)
        }
        return try {
            MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, seed)
        } catch (_: Exception) {
            throw AndroidCustodyException(AndroidCustodyFailure.INVALID_KEY_MATERIAL)
        }
    }
}

interface AndroidCustodyRecordStore {
    fun load(slotID: String): ByteArray?
    fun save(slotID: String, record: ByteArray)
    fun delete(slotID: String)
}

/** Stores only encrypted records under noBackupFilesDir using crash-safe replacement. */
class NoBackupCustodyRecordStore(context: Context) : AndroidCustodyRecordStore {
    private val directory = context.noBackupFilesDir.resolve("activechain-custody-v1")

    override fun load(slotID: String): ByteArray? {
        val file = AtomicFile(directory.resolve(fileName(slotID)))
        if (!file.baseFile.exists()) return null
        return try {
            file.readFully()
        } catch (_: Exception) {
            throw AndroidCustodyException(AndroidCustodyFailure.STORAGE_FAILURE)
        }
    }

    override fun save(slotID: String, record: ByteArray) {
        if (!directory.exists() && !directory.mkdirs()) {
            throw AndroidCustodyException(AndroidCustodyFailure.STORAGE_FAILURE)
        }
        val file = AtomicFile(directory.resolve(fileName(slotID)))
        val output = try {
            file.startWrite()
        } catch (_: Exception) {
            throw AndroidCustodyException(AndroidCustodyFailure.STORAGE_FAILURE)
        }
        try {
            output.write(record)
            output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            throw AndroidCustodyException(AndroidCustodyFailure.STORAGE_FAILURE)
        }
    }

    override fun delete(slotID: String) {
        AtomicFile(directory.resolve(fileName(slotID))).delete()
    }

    private fun fileName(slotID: String) = "slot-$slotID.bin"
}

fun interface AndroidUserPresenceAuthorizer {
    /** Returns the same Cipher only after BiometricPrompt authenticates its CryptoObject. */
    fun authorize(cipher: Cipher, reason: String): Cipher
}

data class AndroidWrappedSeed(
    val alias: String,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val capability: AndroidCustodyCapability,
)

interface AndroidHardwareWrapping {
    fun createAndWrap(
        secret: ByteArray,
        alias: String,
        preferStrongBox: Boolean,
        reason: String,
    ): AndroidWrappedSeed

    fun unwrap(wrapped: AndroidWrappedSeed, reason: String): ByteArray
    fun deleteWrappingKey(alias: String)
}

/**
 * Uses an authenticated Android Keystore AES key only to wrap an ML-DSA-44 seed. The AES key is
 * never transaction authority. The injected authorizer must authenticate the exact Cipher through
 * BiometricPrompt.CryptoObject and return that same instance.
 */
class AndroidKeystoreWrappingBackend(
    private val authorizer: AndroidUserPresenceAuthorizer,
) : AndroidHardwareWrapping {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun createAndWrap(
        secret: ByteArray,
        alias: String,
        preferStrongBox: Boolean,
        reason: String,
    ): AndroidWrappedSeed {
        val key = generate(alias, preferStrongBox)
        val capability = capability(key)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val authenticated = authorizer.authorize(cipher, reason)
            if (authenticated !== cipher) {
                throw AndroidCustodyException(AndroidCustodyFailure.USER_PRESENCE_REQUIRED)
            }
            return AndroidWrappedSeed(alias, authenticated.doFinal(secret), authenticated.iv, capability)
        } catch (error: AndroidCustodyException) {
            deleteWrappingKey(alias)
            throw error
        } catch (_: Exception) {
            deleteWrappingKey(alias)
            throw AndroidCustodyException(AndroidCustodyFailure.USER_PRESENCE_REQUIRED)
        }
    }

    override fun unwrap(wrapped: AndroidWrappedSeed, reason: String): ByteArray {
        val key = keyStore.getKey(wrapped.alias, null) as? SecretKey
            ?: throw AndroidCustodyException(AndroidCustodyFailure.MISSING_SLOT)
        if (capability(key) != wrapped.capability) {
            throw AndroidCustodyException(AndroidCustodyFailure.HARDWARE_UNAVAILABLE)
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, wrapped.iv))
            val authenticated = authorizer.authorize(cipher, reason)
            if (authenticated !== cipher) {
                throw AndroidCustodyException(AndroidCustodyFailure.USER_PRESENCE_REQUIRED)
            }
            return authenticated.doFinal(wrapped.ciphertext)
        } catch (error: AndroidCustodyException) {
            throw error
        } catch (_: Exception) {
            throw AndroidCustodyException(AndroidCustodyFailure.USER_PRESENCE_REQUIRED)
        }
    }

    override fun deleteWrappingKey(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun generate(alias: String, preferStrongBox: Boolean): SecretKey {
        fun generateKey(strongBox: Boolean): SecretKey {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= 30) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (Build.VERSION.SDK_INT >= 28) {
                builder.setUnlockedDeviceRequired(true)
                builder.setIsStrongBoxBacked(strongBox)
            }
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(builder.build())
            return generator.generateKey()
        }

        val key = if (preferStrongBox && Build.VERSION.SDK_INT >= 28) {
            try {
                generateKey(true)
            } catch (_: StrongBoxUnavailableException) {
                generateKey(false)
            }
        } else {
            generateKey(false)
        }
        try {
            capability(key) // Fails closed if the key is not hardware isolated.
        } catch (error: Exception) {
            deleteWrappingKey(alias)
            throw error
        }
        return key
    }

    @Suppress("DEPRECATION")
    private fun capability(key: SecretKey): AndroidCustodyCapability {
        val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info: KeyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (!info.isInsideSecureHardware()) {
            throw AndroidCustodyException(AndroidCustodyFailure.HARDWARE_UNAVAILABLE)
        }
        return if (Build.VERSION.SDK_INT >= 31 &&
            info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX
        ) {
            AndroidCustodyCapability.STRONGBOX_WRAPPED_ML_DSA_44
        } else {
            AndroidCustodyCapability.TEE_WRAPPED_ML_DSA_44
        }
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}

private data class AndroidCustodyRecord(
    val schema: Int,
    val slotID: String,
    val keyVersion: Int,
    val finalizedHeight: Long,
    val publicKey: ByteArray,
    val wrappedSeed: AndroidWrappedSeed,
    val recoveryEnvelope: ByteArray,
    val revoked: Boolean,
)

private data class AndroidRecoveryEnvelope(
    val schema: Int,
    val slotID: String,
    val keyVersion: Int,
    val finalizedHeight: Long,
    val publicKey: ByteArray,
    val iv: ByteArray,
    val ciphertext: ByteArray,
) {
    fun authenticatedMetadata(): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { output ->
            output.writeUTF("ACTIVECHAIN-ANDROID-MLDSA44-RECOVERY-V1")
            output.writeUTF(slotID)
            output.writeInt(keyVersion)
            output.writeLong(finalizedHeight)
            output.write(publicKey)
        }
    }.toByteArray()
}

private object AndroidCustodyCodec {
    private const val RECORD_MAGIC = 0x41434b31
    private const val RECOVERY_MAGIC = 0x41435231
    const val SCHEMA = 1
    private const val MAX_RECORD = 64 * 1024
    private const val MAX_FIELD = 16 * 1024

    fun encode(record: AndroidCustodyRecord): ByteArray = encodeBounded { output ->
        output.writeInt(RECORD_MAGIC)
        output.writeShort(record.schema)
        output.writeUTF(record.slotID)
        output.writeInt(record.keyVersion)
        output.writeLong(record.finalizedHeight)
        writeBytes(output, record.publicKey)
        output.writeUTF(record.wrappedSeed.alias)
        writeBytes(output, record.wrappedSeed.ciphertext)
        writeBytes(output, record.wrappedSeed.iv)
        output.writeByte(record.wrappedSeed.capability.ordinal)
        writeBytes(output, record.recoveryEnvelope)
        output.writeBoolean(record.revoked)
    }

    fun decode(bytes: ByteArray): AndroidCustodyRecord = decodeBounded(bytes) { input ->
        if (input.readInt() != RECORD_MAGIC) unsupported()
        val schema = input.readUnsignedShort()
        val slotID = input.readUTF()
        val keyVersion = input.readInt()
        val finalizedHeight = input.readLong()
        val publicKey = readBytes(input)
        val alias = input.readUTF()
        val ciphertext = readBytes(input)
        val iv = readBytes(input)
        val capability = AndroidCustodyCapability.entries.getOrNull(input.readUnsignedByte())
            ?: unsupported()
        val recovery = readBytes(input)
        val revoked = input.readBoolean()
        AndroidCustodyRecord(
            schema,
            slotID,
            keyVersion,
            finalizedHeight,
            publicKey,
            AndroidWrappedSeed(alias, ciphertext, iv, capability),
            recovery,
            revoked,
        )
    }

    fun encode(envelope: AndroidRecoveryEnvelope): ByteArray = encodeBounded { output ->
        output.writeInt(RECOVERY_MAGIC)
        output.writeShort(envelope.schema)
        output.writeUTF(envelope.slotID)
        output.writeInt(envelope.keyVersion)
        output.writeLong(envelope.finalizedHeight)
        writeBytes(output, envelope.publicKey)
        writeBytes(output, envelope.iv)
        writeBytes(output, envelope.ciphertext)
    }

    fun decodeRecovery(bytes: ByteArray): AndroidRecoveryEnvelope = decodeBounded(bytes) { input ->
        if (input.readInt() != RECOVERY_MAGIC) unsupported()
        AndroidRecoveryEnvelope(
            input.readUnsignedShort(),
            input.readUTF(),
            input.readInt(),
            input.readLong(),
            readBytes(input),
            readBytes(input),
            readBytes(input),
        )
    }

    private fun encodeBounded(write: (DataOutputStream) -> Unit): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use(write)
        return bytes.toByteArray().also { if (it.size > MAX_RECORD) unsupported() }
    }

    private fun <T> decodeBounded(bytes: ByteArray, read: (DataInputStream) -> T): T {
        if (bytes.isEmpty() || bytes.size > MAX_RECORD) unsupported()
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val value = read(input)
                if (input.available() != 0) unsupported()
                value
            }
        } catch (error: AndroidCustodyException) {
            throw error
        } catch (_: Exception) {
            unsupported()
        }
    }

    private fun writeBytes(output: DataOutputStream, bytes: ByteArray) {
        if (bytes.size > MAX_FIELD) unsupported()
        output.writeInt(bytes.size)
        output.write(bytes)
    }

    private fun readBytes(input: DataInputStream): ByteArray {
        val length = input.readInt()
        if (length < 0 || length > MAX_FIELD || length > input.available()) unsupported()
        return ByteArray(length).also(input::readFully)
    }

    private fun unsupported(): Nothing =
        throw AndroidCustodyException(AndroidCustodyFailure.UNSUPPORTED_RECORD)
}

class AndroidNativeCustodyProvider(
    private val store: AndroidCustodyRecordStore,
    private val hardware: AndroidHardwareWrapping,
    private val engine: AndroidMLDSA44Engine,
    private val random: SecureRandom = SecureRandom(),
) {
    fun provision(
        slotID: String,
        keyVersion: Int,
        finalizedHeight: Long,
        recoveryKey: ByteArray,
        preferStrongBox: Boolean = true,
    ): ByteArray {
        validateSlot(slotID)
        if (store.load(slotID) != null) failure(AndroidCustodyFailure.ROLLBACK)
        val seed = engine.generateSeed()
        return try {
            install(seed, slotID, keyVersion, finalizedHeight, recoveryKey, preferStrongBox, null)
        } finally {
            seed.fill(0)
        }
    }

    fun sign(
        slotID: String,
        payload: ByteArray,
        minimumVersion: Int,
        minimumFinalizedHeight: Long,
        reason: String,
    ): ByteArray {
        val record = load(slotID)
        if (record.revoked) failure(AndroidCustodyFailure.REVOKED)
        if (record.keyVersion < minimumVersion || record.finalizedHeight < minimumFinalizedHeight) {
            failure(AndroidCustodyFailure.ROLLBACK)
        }
        val seed = hardware.unwrap(record.wrappedSeed, reason)
        return try {
            validateSeed(seed, record.publicKey)
            engine.sign(payload, seed).also {
                if (it.size != SIGNATURE_LENGTH) failure(AndroidCustodyFailure.INVALID_SIGNATURE)
            }
        } finally {
            seed.fill(0)
        }
    }

    fun publicKey(slotID: String): ByteArray {
        val record = load(slotID)
        if (record.revoked) failure(AndroidCustodyFailure.REVOKED)
        return record.publicKey.copyOf()
    }

    fun rotate(
        slotID: String,
        newVersion: Int,
        finalizedHeight: Long,
        recoveryKey: ByteArray,
        preferStrongBox: Boolean = true,
    ): ByteArray {
        val current = load(slotID)
        if (current.revoked || newVersion <= current.keyVersion ||
            finalizedHeight < current.finalizedHeight
        ) {
            failure(AndroidCustodyFailure.ROLLBACK)
        }
        val seed = engine.generateSeed()
        return try {
            install(seed, slotID, newVersion, finalizedHeight, recoveryKey, preferStrongBox, current)
        } finally {
            seed.fill(0)
        }
    }

    fun revoke(slotID: String) {
        val current = load(slotID)
        if (current.revoked) return
        store.save(slotID, AndroidCustodyCodec.encode(current.copy(revoked = true)))
        hardware.deleteWrappingKey(current.wrappedSeed.alias)
    }

    fun exportRecoveryEnvelope(slotID: String): ByteArray {
        val current = load(slotID)
        if (current.revoked) failure(AndroidCustodyFailure.REVOKED)
        return current.recoveryEnvelope.copyOf()
    }

    fun recover(
        envelopeBytes: ByteArray,
        expectedPublicKey: ByteArray,
        newVersion: Int,
        finalizedHeight: Long,
        recoveryKey: ByteArray,
        preferStrongBox: Boolean = true,
    ): ByteArray {
        requireRecoveryKey(recoveryKey)
        val envelope = AndroidCustodyCodec.decodeRecovery(envelopeBytes)
        if (envelope.schema != AndroidCustodyCodec.SCHEMA) {
            failure(AndroidCustodyFailure.UNSUPPORTED_RECORD)
        }
        validateSlot(envelope.slotID)
        if (!constantTimeEquals(envelope.publicKey, expectedPublicKey)) {
            failure(AndroidCustodyFailure.WRONG_KEY)
        }
        if (newVersion <= envelope.keyVersion || finalizedHeight < envelope.finalizedHeight) {
            failure(AndroidCustodyFailure.ROLLBACK)
        }
        val cipher = Cipher.getInstance(RECOVERY_TRANSFORMATION)
        val seed = try {
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(recoveryKey, "AES"),
                GCMParameterSpec(GCM_TAG_BITS, envelope.iv),
            )
            cipher.updateAAD(envelope.authenticatedMetadata())
            cipher.doFinal(envelope.ciphertext)
        } catch (_: Exception) {
            failure(AndroidCustodyFailure.CRYPTOGRAPHIC_FAILURE)
        }
        return try {
            validateSeed(seed, expectedPublicKey)
            val current = store.load(envelope.slotID)?.let(AndroidCustodyCodec::decode)
            if (current != null && newVersion <= current.keyVersion) {
                failure(AndroidCustodyFailure.ROLLBACK)
            }
            install(
                seed,
                envelope.slotID,
                newVersion,
                finalizedHeight,
                recoveryKey,
                preferStrongBox,
                current,
            )
        } finally {
            seed.fill(0)
        }
    }

    private fun install(
        seed: ByteArray,
        slotID: String,
        keyVersion: Int,
        finalizedHeight: Long,
        recoveryKey: ByteArray,
        preferStrongBox: Boolean,
        current: AndroidCustodyRecord?,
    ): ByteArray {
        if (seed.size != SEED_LENGTH) failure(AndroidCustodyFailure.INVALID_KEY_MATERIAL)
        requireRecoveryKey(recoveryKey)
        val publicKey = engine.publicKey(seed)
        if (publicKey.size != PUBLIC_KEY_LENGTH) failure(AndroidCustodyFailure.INVALID_KEY_MATERIAL)
        val alias = "activechain.custody.$slotID.$keyVersion.${random.nextLong().toULong()}"
        val wrapped = hardware.createAndWrap(seed, alias, preferStrongBox, "Protect ActiveChain key")
        try {
            val recovery = sealRecovery(seed, slotID, keyVersion, finalizedHeight, publicKey, recoveryKey)
            store.save(
                slotID,
                AndroidCustodyCodec.encode(
                    AndroidCustodyRecord(
                        AndroidCustodyCodec.SCHEMA,
                        slotID,
                        keyVersion,
                        finalizedHeight,
                        publicKey,
                        wrapped,
                        recovery,
                        false,
                    ),
                ),
            )
        } catch (error: Exception) {
            hardware.deleteWrappingKey(alias)
            throw error
        }
        current?.let { hardware.deleteWrappingKey(it.wrappedSeed.alias) }
        return publicKey
    }

    private fun sealRecovery(
        seed: ByteArray,
        slotID: String,
        keyVersion: Int,
        finalizedHeight: Long,
        publicKey: ByteArray,
        recoveryKey: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance(RECOVERY_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(recoveryKey, "AES"))
        val metadata = AndroidRecoveryEnvelope(
            AndroidCustodyCodec.SCHEMA,
            slotID,
            keyVersion,
            finalizedHeight,
            publicKey,
            cipher.iv,
            ByteArray(0),
        )
        cipher.updateAAD(metadata.authenticatedMetadata())
        return AndroidCustodyCodec.encode(metadata.copy(ciphertext = cipher.doFinal(seed)))
    }

    private fun load(slotID: String): AndroidCustodyRecord {
        validateSlot(slotID)
        val bytes = store.load(slotID) ?: failure(AndroidCustodyFailure.MISSING_SLOT)
        val record = AndroidCustodyCodec.decode(bytes)
        if (record.schema != AndroidCustodyCodec.SCHEMA || record.slotID != slotID) {
            failure(AndroidCustodyFailure.UNSUPPORTED_RECORD)
        }
        return record
    }

    private fun validateSeed(seed: ByteArray, publicKey: ByteArray) {
        if (seed.size != SEED_LENGTH || publicKey.size != PUBLIC_KEY_LENGTH ||
            !constantTimeEquals(engine.publicKey(seed), publicKey)
        ) {
            failure(AndroidCustodyFailure.WRONG_KEY)
        }
    }

    private fun validateSlot(slotID: String) {
        if (slotID.isEmpty() || slotID.length > 64 ||
            !slotID.all { it.isLetterOrDigit() || it in "-_." }
        ) {
            failure(AndroidCustodyFailure.INVALID_SLOT)
        }
    }

    private fun requireRecoveryKey(key: ByteArray) {
        if (key.size != 32) failure(AndroidCustodyFailure.INVALID_RECOVERY_KEY)
    }

    private fun constantTimeEquals(first: ByteArray, second: ByteArray): Boolean {
        if (first.size != second.size) return false
        var difference = 0
        for (index in first.indices) difference = difference or (first[index].toInt() xor second[index].toInt())
        return difference == 0
    }

    private fun failure(failure: AndroidCustodyFailure): Nothing = throw AndroidCustodyException(failure)

    private companion object {
        const val SEED_LENGTH = 32
        const val PUBLIC_KEY_LENGTH = 1_312
        const val SIGNATURE_LENGTH = 2_420
        const val RECOVERY_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}
