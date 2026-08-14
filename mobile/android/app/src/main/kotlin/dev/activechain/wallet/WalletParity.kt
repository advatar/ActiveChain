package dev.activechain.wallet

import android.content.Context
import android.content.Intent
import android.util.AtomicFile
import java.net.URI
import java.net.URLEncoder

data class WalletDeviceProfile(val owner: ByteArray, val chainGenesis: ByteArray) {
    init {
        require(owner.size == 48 && owner.any { it.toInt() != 0 })
        require(chainGenesis.size == 48 && chainGenesis.any { it.toInt() != 0 })
    }

    override fun equals(other: Any?) = other is WalletDeviceProfile &&
        owner.contentEquals(other.owner) && chainGenesis.contentEquals(other.chainGenesis)
    override fun hashCode() = 31 * owner.contentHashCode() + chainGenesis.contentHashCode()
}

/** Device-local, excluded-from-backup profile storage. This record contains identifiers, not keys. */
class WalletDeviceProfileStore(context: Context) {
    private val file = AtomicFile(context.noBackupFilesDir.resolve("activechain-wallet-profile-v1.bin"))

    fun load(): WalletDeviceProfile? {
        if (!file.baseFile.isFile) return null
        return try {
            val bytes = file.readFully()
            if (bytes.size != 97 || bytes[0] != 1.toByte()) null
            else WalletDeviceProfile(bytes.copyOfRange(1, 49), bytes.copyOfRange(49, 97))
        } catch (_: Exception) {
            null
        }
    }

    fun save(profile: WalletDeviceProfile) {
        val output = file.startWrite()
        try {
            output.write(byteArrayOf(1) + profile.owner + profile.chainGenesis)
            output.fd.sync()
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }
}

data class WalletFaucetTerms(
    val chainID: ByteArray,
    val genesis: ByteArray,
    val challengeKind: Int,
)

data class WalletFaucetReceipt(
    val reference: ByteArray,
    val state: Int,
    val finalizedHeight: Long?,
)

data class WalletOwnerCoinRecord(
    val key: ByteArray,
    val finalizedHeight: Long,
    val value: ByteArray,
    val proof: ByteArray,
    val finality: ByteArray,
)

data class WalletOwnerCoinPage(val records: List<WalletOwnerCoinRecord>, val next: ByteArray?) {
    fun validated(
        owner: ByteArray,
        chainGenesis: ByteArray,
        finalizedHeight: Long,
        verifier: WalletOwnerCoinProofVerifier,
    ): WalletOwnerCoinPage {
        require(owner.size == 48 && owner.any { it.toInt() != 0 })
        require(chainGenesis.contentEquals(KanalenNetwork.genesis))
        require(records.isNotEmpty()) // absence requires an authenticated absence proof not yet exposed
        require(records.all {
            it.finalizedHeight == finalizedHeight && verifier.verify(it, owner, chainGenesis)
        })
        return this
    }
}

fun interface WalletOwnerCoinProofVerifier {
    fun verify(record: WalletOwnerCoinRecord, owner: ByteArray, chainGenesis: ByteArray): Boolean
}

internal object NativeOwnerCoinProofVerifier : WalletOwnerCoinProofVerifier {
    init { System.loadLibrary("activechain_wallet_ffi") }

    override fun verify(
        record: WalletOwnerCoinRecord,
        owner: ByteArray,
        chainGenesis: ByteArray,
    ): Boolean = try {
        nativeVerify(
            record.key, record.finalizedHeight, record.value, record.proof, record.finality,
            owner, chainGenesis,
        )
    } catch (_: RuntimeException) {
        false
    }

    @JvmStatic private external fun nativeVerify(
        key: ByteArray,
        finalizedHeight: Long,
        value: ByteArray,
        proof: ByteArray,
        finality: ByteArray,
        owner: ByteArray,
        trustedGenesis: ByteArray,
    ): Boolean
}

data class ReceiveRequest(val networkID: String, val genesis: String, val address: String) {
    init { require(networkID.isNotBlank() && genesis.isNotBlank() && address.isNotBlank()) }

    val payload: String get() = "activechain://receive?network=${encode(networkID)}&" +
        "genesis=${encode(genesis)}&address=${encode(address)}"

    private fun encode(value: String) = URLEncoder.encode(value, Charsets.UTF_8).replace("+", "%20")
}

data class OpenWalletCredentialReference(
    val credentialID: String,
    val schemaID: String,
    val issuer: String,
)

data class OpenWalletApplicationSession(
    val sessionID: String,
    val relyingParty: String,
    val expiresAt: ULong,
)

class OpenWalletAdapter {
    private val credentialRecords = sortedMapOf<String, OpenWalletCredentialReference>()
    private val sessionRecords = sortedMapOf<String, OpenWalletApplicationSession>()
    val credentials: List<OpenWalletCredentialReference> get() = credentialRecords.values.toList()
    val sessions: List<OpenWalletApplicationSession> get() = sessionRecords.values.toList()

    fun register(credential: OpenWalletCredentialReference): Boolean {
        if (credential.credentialID.isBlank() || credentialRecords.containsKey(credential.credentialID)) return false
        credentialRecords[credential.credentialID] = credential
        return true
    }

    fun open(session: OpenWalletApplicationSession, atHeight: ULong): Boolean {
        if (session.sessionID.isBlank() || session.relyingParty.isBlank() ||
            session.expiresAt < atHeight || sessionRecords.containsKey(session.sessionID)) return false
        sessionRecords[session.sessionID] = session
        return true
    }
}

enum class AgentEnrollmentFailure { INVALID_LABEL, INVALID_PRINCIPAL, INVALID_CAPABILITIES, INVALID_BUDGET, INVALID_EXPIRY }
class AgentEnrollmentException(val failure: AgentEnrollmentFailure) : IllegalArgumentException(failure.name)

data class AgentEnrollmentDraft(
    val label: String,
    val principal: String,
    val capabilityIDs: String,
    val connection: AgentConnection = AgentConnection.THIRD_PARTY,
    val budget: ULong,
    val expiresAt: ULong,
) {
    fun validate() {
        if (label.trim().isEmpty() || label.toByteArray().size > 96) fail(AgentEnrollmentFailure.INVALID_LABEL)
        principalBytes()
        capabilityBytes()
        if (budget == 0uL) fail(AgentEnrollmentFailure.INVALID_BUDGET)
        if (expiresAt == 0uL) fail(AgentEnrollmentFailure.INVALID_EXPIRY)
    }

    fun principalBytes() = decode(principal, AgentEnrollmentFailure.INVALID_PRINCIPAL)

    fun capabilityBytes(): ByteArray {
        val decoded = capabilityIDs.split(',', '\n', ' ').filter(String::isNotBlank)
            .map { decode(it, AgentEnrollmentFailure.INVALID_CAPABILITIES) }
        if (decoded.isEmpty() || decoded.zipWithNext().any { (a, b) -> !a.lexicographicBefore(b) }) {
            fail(AgentEnrollmentFailure.INVALID_CAPABILITIES)
        }
        return decoded.fold(ByteArray(0), ByteArray::plus)
    }

    private fun decode(value: String, failure: AgentEnrollmentFailure): ByteArray {
        val canonical = value.trim()
        if (canonical.length != 96 || canonical.any { it !in '0'..'9' && it !in 'a'..'f' }) fail(failure)
        return ByteArray(48) { canonical.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun fail(failure: AgentEnrollmentFailure): Nothing = throw AgentEnrollmentException(failure)
}

internal enum class WalletRoute { WALLET, APPROVALS, AGENTS, RECEIVE }

internal object WalletIntentRouter {
    const val scheme = "activechain-wallet"
    fun route(intent: Intent?): WalletRoute? = route(intent?.dataString)

    fun route(raw: String?): WalletRoute? {
        val uri = try { raw?.let(::URI) } catch (_: Exception) { null } ?: return null
        if (uri.scheme != scheme || uri.rawQuery != null || uri.fragment != null) return null
        return when (uri.host) {
            "approvals" -> WalletRoute.APPROVALS
            "agents" -> WalletRoute.AGENTS
            "receive" -> WalletRoute.RECEIVE
            else -> null
        }
    }
}

internal fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
