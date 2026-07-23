package dev.activechain.wallet

enum class AgentConnection(val label: String) {
    WALLET_OWNED("Wallet-owned"),
    THIRD_PARTY("Third-party"),
    REMOTE("Remote"),
    MANAGED_DEVICE("Managed device")
}

sealed class AgentLifecycle {
    data object Active : AgentLifecycle()
    data object Paused : AgentLifecycle()
    data object RevocationPending : AgentLifecycle()
    data class Revoked(val finalizedHeight: Long) : AgentLifecycle()
}

data class AgentDelegation(val id: String, val label: String, val capabilities: List<String>,
                           val dailyLimit: Long, val expiresAt: Long,
                           val connection: AgentConnection = AgentConnection.THIRD_PARTY,
                           var spentToday: Long = 0,
                           var lifecycle: AgentLifecycle = AgentLifecycle.Active) {
    val revoked: Boolean get() = lifecycle is AgentLifecycle.Revoked
}
data class PendingApproval(val id: String, val agentId: String, val recipient: String,
                           val amount: Long, val feeReserve: Long, val networkId: String)

class AgentWalletStore {
    val agents = mutableListOf<AgentDelegation>()
    val pending = mutableListOf<PendingApproval>()
    fun delegate(agent: AgentDelegation): Boolean { if (agents.any { it.id == agent.id }) return false; agents += agent; return true }
    fun enqueue(approval: PendingApproval) { pending += approval }
    fun pause(id: String) {
        agents.firstOrNull { it.id == id && it.lifecycle == AgentLifecycle.Active }?.lifecycle =
            AgentLifecycle.Paused
    }
    fun resume(id: String) {
        agents.firstOrNull { it.id == id && it.lifecycle == AgentLifecycle.Paused }?.lifecycle =
            AgentLifecycle.Active
    }
    fun revoke(id: String) {
        agents.firstOrNull { it.id == id && it.lifecycle !is AgentLifecycle.Revoked }?.lifecycle =
            AgentLifecycle.RevocationPending
    }
    fun finalizeRevocation(id: String, height: Long) {
        if (height <= 0) return
        agents.firstOrNull {
            it.id == id && it.lifecycle == AgentLifecycle.RevocationPending
        }?.lifecycle = AgentLifecycle.Revoked(height)
    }
}
