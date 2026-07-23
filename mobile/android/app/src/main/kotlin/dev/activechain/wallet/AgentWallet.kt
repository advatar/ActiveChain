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
