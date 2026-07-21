package dev.activechain.wallet

data class AgentDelegation(val id: String, val label: String, val capabilities: List<String>,
                           val dailyLimit: Long, val expiresAt: Long, var revoked: Boolean = false)
data class PendingApproval(val id: String, val agentId: String, val recipient: String,
                           val amount: Long, val feeReserve: Long, val networkId: String)

class AgentWalletStore {
    val agents = mutableListOf<AgentDelegation>()
    val pending = mutableListOf<PendingApproval>()
    fun delegate(agent: AgentDelegation): Boolean { if (agents.any { it.id == agent.id }) return false; agents += agent; return true }
    fun enqueue(approval: PendingApproval) { pending += approval }
    fun revoke(id: String) { agents.firstOrNull { it.id == id }?.revoked = true }
}
