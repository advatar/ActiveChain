package dev.activechain.wallet

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AgentWalletTest {
    @Test fun delegationIsReplaySafeAndRevocable() {
        val store = AgentWalletStore()
        val agent = AgentDelegation("agent-1", "Research agent", listOf("transfer"), 100, 100)
        assertTrue(store.delegate(agent)); assertFalse(store.delegate(agent)); store.revoke("agent-1")
        assertTrue(store.agents.single().revoked)
    }
}
