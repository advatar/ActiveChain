package dev.activechain.wallet

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AgentWalletTest {
    @Test fun delegationIsReplaySafePauseableAndFinalityAware() {
        val store = AgentWalletStore()
        val agent = AgentDelegation("agent-1", "Research agent", listOf("transfer"), 100, 100)
        assertTrue(store.delegate(agent))
        assertFalse(store.delegate(agent))
        store.pause("agent-1")
        assertEquals(AgentLifecycle.Paused, store.agents.single().lifecycle)
        store.resume("agent-1")
        assertEquals(AgentLifecycle.Active, store.agents.single().lifecycle)
        store.revoke("agent-1")
        assertEquals(AgentLifecycle.RevocationPending, store.agents.single().lifecycle)
        assertFalse(store.agents.single().revoked)
        store.resume("agent-1")
        assertEquals(AgentLifecycle.RevocationPending, store.agents.single().lifecycle)
        store.finalizeRevocation("agent-1", 42)
        assertEquals(AgentLifecycle.Revoked(42), store.agents.single().lifecycle)
        assertTrue(store.agents.single().revoked)
    }
}
