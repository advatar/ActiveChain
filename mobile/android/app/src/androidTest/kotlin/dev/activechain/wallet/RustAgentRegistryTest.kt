package dev.activechain.wallet

import androidx.test.core.app.ApplicationProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class RustAgentRegistryTest {
    @Test
    fun lifecycleTransitionsSurviveSnapshotReload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val snapshot = File(context.cacheDir, "agent-test-${System.nanoTime()}.bin")
        try {
            val initial = RustAgentRegistry(snapshot)
            assertEquals(2, initial.agents.size)
            val id = initial.agents.first().id
            initial.pause(id)
            assertEquals(AgentLifecycle.Paused, initial.agents.first().lifecycle)

            val restored = RustAgentRegistry(snapshot)
            assertEquals(AgentLifecycle.Paused, restored.agents.first().lifecycle)
            restored.resume(id)
            restored.revoke(id)
            assertEquals(AgentLifecycle.RevocationPending, restored.agents.first().lifecycle)
            restored.finalizeRevocation(id, 42)

            val finalized = RustAgentRegistry(snapshot)
            assertEquals(AgentLifecycle.Revoked(42), finalized.agents.first().lifecycle)
        } finally {
            snapshot.delete()
        }
    }
}
