package dev.activechain.wallet

import androidx.test.core.app.ApplicationProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertEquals

class RustAgentRegistryTest {
    @Test
    fun emptyRegistryDoesNotInventAgentsOrPersistSampleAuthority() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val snapshot = File(context.cacheDir, "agent-test-${System.nanoTime()}.bin")
        try {
            assertEquals(emptyList(), RustAgentRegistry(snapshot).agents)
            assertFalse(snapshot.exists())
        } finally {
            snapshot.delete()
        }
    }
}
