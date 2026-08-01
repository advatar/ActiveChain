package dev.activechain.wallet

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class BiometricPromptAuthorizerTest {
    @Test
    fun firstTerminalCallbackWinsAndDuplicateCannotAuthorize() {
        val attempt = BiometricAuthorizationAttempt()
        assertTrue(
            attempt.complete(
                BiometricAuthorizationResult.Rejected(AndroidCustodyFailure.AUTHENTICATION_CANCELLED),
            ),
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        assertFalse(attempt.complete(BiometricAuthorizationResult.Authorized(cipher)))
        assertEquals(
            BiometricAuthorizationResult.Rejected(AndroidCustodyFailure.AUTHENTICATION_CANCELLED),
            attempt.await(1),
        )
    }

    @Test
    fun authorizedAttemptReturnsTheExactCipherInstance() {
        val attempt = BiometricAuthorizationAttempt()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        assertTrue(attempt.complete(BiometricAuthorizationResult.Authorized(cipher)))
        val result = attempt.await(1) as BiometricAuthorizationResult.Authorized
        assertSame(cipher, result.cipher)
    }

    @Test
    fun awaitTimesOutWithoutAResultAndLateCompletionRemainsSingleUse() {
        val attempt = BiometricAuthorizationAttempt()
        assertNull(attempt.await(1))
        val released = CountDownLatch(1)
        thread {
            assertTrue(
                attempt.complete(
                    BiometricAuthorizationResult.Rejected(AndroidCustodyFailure.DEVICE_LOCKED),
                ),
            )
            released.countDown()
        }
        assertTrue(released.await(1, TimeUnit.SECONDS))
        assertEquals(
            BiometricAuthorizationResult.Rejected(AndroidCustodyFailure.DEVICE_LOCKED),
            attempt.await(1),
        )
    }
}
