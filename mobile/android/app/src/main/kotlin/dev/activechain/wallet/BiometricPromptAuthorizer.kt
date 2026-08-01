package dev.activechain.wallet

import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher

internal sealed interface BiometricAuthorizationResult {
    data class Authorized(val cipher: Cipher) : BiometricAuthorizationResult
    data class Rejected(val failure: AndroidCustodyFailure) : BiometricAuthorizationResult
}

/** One terminal result wins; late or duplicate callbacks cannot authorize a consumed attempt. */
internal class BiometricAuthorizationAttempt {
    private val completed = AtomicBoolean(false)
    private val result = AtomicReference<BiometricAuthorizationResult?>()
    private val latch = CountDownLatch(1)

    fun complete(candidate: BiometricAuthorizationResult): Boolean {
        if (!completed.compareAndSet(false, true)) return false
        result.set(candidate)
        latch.countDown()
        return true
    }

    fun await(timeoutMillis: Long): BiometricAuthorizationResult? {
        if (!latch.await(timeoutMillis, TimeUnit.MILLISECONDS)) return null
        return result.get()
    }
}

/**
 * Authenticates the exact Android Keystore Cipher through AndroidX BiometricPrompt.
 *
 * Custody work must invoke this adapter off the main thread. Prompt callbacks execute on the main
 * executor; this call blocks only the custody worker until one terminal callback or timeout.
 */
class BiometricPromptAuthorizer(
    private val activity: FragmentActivity,
    private val timeoutMillis: Long = 120_000,
) : AndroidUserPresenceAuthorizer {
    init {
        require(timeoutMillis > 0)
    }

    override fun authorize(cipher: Cipher, reason: String): Cipher {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw AndroidCustodyException(AndroidCustodyFailure.USER_PRESENCE_REQUIRED)
        }
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        when (BiometricManager.from(activity).canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN,
            -> throw AndroidCustodyException(AndroidCustodyFailure.HARDWARE_UNAVAILABLE)

            else -> throw AndroidCustodyException(AndroidCustodyFailure.HARDWARE_UNAVAILABLE)
        }

        val attempt = BiometricAuthorizationAttempt()
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.cipher
                    val outcome = if (authenticated === cipher) {
                        BiometricAuthorizationResult.Authorized(cipher)
                    } else {
                        BiometricAuthorizationResult.Rejected(AndroidCustodyFailure.WRONG_KEY)
                    }
                    attempt.complete(outcome)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    attempt.complete(BiometricAuthorizationResult.Rejected(mapError(errorCode)))
                }

                // A failed biometric comparison is non-terminal. BiometricPrompt continues and
                // eventually reports success, cancellation, lockout, or another terminal error.
                override fun onAuthenticationFailed() = Unit
            },
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authorize ActiveChain wallet")
            .setSubtitle(reason)
            .setAllowedAuthenticators(authenticators)
            .build()
        activity.runOnUiThread {
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }

        val result = try {
            attempt.await(timeoutMillis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }
        if (result == null) {
            attempt.complete(
                BiometricAuthorizationResult.Rejected(
                    AndroidCustodyFailure.AUTHENTICATION_CANCELLED,
                ),
            )
            activity.runOnUiThread(prompt::cancelAuthentication)
            throw AndroidCustodyException(AndroidCustodyFailure.AUTHENTICATION_CANCELLED)
        }
        return when (result) {
            is BiometricAuthorizationResult.Authorized -> result.cipher
            is BiometricAuthorizationResult.Rejected -> throw AndroidCustodyException(result.failure)
        }
    }

    private fun mapError(errorCode: Int): AndroidCustodyFailure = when (errorCode) {
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        -> AndroidCustodyFailure.DEVICE_LOCKED

        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
        -> AndroidCustodyFailure.HARDWARE_UNAVAILABLE

        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_TIMEOUT,
        -> AndroidCustodyFailure.AUTHENTICATION_CANCELLED

        else -> AndroidCustodyFailure.USER_PRESENCE_REQUIRED
    }
}
