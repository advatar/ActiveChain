use super::{
    ActivechainWalletAgentSummary, ActivechainWalletCashApproval,
    ActivechainWalletProposalApproval, WALLET_BUFFER_TOO_SMALL, WALLET_OK,
    activechain_wallet_agent_count, activechain_wallet_agent_register,
    activechain_wallet_agent_revoke, activechain_wallet_agent_set_paused,
    activechain_wallet_agent_summary, activechain_wallet_cash_approval,
    activechain_wallet_proposal_approval, activechain_wallet_sign_cash_intent,
    activechain_wallet_sign_proposal_intent, activechain_wallet_submit_authorized,
    activechain_wallet_submit_authorized_proposal,
    activechain_wallet_verify_owner_coin_cell_record,
};
use activechain_canonical_codec::decode_envelope;
use activechain_proposal_gateway::ActionIntentV1;
use activechain_wallet_core::CashAuthorizationRequestV1;
use core::ffi::c_void;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};

const INTENT_LENGTH: usize = 48;
const PUBLIC_KEY_LENGTH: usize = 1_312;
const SIGNATURE_LENGTH: usize = 2_420;

fn snapshot(env: &JNIEnv<'_>, value: &JByteArray<'_>) -> Result<Vec<u8>, String> {
    env.convert_byte_array(value).map_err(|error| error.to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeOwnerCoinProofVerifier_nativeVerify(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    key: JByteArray<'_>,
    finalized_height: jlong,
    value: JByteArray<'_>,
    proof: JByteArray<'_>,
    finality: JByteArray<'_>,
    owner: JByteArray<'_>,
    trusted_genesis: JByteArray<'_>,
) -> jboolean {
    let result: Result<jboolean, String> = (|| {
        let key = snapshot(&env, &key)?;
        let value = snapshot(&env, &value)?;
        let proof = snapshot(&env, &proof)?;
        let finality = snapshot(&env, &finality)?;
        let owner = snapshot(&env, &owner)?;
        let trusted_genesis = snapshot(&env, &trusted_genesis)?;
        if key.len() != 48 || owner.len() != 48 || trusted_genesis.len() != 48 {
            return Err("owner proof identifiers must be 48 bytes".into());
        }
        let height =
            u64::try_from(finalized_height).map_err(|_| "negative finalized height".to_string())?;
        let lengths = [value.len(), proof.len(), finality.len()];
        if lengths.iter().any(|length| *length > u32::MAX as usize) {
            return Err("owner proof input exceeds ABI length".into());
        }
        let code = unsafe {
            activechain_wallet_verify_owner_coin_cell_record(
                key.as_ptr(),
                height,
                value.as_ptr(),
                value.len() as u32,
                proof.as_ptr(),
                proof.len() as u32,
                finality.as_ptr(),
                finality.len() as u32,
                owner.as_ptr(),
                trusted_genesis.as_ptr(),
            )
        };
        Ok(if code == WALLET_OK { 1 } else { 0 })
    })();
    result.unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeProposalApproval_nativeReviewProposal(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    intent: JByteArray<'_>,
    height: jlong,
) -> jstring {
    let result = (|| {
        let intent = snapshot(&env, &intent)?;
        let height = u64::try_from(height).map_err(|_| "negative finalized height")?;
        let mut approval = ActivechainWalletProposalApproval::default();
        let code = unsafe {
            activechain_wallet_proposal_approval(
                intent.as_ptr(),
                intent.len() as u32,
                height,
                &mut approval,
            )
        };
        if code != WALLET_OK {
            return Err(format!("canonical proposal review failed with {code}"));
        }
        let text = |bytes: &[u8], length: u32| -> Result<String, String> {
            core::str::from_utf8(&bytes[..length as usize])
                .map(str::to_owned)
                .map_err(|_| "non-UTF-8 canonical identifier".into())
        };
        Ok(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            text(&approval.request_id, approval.request_id_len)?,
            text(&approval.chain_id, approval.chain_id_len)?,
            text(&approval.wallet_id, approval.wallet_id_len)?,
            text(&approval.request_nonce, approval.request_nonce_len)?,
            hex(&approval.agent_principal),
            hex(&approval.capability_id),
            hex(&approval.resource),
            hex(&approval.recipient),
            hex(&approval.replay_domain),
            hex(&approval.intent_commitment),
            hex(&approval.proposal_id),
            approval.action,
            approval.amount_high,
            approval.amount_low,
            approval.maximum_fee_high,
            approval.maximum_fee_low,
            approval.expires_at_height
        ))
    })();
    match result.and_then(|value| {
        env.new_string(value).map(|value| value.into_raw()).map_err(|error| error.to_string())
    }) {
        Ok(value) => value,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", error);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeProposalApproval_nativeProposalSigningPayload(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    intent: JByteArray<'_>,
    commitment: JByteArray<'_>,
    height: jlong,
) -> jbyteArray {
    let result = (|| {
        let intent = snapshot(&env, &intent)?;
        let approved = snapshot(&env, &commitment)?;
        let height = u64::try_from(height).map_err(|_| "negative finalized height")?;
        if approved.len() != INTENT_LENGTH {
            return Err("approved commitment must be 48 bytes".into());
        }
        let decoded = decode_envelope::<ActionIntentV1>(&intent)
            .map_err(|_| "malformed canonical proposal intent".to_owned())?;
        if height >= decoded.expires_at_height {
            return Err("canonical proposal expired".into());
        }
        if decoded.commitment().map_err(|_| "invalid proposal commitment")?.as_bytes()
            != approved.as_slice()
        {
            return Err("canonical proposal approval does not match intent".into());
        }
        decoded.signing_payload().map_err(|_| "invalid proposal signing payload".into())
    })();
    byte_array_or_throw(env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeProposalApproval_nativeAuthorizeProposal(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    intent: JByteArray<'_>,
    commitment: JByteArray<'_>,
    height: jlong,
    public_key: JByteArray<'_>,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let intent = snapshot(&env, &intent)?;
        let commitment = snapshot(&env, &commitment)?;
        let height = u64::try_from(height).map_err(|_| "negative finalized height")?;
        let public_key = snapshot(&env, &public_key)?;
        let signature = FixedSignature(snapshot(&env, &signature)?);
        if commitment.len() != INTENT_LENGTH
            || public_key.len() != PUBLIC_KEY_LENGTH
            || signature.0.len() != SIGNATURE_LENGTH
        {
            return Err("invalid canonical proposal signing material length".into());
        }
        let context = (&signature as *const FixedSignature).cast_mut().cast::<c_void>();
        let mut required = 0;
        let invoke = |output, capacity, required: &mut u32| unsafe {
            activechain_wallet_sign_proposal_intent(
                intent.as_ptr(),
                intent.len() as u32,
                height,
                commitment.as_ptr(),
                public_key.as_ptr(),
                Some(fixed_signature_callback),
                context,
                output,
                capacity,
                required,
            )
        };
        let query = invoke(core::ptr::null_mut(), 0, &mut required);
        if query != WALLET_BUFFER_TOO_SMALL || required == 0 {
            return Err(format!("proposal authorization size query failed with {query}"));
        }
        let mut output = vec![0; required as usize];
        let code = invoke(output.as_mut_ptr(), required, &mut required);
        if code != WALLET_OK {
            return Err(format!("proposal authorization failed with {code}"));
        }
        Ok(output)
    })();
    byte_array_or_throw(env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeProposalApproval_nativeVerifyProposalForSubmission(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    envelope: JByteArray<'_>,
    height: jlong,
) -> jbyteArray {
    let result = (|| {
        let envelope = snapshot(&env, &envelope)?;
        let height = u64::try_from(height).map_err(|_| "negative finalized height")?;
        let mut captured = Vec::new();
        let code = unsafe {
            activechain_wallet_submit_authorized_proposal(
                envelope.as_ptr(),
                envelope.len() as u32,
                height,
                Some(capture_submission_callback),
                (&mut captured as *mut Vec<u8>).cast(),
            )
        };
        if code != WALLET_OK {
            return Err(format!("proposal submission verification failed with {code}"));
        }
        Ok(captured)
    })();
    byte_array_or_throw(env, result)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeCanonicalApproval_nativeReview(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    request: JByteArray<'_>,
) -> jstring {
    let result = (|| {
        let request = snapshot(&env, &request)?;
        let mut approval = ActivechainWalletCashApproval::default();
        let code = unsafe {
            activechain_wallet_cash_approval(request.as_ptr(), request.len() as u32, &mut approval)
        };
        if code != WALLET_OK {
            return Err(format!("canonical wallet approval failed with {code}"));
        }
        Ok(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            hex(&approval.chain_id),
            hex(&approval.signer),
            hex(&approval.recipient),
            hex(&approval.fee_reserve),
            hex(&approval.session_id),
            hex(&approval.intent_id),
            approval.nonce,
            approval.session_expires_at,
            approval.amount_high,
            approval.amount_low,
            approval.fee_high,
            approval.fee_low,
            approval.valid_until,
            approval.input_count,
        ))
    })();
    match result.and_then(|value| {
        env.new_string(value).map(|value| value.into_raw()).map_err(|error| error.to_string())
    }) {
        Ok(value) => value,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", error);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeCanonicalApproval_nativeSigningPayload(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    request: JByteArray<'_>,
    intent: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let request = snapshot(&env, &request)?;
        let approved = snapshot(&env, &intent)?;
        if approved.len() != INTENT_LENGTH {
            return Err("approved intent must be 48 bytes".into());
        }
        let decoded = decode_envelope::<CashAuthorizationRequestV1>(&request)
            .map_err(|_| "malformed canonical cash request".to_owned())?;
        let actual = decoded.intent_id().map_err(|_| "invalid cash intent".to_owned())?;
        if actual.as_bytes() != approved.as_slice() {
            return Err("canonical approval does not match request".into());
        }
        decoded.signing_payload().map_err(|_| "invalid cash signing payload".to_owned())
    })();
    byte_array_or_throw(env, result)
}

struct FixedSignature(Vec<u8>);

unsafe extern "C" fn fixed_signature_callback(
    context: *mut c_void,
    _payload: *const u8,
    _payload_len: u32,
    signature_out: *mut u8,
    signature_len: u32,
) -> u32 {
    if context.is_null() || signature_out.is_null() || signature_len as usize != SIGNATURE_LENGTH {
        return 1;
    }
    let signature = unsafe { &*context.cast::<FixedSignature>() };
    if signature.0.len() != SIGNATURE_LENGTH {
        return 1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(signature.0.as_ptr(), signature_out, SIGNATURE_LENGTH);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeCanonicalApproval_nativeAuthorize(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    request: JByteArray<'_>,
    intent: JByteArray<'_>,
    public_key: JByteArray<'_>,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let request = snapshot(&env, &request)?;
        let intent = snapshot(&env, &intent)?;
        let public_key = snapshot(&env, &public_key)?;
        let signature = FixedSignature(snapshot(&env, &signature)?);
        if intent.len() != INTENT_LENGTH
            || public_key.len() != PUBLIC_KEY_LENGTH
            || signature.0.len() != SIGNATURE_LENGTH
        {
            return Err("invalid canonical signing material length".into());
        }
        let mut required = 0;
        let context = (&signature as *const FixedSignature).cast_mut().cast::<c_void>();
        let query = unsafe {
            activechain_wallet_sign_cash_intent(
                request.as_ptr(),
                request.len() as u32,
                intent.as_ptr(),
                public_key.as_ptr(),
                Some(fixed_signature_callback),
                context,
                core::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if query != WALLET_BUFFER_TOO_SMALL || required == 0 {
            return Err(format!("canonical authorization size query failed with {query}"));
        }
        let mut authorized = vec![0; required as usize];
        let code = unsafe {
            activechain_wallet_sign_cash_intent(
                request.as_ptr(),
                request.len() as u32,
                intent.as_ptr(),
                public_key.as_ptr(),
                Some(fixed_signature_callback),
                context,
                authorized.as_mut_ptr(),
                required,
                &mut required,
            )
        };
        if code != WALLET_OK {
            return Err(format!("canonical authorization failed with {code}"));
        }
        Ok(authorized)
    })();
    byte_array_or_throw(env, result)
}

unsafe extern "C" fn capture_submission_callback(
    context: *mut c_void,
    envelope: *const u8,
    envelope_len: u32,
) -> u32 {
    if context.is_null() || envelope.is_null() || envelope_len == 0 {
        return 1;
    }
    let captured = unsafe { &mut *context.cast::<Vec<u8>>() };
    let bytes = unsafe { core::slice::from_raw_parts(envelope, envelope_len as usize) };
    captured.extend_from_slice(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_NativeCanonicalApproval_nativeVerifyForSubmission(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    envelope: JByteArray<'_>,
    public_key: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let envelope = snapshot(&env, &envelope)?;
        let public_key = snapshot(&env, &public_key)?;
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err("invalid submission public key length".into());
        }
        let mut captured = Vec::new();
        let code = unsafe {
            activechain_wallet_submit_authorized(
                envelope.as_ptr(),
                envelope.len() as u32,
                public_key.as_ptr(),
                Some(capture_submission_callback),
                (&mut captured as *mut Vec<u8>).cast(),
            )
        };
        if code != WALLET_OK {
            return Err(format!("canonical submission verification failed with {code}"));
        }
        Ok(captured)
    })();
    byte_array_or_throw(env, result)
}

fn principal(value: &[u8]) -> Result<[u8; 48], String> {
    value.try_into().map_err(|_| "principal must be 48 bytes".into())
}

fn transition(
    current: &[u8],
    operation: impl Fn(*mut u8, u32, *mut u32) -> u32,
) -> Result<Vec<u8>, String> {
    let mut required = 0;
    let query = operation(core::ptr::null_mut(), 0, &mut required);
    if query != WALLET_BUFFER_TOO_SMALL || required == 0 {
        return Err(format!("wallet ABI size query failed with {query}"));
    }
    let mut next = vec![0; required as usize];
    let code = operation(next.as_mut_ptr(), required, &mut required);
    if code != WALLET_OK {
        return Err(format!("wallet ABI transition failed with {code}"));
    }
    let _ = current;
    Ok(next)
}

fn byte_array_or_throw(mut env: JNIEnv<'_>, result: Result<Vec<u8>, String>) -> jbyteArray {
    match result.and_then(|bytes| {
        env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw())
            .map_err(|error| error.to_string())
    }) {
        Ok(array) => array,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalStateException", error);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_RustAgentRegistry_nativeRegister(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    registry: JByteArray<'_>,
    principal_byte: jint,
    capability_byte: jint,
    label: JString<'_>,
    connection: jint,
    budget: jlong,
    expires_at: jlong,
) -> jbyteArray {
    let result = (|| {
        let current = snapshot(&env, &registry)?;
        let principal = [principal_byte as u8; 48];
        let capability = [capability_byte as u8; 48];
        let label: String = env.get_string(&label).map_err(|error| error.to_string())?.into();
        transition(&current, |output, capacity, required| unsafe {
            activechain_wallet_agent_register(
                current.as_ptr(),
                current.len() as u32,
                principal.as_ptr(),
                label.as_ptr(),
                label.len() as u32,
                connection as u32,
                capability.as_ptr(),
                1,
                0,
                budget as u64,
                expires_at as u64,
                output,
                capacity,
                required,
            )
        })
    })();
    byte_array_or_throw(env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_RustAgentRegistry_nativeSetPaused(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    registry: JByteArray<'_>,
    principal_bytes: JByteArray<'_>,
    paused: jboolean,
) -> jbyteArray {
    let result = (|| {
        let current = snapshot(&env, &registry)?;
        let principal = principal(&snapshot(&env, &principal_bytes)?)?;
        transition(&current, |output, capacity, required| unsafe {
            activechain_wallet_agent_set_paused(
                current.as_ptr(),
                current.len() as u32,
                principal.as_ptr(),
                u32::from(paused != 0),
                output,
                capacity,
                required,
            )
        })
    })();
    byte_array_or_throw(env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_RustAgentRegistry_nativeRevoke(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    registry: JByteArray<'_>,
    principal_bytes: JByteArray<'_>,
    finalized_height: jlong,
) -> jbyteArray {
    let result = (|| {
        let current = snapshot(&env, &registry)?;
        let principal = principal(&snapshot(&env, &principal_bytes)?)?;
        let transaction = principal.map(|byte| byte ^ 0x5a);
        transition(&current, |output, capacity, required| unsafe {
            activechain_wallet_agent_revoke(
                current.as_ptr(),
                current.len() as u32,
                principal.as_ptr(),
                transaction.as_ptr(),
                finalized_height as u64,
                output,
                capacity,
                required,
            )
        })
    })();
    byte_array_or_throw(env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_RustAgentRegistry_nativeCount(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    registry: JByteArray<'_>,
) -> jint {
    let result = (|| {
        let current = snapshot(&env, &registry)?;
        let mut count = 0;
        let code = unsafe {
            activechain_wallet_agent_count(current.as_ptr(), current.len() as u32, &mut count)
        };
        (code == WALLET_OK)
            .then_some(count as jint)
            .ok_or_else(|| format!("wallet ABI count failed with {code}"))
    })();
    match result {
        Ok(count) => count,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalStateException", error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_activechain_wallet_RustAgentRegistry_nativeSummary(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    registry: JByteArray<'_>,
    index: jint,
) -> jstring {
    let result = (|| {
        let current = snapshot(&env, &registry)?;
        let mut summary = ActivechainWalletAgentSummary::default();
        let mut required = 0;
        let query = unsafe {
            activechain_wallet_agent_summary(
                current.as_ptr(),
                current.len() as u32,
                index as u32,
                &mut summary,
                core::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if query != WALLET_BUFFER_TOO_SMALL || required == 0 {
            return Err(format!("wallet ABI summary query failed with {query}"));
        }
        let mut label = vec![0; required as usize];
        let code = unsafe {
            activechain_wallet_agent_summary(
                current.as_ptr(),
                current.len() as u32,
                index as u32,
                &mut summary,
                label.as_mut_ptr(),
                required,
                &mut required,
            )
        };
        if code != WALLET_OK {
            return Err(format!("wallet ABI summary failed with {code}"));
        }
        let label = String::from_utf8(label).map_err(|error| error.to_string())?;
        let principal =
            summary.principal.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        Ok(format!(
            "{principal}\t{label}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            summary.connection,
            summary.lifecycle,
            summary.capability_count,
            summary.budget_limit_low,
            summary.budget_spent_low,
            summary.expires_at,
            summary.revocation_finalized_height,
        ))
    })();
    match result.and_then(|value| {
        env.new_string(value).map(|string| string.into_raw()).map_err(|error| error.to_string())
    }) {
        Ok(string) => string,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalStateException", error);
            core::ptr::null_mut()
        }
    }
}
