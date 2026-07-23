use super::{
    ActivechainWalletAgentSummary, WALLET_BUFFER_TOO_SMALL, WALLET_OK,
    activechain_wallet_agent_count, activechain_wallet_agent_register,
    activechain_wallet_agent_revoke, activechain_wallet_agent_set_paused,
    activechain_wallet_agent_summary,
};
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};

fn snapshot(env: &JNIEnv<'_>, value: &JByteArray<'_>) -> Result<Vec<u8>, String> {
    env.convert_byte_array(value).map_err(|error| error.to_string())
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
