use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use activechain_protocol_types::Digest384;

use crate::{
    DurableUsageRegistry, MAX_USAGE_ENTRIES, UsageEntry, UsageRegistrationV1, UsageState,
    VerificationErrorCodeV1, VerificationErrorV1, encode_usage,
};

const HELPER_ENV: &str = "ACTUM_USAGE_TEST_HELPER";
const PATH_ENV: &str = "ACTUM_USAGE_TEST_PATH";
const START_ENV: &str = "ACTUM_USAGE_TEST_START";
const RESULT_ENV: &str = "ACTUM_USAGE_TEST_RESULT";
const DOMAIN_ENV: &str = "ACTUM_USAGE_TEST_DOMAIN";
const NULLIFIER_ENV: &str = "ACTUM_USAGE_TEST_NULLIFIER";
const CLAIM_ENV: &str = "ACTUM_USAGE_TEST_CLAIM";

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn indexed_digest(prefix: u8, index: u64) -> Digest384 {
    let mut bytes = [prefix; 48];
    bytes[40..].copy_from_slice(&index.to_be_bytes());
    Digest384::new(bytes)
}

fn env_byte(name: &str) -> u8 {
    env::var(name).expect("helper byte environment").parse().expect("valid helper byte")
}

#[test]
fn usage_registry_process_helper() {
    if env::var_os(HELPER_ENV).is_none() {
        return;
    }
    if let Some(start) = env::var_os(START_ENV).map(PathBuf::from) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !start.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(start.exists(), "multiprocess start barrier timed out");
    }
    let path = PathBuf::from(env::var_os(PATH_ENV).expect("helper registry path"));
    let result_path = PathBuf::from(env::var_os(RESULT_ENV).expect("helper result path"));
    let registry = DurableUsageRegistry::open(path).expect("open helper registry");
    let result = registry.register_all(
        digest(env_byte(DOMAIN_ENV)),
        &[digest(env_byte(NULLIFIER_ENV))],
        digest(env_byte(CLAIM_ENV)),
        1,
        1,
        100,
    );
    let label = match result {
        Ok(UsageRegistrationV1::Inserted) => "inserted",
        Ok(UsageRegistrationV1::Idempotent) => "idempotent",
        Err(VerificationErrorV1 { code: VerificationErrorCodeV1::UsageDoubleSpend, .. }) => {
            "double_spend"
        }
        Err(_) => "unexpected_error",
    };
    fs::write(result_path, label).expect("write helper result");
}

struct HelperProcess {
    child: Child,
    result_path: PathBuf,
}

fn spawn_helper(
    directory: &Path,
    registry_path: &Path,
    start_path: Option<&Path>,
    result_name: &str,
    nullifier: u8,
    claim: u8,
    crash_point: Option<&str>,
) -> HelperProcess {
    let result_path = directory.join(result_name);
    let mut command = Command::new(env::current_exe().expect("current test binary"));
    command
        .arg("--exact")
        .arg("multiprocess_tests::usage_registry_process_helper")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(HELPER_ENV, "1")
        .env(PATH_ENV, registry_path)
        .env(RESULT_ENV, &result_path)
        .env(DOMAIN_ENV, "1")
        .env(NULLIFIER_ENV, nullifier.to_string())
        .env(CLAIM_ENV, claim.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(start_path) = start_path {
        command.env(START_ENV, start_path);
    }
    if let Some(crash_point) = crash_point {
        command.env("ACTUM_USAGE_TEST_CRASH_POINT", crash_point);
    }
    HelperProcess { child: command.spawn().expect("spawn registry helper"), result_path }
}

fn finish_helper(mut helper: HelperProcess) -> (ExitStatus, Option<String>) {
    let status = helper.child.wait().expect("wait for registry helper");
    let result = fs::read_to_string(helper.result_path).ok();
    (status, result)
}

fn simultaneous_results(
    directory: &Path,
    registry_path: &Path,
    left: (u8, u8),
    right: (u8, u8),
) -> Vec<String> {
    let start_path = directory.join("start");
    let left = spawn_helper(
        directory,
        registry_path,
        Some(&start_path),
        "left.result",
        left.0,
        left.1,
        None,
    );
    let right = spawn_helper(
        directory,
        registry_path,
        Some(&start_path),
        "right.result",
        right.0,
        right.1,
        None,
    );
    fs::write(&start_path, b"go").expect("release process barrier");
    let (left_status, left_result) = finish_helper(left);
    let (right_status, right_result) = finish_helper(right);
    assert!(left_status.success() && right_status.success());
    let mut results = vec![left_result.expect("left result"), right_result.expect("right result")];
    results.sort();
    results
}

#[test]
fn multiprocess_conflict_and_exact_claim_retry_are_serialized() {
    let conflict_directory = tempfile::tempdir().expect("conflict directory");
    let conflict_path = conflict_directory.path().join("usage.bin");
    assert_eq!(
        simultaneous_results(conflict_directory.path(), &conflict_path, (9, 7), (9, 8)),
        ["double_spend", "inserted"]
    );
    assert_eq!(
        DurableUsageRegistry::open(&conflict_path)
            .expect("open conflict result")
            .claim_entries()
            .expect("read conflict result")
            .len(),
        1
    );

    let retry_directory = tempfile::tempdir().expect("retry directory");
    let retry_path = retry_directory.path().join("usage.bin");
    assert_eq!(
        simultaneous_results(retry_directory.path(), &retry_path, (10, 11), (10, 11)),
        ["idempotent", "inserted"]
    );
    assert_eq!(
        DurableUsageRegistry::open(&retry_path)
            .expect("open retry result")
            .claim_entries()
            .expect("read retry result")
            .len(),
        1
    );
}

#[test]
fn multiprocess_nonconflicting_claims_and_stale_cache_preserve_all_entries() {
    let directory = tempfile::tempdir().expect("nonconflict directory");
    let path = directory.path().join("usage.bin");
    let stale = DurableUsageRegistry::open(&path).expect("open stale registry instance");
    assert_eq!(
        simultaneous_results(directory.path(), &path, (20, 21), (22, 23)),
        ["inserted", "inserted"]
    );
    assert_eq!(stale.claim_entries().expect("reload stale cache").len(), 2);
    assert_eq!(
        stale.register_all(digest(1), &[digest(20)], digest(24), 1, 1, 101),
        Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::UsageDoubleSpend))
    );
    assert_eq!(
        DurableUsageRegistry::open(path)
            .expect("open nonconflict result")
            .claim_entries()
            .expect("read nonconflict result")
            .len(),
        2
    );
}

#[test]
fn multiprocess_crash_boundaries_preserve_atomic_registry_state() {
    let directory = tempfile::tempdir().expect("crash directory");
    let path = directory.path().join("usage.bin");
    let registry = DurableUsageRegistry::open(&path).expect("open crash registry");
    assert_eq!(
        registry.register_all(digest(1), &[digest(30)], digest(31), 1, 1, 100),
        Ok(UsageRegistrationV1::Inserted)
    );
    drop(registry);

    let before_rename = spawn_helper(
        directory.path(),
        &path,
        None,
        "before-rename.result",
        32,
        33,
        Some("after_temp_sync"),
    );
    let (status, result) = finish_helper(before_rename);
    assert_eq!(status.code(), Some(86));
    assert!(result.is_none());
    assert_eq!(
        DurableUsageRegistry::open(&path)
            .expect("registry valid after pre-rename crash")
            .claim_entries()
            .expect("read after pre-rename crash")
            .len(),
        1
    );

    let after_rename = spawn_helper(
        directory.path(),
        &path,
        None,
        "after-rename.result",
        34,
        35,
        Some("after_rename"),
    );
    let (status, result) = finish_helper(after_rename);
    assert_eq!(status.code(), Some(86));
    assert!(result.is_none());
    assert_eq!(
        DurableUsageRegistry::open(path)
            .expect("registry valid after post-rename crash")
            .claim_entries()
            .expect("read after post-rename crash")
            .len(),
        2
    );
}

#[test]
#[ignore = "writes and reloads complete registry files up to the one-million-entry Preview bound"]
fn usage_registry_operational_load_profile() {
    for entries_after_admission in [10_000_usize, 100_000, 500_000, MAX_USAGE_ENTRIES] {
        let directory = tempfile::tempdir().expect("load-profile directory");
        let path = directory.path().join("usage.bin");
        let mut state = UsageState::default();
        for index in 0..entries_after_admission - 1 {
            let index = index as u64;
            let usage_domain = digest(1);
            let nullifier = indexed_digest(2, index);
            state.entries.insert(
                (usage_domain, nullifier),
                UsageEntry {
                    usage_domain,
                    nullifier,
                    claim_id: indexed_digest(3, index),
                    verifier_revision: 1,
                    trust_sequence: 1,
                    accepted_at_ms: 100,
                },
            );
        }
        let bytes = encode_usage(&state);
        fs::write(&path, &bytes).expect("write load-profile registry");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure load-profile registry");
        let open_started = Instant::now();
        let registry = DurableUsageRegistry::open(&path).expect("open load-profile registry");
        let open_elapsed = open_started.elapsed();
        let admission_started = Instant::now();
        assert_eq!(
            registry.register_all(
                digest(1),
                &[indexed_digest(2, entries_after_admission as u64)],
                indexed_digest(3, entries_after_admission as u64),
                1,
                1,
                100,
            ),
            Ok(UsageRegistrationV1::Inserted)
        );
        let admission_elapsed = admission_started.elapsed();
        println!(
            "entries={entries_after_admission} file_bytes={} open_ms={} admission_ms={}",
            fs::metadata(&path).expect("load-profile metadata").len(),
            open_elapsed.as_millis(),
            admission_elapsed.as_millis(),
        );
    }
}
