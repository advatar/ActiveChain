use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use activechain_protocol_types::Digest384;

use crate::status::DurableProofStatusStore;
use crate::{DurableUsageRegistry, MAX_USAGE_FILE_BYTES, ProofLifecycleV1, USAGE_MAGIC};

#[test]
fn durable_files_are_private_regular_files_and_oversize_fails_before_decode() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let usage_path = directory.path().join("usage.bin");
    let usage = DurableUsageRegistry::open(&usage_path).expect("open empty usage registry");
    usage
        .register_all(
            Digest384::new([1; 48]),
            &[Digest384::new([2; 48])],
            Digest384::new([3; 48]),
            1,
            1,
            1,
        )
        .expect("persist usage registry");
    assert_eq!(fs::metadata(&usage_path).expect("usage metadata").permissions().mode() & 0o077, 0);
    let lock_path = directory.path().join("usage.bin.lock");
    assert_eq!(
        fs::metadata(&lock_path).expect("usage lock metadata").permissions().mode() & 0o077,
        0
    );

    let alias = directory.path().join("usage-link.bin");
    symlink(&usage_path, &alias).expect("create usage symlink");
    assert!(DurableUsageRegistry::open(&alias).is_err());

    let lock_alias = directory.path().join("usage-alias.bin.lock");
    symlink(&lock_path, &lock_alias).expect("create usage lock symlink");
    assert!(DurableUsageRegistry::open(directory.path().join("usage-alias.bin")).is_err());

    fs::set_permissions(&usage_path, fs::Permissions::from_mode(0o644))
        .expect("make usage file insecure");
    assert!(DurableUsageRegistry::open(&usage_path).is_err());

    let oversized = directory.path().join("oversized.bin");
    let file = fs::File::create(&oversized).expect("create sparse usage file");
    file.set_len(MAX_USAGE_FILE_BYTES + 1).expect("size sparse usage file");
    file.set_permissions(fs::Permissions::from_mode(0o600)).expect("secure sparse usage file");
    assert!(DurableUsageRegistry::open(&oversized).is_err());

    let malformed = directory.path().join("malformed.bin");
    let mut empty = USAGE_MAGIC.to_vec();
    empty.extend_from_slice(&0_u32.to_be_bytes());
    fs::write(&malformed, empty).expect("write empty usage registry");
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600))
        .expect("secure empty usage registry");
    assert!(DurableUsageRegistry::open(&malformed).is_ok());
}

#[test]
fn proof_status_permissions_fail_closed_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("status.bin");
    let claim_id = [4_u8; 48];
    let mut status = DurableProofStatusStore::open(&path).expect("open proof status");
    status.record(claim_id, ProofLifecycleV1::ProofGenerated).expect("persist proof status");
    assert_eq!(fs::metadata(&path).expect("status metadata").permissions().mode() & 0o077, 0);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
        .expect("make proof status insecure");
    assert!(DurableProofStatusStore::open(&path).is_err());
}
