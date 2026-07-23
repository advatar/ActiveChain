#![forbid(unsafe_code)]

use cbindgen::{Builder, Config, Language};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ArtifactHash {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SchemaRevision {
    name: String,
    type_tag: String,
    schema_revision: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CompatibilityManifest {
    format: String,
    source_revision: String,
    release_status: String,
    independently_audited: bool,
    verifier_abi_revision: u32,
    verifier_schema_revision: u32,
    wallet_abi_revision: u32,
    rpc_schema_revision: u32,
    light_client_schema_revision: u32,
    minimum_protocol_revision: u64,
    supported_protocol_revisions: Vec<u64>,
    schemas: Vec<SchemaRevision>,
    apple_slices: Vec<String>,
    upgrade_policy: String,
    artifacts: Vec<ArtifactHash>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("headers") => {
            let root = required_path(&mut arguments, "repository root")?;
            let output = required_path(&mut arguments, "header output directory")?;
            no_extra(arguments)?;
            generate_headers(&root, &output)
        }
        Some("sync-headers") => {
            let root = required_path(&mut arguments, "repository root")?;
            no_extra(arguments)?;
            sync_headers(&root)
        }
        Some("check-headers") => {
            let root = required_path(&mut arguments, "repository root")?;
            no_extra(arguments)?;
            check_headers(&root)
        }
        Some("manifest") => {
            let distribution = required_path(&mut arguments, "distribution directory")?;
            let source_revision = arguments.next().ok_or("missing source revision")?;
            let output = required_path(&mut arguments, "manifest output path")?;
            no_extra(arguments)?;
            write_manifest(&distribution, &source_revision, &output)
        }
        Some("package") => {
            let output = required_path(&mut arguments, "Package.swift output path")?;
            no_extra(arguments)?;
            write_swift_package(&output)
        }
        Some("verify") => {
            let manifest = required_path(&mut arguments, "manifest path")?;
            let distribution = required_path(&mut arguments, "distribution directory")?;
            no_extra(arguments)?;
            verify_manifest(&manifest, &distribution)
        }
        _ => Err("usage: activechain-apple-distribution \
             headers <repo> <output> | \
             sync-headers <repo> | check-headers <repo> | \
             manifest <distribution> <source-revision> <output> | \
             package <Package.swift-output> | \
             verify <manifest> <distribution>"
            .into()),
    }
}

fn write_swift_package(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        output,
        concat!(
            "// swift-tools-version: 5.9\n",
            "import PackageDescription\n\n",
            "let package = Package(\n",
            "    name: \"ActiveChainKit\",\n",
            "    platforms: [.iOS(.v15), .macOS(.v13)],\n",
            "    products: [\n",
            "        .library(name: \"ActiveChainVerifier\", targets: [\"ActiveChainVerifier\"]),\n",
            "        .library(name: \"ActiveChainWallet\", targets: [\"ActiveChainWallet\"]),\n",
            "    ],\n",
            "    targets: [\n",
            "        .binaryTarget(name: \"ActiveChainVerifier\", path: \"ActiveChainVerifier.xcframework\"),\n",
            "        .binaryTarget(name: \"ActiveChainWallet\", path: \"ActiveChainWallet.xcframework\"),\n",
            "    ]\n",
            ")\n",
        ),
    )?;
    Ok(())
}

fn sync_headers(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = temporary_headers_directory();
    let _ = fs::remove_dir_all(&temporary);
    generate_headers(root, &temporary)?;
    fs::create_dir_all(root.join("crates/verifier-api/include"))?;
    fs::create_dir_all(root.join("crates/wallet-ffi/include"))?;
    fs::copy(
        temporary.join("activechain_verifier.h"),
        root.join("crates/verifier-api/include/activechain_verifier.h"),
    )?;
    fs::copy(
        temporary.join("activechain_wallet.h"),
        root.join("crates/wallet-ffi/include/activechain_wallet.h"),
    )?;
    fs::remove_dir_all(temporary)?;
    Ok(())
}

fn check_headers(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = temporary_headers_directory();
    let _ = fs::remove_dir_all(&temporary);
    generate_headers(root, &temporary)?;
    let pairs = [
        (
            temporary.join("activechain_verifier.h"),
            root.join("crates/verifier-api/include/activechain_verifier.h"),
        ),
        (
            temporary.join("activechain_wallet.h"),
            root.join("crates/wallet-ffi/include/activechain_wallet.h"),
        ),
    ];
    for (generated, checked_in) in pairs {
        if fs::read(&generated)? != fs::read(&checked_in)? {
            return Err(format!("generated header drift: {}", checked_in.display()).into());
        }
    }
    fs::remove_dir_all(temporary)?;
    Ok(())
}

fn temporary_headers_directory() -> PathBuf {
    env::temp_dir().join(format!("activechain-generated-headers-{}", std::process::id()))
}

fn required_path(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments.next().map(PathBuf::from).ok_or_else(|| format!("missing {name}").into())
}

fn no_extra(mut arguments: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.next().is_some() { Err("unexpected argument".into()) } else { Ok(()) }
}

fn generate_headers(root: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output)?;
    generate_header(
        &root.join("crates/verifier-ffi"),
        &output.join("activechain_verifier.h"),
        "ACTIVECHAIN_VERIFIER_H",
    )?;
    let wallet = output.join("activechain_wallet.h");
    generate_header(&root.join("crates/wallet-ffi"), &wallet, "ACTIVECHAIN_WALLET_H")?;
    normalize_wallet_callbacks(&wallet)
}

fn generate_header(
    crate_dir: &Path,
    output: &Path,
    guard: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        language: Language::C,
        include_guard: Some(guard.to_owned()),
        autogen_warning: Some(
            "/* Generated by activechain-apple-distribution. Do not edit manually. */".to_owned(),
        ),
        documentation: true,
        cpp_compat: true,
        usize_is_size_t: true,
        ..Config::default()
    };
    Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .map_err(|error| format!("could not generate {}: {error}", crate_dir.display()))?
        .write_to_file(output);
    Ok(())
}

fn normalize_wallet_callbacks(header: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let original = fs::read_to_string(header)?;
    let sign_forward = "typedef struct Option_ActivechainWalletSignCallback Option_ActivechainWalletSignCallback;\n";
    let submit_forward = "typedef struct Option_ActivechainWalletSubmitCallback Option_ActivechainWalletSubmitCallback;\n";
    let sign_parameter = "struct Option_ActivechainWalletSignCallback callback";
    let submit_parameter = "struct Option_ActivechainWalletSubmitCallback callback";
    if !original.contains(sign_forward)
        || !original.contains(submit_forward)
        || !original.contains(sign_parameter)
        || !original.contains(submit_parameter)
    {
        return Err("cbindgen wallet callback layout changed unexpectedly".into());
    }
    let callbacks = concat!(
        "typedef uint32_t (*activechain_wallet_sign_callback)(\n",
        "    void *context,\n",
        "    const uint8_t *payload,\n",
        "    uint32_t payload_len,\n",
        "    uint8_t *signature_out,\n",
        "    uint32_t signature_len);\n\n",
        "typedef uint32_t (*activechain_wallet_submit_callback)(\n",
        "    void *context,\n",
        "    const uint8_t *envelope,\n",
        "    uint32_t envelope_len);\n",
    );
    let normalized = original
        .replace(sign_forward, callbacks)
        .replace(submit_forward, "")
        .replace(sign_parameter, "activechain_wallet_sign_callback callback")
        .replace(submit_parameter, "activechain_wallet_submit_callback callback");
    fs::write(header, normalized)?;
    Ok(())
}

fn write_manifest(
    distribution: &Path,
    source_revision: &str,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if source_revision.len() != 40 || !source_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("source revision must be a full hexadecimal Git object ID".into());
    }
    let mut artifacts = artifact_hashes(distribution, Some(output))?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = CompatibilityManifest {
        format: "activechain-apple-compatibility-v1".to_owned(),
        source_revision: source_revision.to_ascii_lowercase(),
        release_status: "developmental-unaudited".to_owned(),
        independently_audited: false,
        verifier_abi_revision: 1,
        verifier_schema_revision: 1,
        wallet_abi_revision: 1,
        rpc_schema_revision: 1,
        light_client_schema_revision: 1,
        minimum_protocol_revision: 1,
        supported_protocol_revisions: vec![1],
        schemas: supported_schemas(),
        apple_slices: vec![
            "aarch64-apple-darwin".to_owned(),
            "aarch64-apple-ios".to_owned(),
            "aarch64-apple-ios-sim".to_owned(),
        ],
        upgrade_policy: "reject-unknown-abi-schema-or-protocol-revision".to_owned(),
        artifacts,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(output, [bytes.as_slice(), b"\n"].concat())?;
    Ok(())
}

fn verify_manifest(
    manifest_path: &Path,
    distribution: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(manifest_path)?;
    let manifest: CompatibilityManifest = serde_json::from_slice(&bytes)?;
    if manifest.format != "activechain-apple-compatibility-v1"
        || manifest.release_status != "developmental-unaudited"
        || manifest.independently_audited
        || manifest.verifier_abi_revision != 1
        || manifest.verifier_schema_revision != 1
        || manifest.wallet_abi_revision != 1
        || manifest.rpc_schema_revision != 1
        || manifest.light_client_schema_revision != 1
        || manifest.minimum_protocol_revision != 1
        || manifest.supported_protocol_revisions != [1]
        || manifest.schemas != supported_schemas()
        || manifest.apple_slices
            != ["aarch64-apple-darwin", "aarch64-apple-ios", "aarch64-apple-ios-sim"]
        || manifest.upgrade_policy != "reject-unknown-abi-schema-or-protocol-revision"
        || manifest.source_revision.len() != 40
        || !manifest.source_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        || manifest.artifacts.is_empty()
        || manifest.artifacts.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || manifest.artifacts.iter().any(|artifact| {
            artifact.sha256.len() != 64
                || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("incompatible ActiveChain Apple manifest".into());
    }
    let mut actual = artifact_hashes(distribution, Some(manifest_path))?;
    actual.sort_by(|left, right| left.path.cmp(&right.path));
    if actual != manifest.artifacts {
        return Err("Apple artifact hashes do not match the compatibility manifest".into());
    }
    Ok(())
}

fn supported_schemas() -> Vec<SchemaRevision> {
    [
        ("Principal", "0x0020"),
        ("CapabilityGrant", "0x0030"),
        ("PolicyDecision", "0x0042"),
        ("StateProof", "0x0055"),
        ("StateCommitment", "0x0056"),
        ("BlockReceipt", "0x0074"),
        ("FinalityCertificateBundle", "0x007a"),
        ("CashAuthorizationRequestV1", "0x008a"),
        ("AuthorizedCashTransferV1", "0x008b"),
    ]
    .into_iter()
    .map(|(name, type_tag)| SchemaRevision {
        name: name.to_owned(),
        type_tag: type_tag.to_owned(),
        schema_revision: 1,
    })
    .collect()
}

fn artifact_hashes(
    distribution: &Path,
    excluded: Option<&Path>,
) -> Result<Vec<ArtifactHash>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_files(distribution, &mut files)?;
    let excluded = excluded.and_then(|path| path.canonicalize().ok());
    let mut hashes = Vec::with_capacity(files.len());
    for file in files {
        if excluded.as_ref().is_some_and(|excluded| {
            file.canonicalize().is_ok_and(|candidate| candidate == *excluded)
        }) {
            continue;
        }
        let relative = file.strip_prefix(distribution)?;
        let path = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let digest = Sha256::digest(fs::read(&file)?);
        hashes.push(ArtifactHash { path, sha256: format!("{digest:x}") });
    }
    Ok(hashes)
}

fn collect_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        } else {
            return Err(format!("unsupported distribution entry: {}", path.display()).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_verification_rejects_revision_and_artifact_substitution() {
        let root =
            env::temp_dir().join(format!("activechain-apple-manifest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Artifacts")).unwrap();
        fs::write(root.join("Artifacts/library.a"), b"stable artifact").unwrap();
        let manifest = root.join("compatibility.json");
        write_manifest(&root, &"a".repeat(40), &manifest).unwrap();
        verify_manifest(&manifest, &root).unwrap();

        let mut incompatible: CompatibilityManifest =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        incompatible.verifier_abi_revision = 2;
        fs::write(&manifest, serde_json::to_vec_pretty(&incompatible).unwrap()).unwrap();
        assert!(verify_manifest(&manifest, &root).is_err());
        write_manifest(&root, &"a".repeat(40), &manifest).unwrap();

        fs::write(root.join("Artifacts/library.a"), b"substituted").unwrap();
        assert!(verify_manifest(&manifest, &root).is_err());
        assert!(write_manifest(&root, "short", &manifest).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
