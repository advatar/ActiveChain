//! Canonical native-cash genesis ledger provisioner.

use activechain_canonical_codec::encode_envelope;
use activechain_cash_kernel::{
    CashLedger, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{env, fs, io::Write, path::Path};

fn parse_digest(value: &str, name: &str) -> Result<Digest384, String> {
    if value.len() != 96 {
        return Err(format!("{name} must contain exactly 96 lowercase hex characters"));
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(format!("{name} contains non-lowercase-hex input")),
        };
        bytes[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    let digest = Digest384::new(bytes);
    if digest == Digest384::ZERO {
        return Err(format!("{name} must not be zero"));
    }
    Ok(digest)
}

fn policy_commitment(chain: ChainId, label: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-KANALEN-CASH-GENESIS-POLICY-V1");
    hasher.update(chain.digest().as_bytes());
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

fn ledger(
    chain: ChainId,
    owner: PrincipalId,
    genesis_supply: u128,
    security_reserve: u128,
) -> Result<CashLedger, String> {
    let allocation = genesis_supply
        .checked_sub(security_reserve)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| "security reserve must be smaller than genesis supply".to_owned())?;
    let definition = NativeAssetDefinition::new(
        chain,
        b"ACT".to_vec(),
        18,
        genesis_supply,
        150,
        policy_commitment(chain, b"issuance"),
        policy_commitment(chain, b"burn"),
        policy_commitment(chain, b"rewards"),
    )
    .map_err(|error| format!("invalid native asset definition: {error:?}"))?;
    let fee_reserve = allocation / 2;
    let spendable = allocation - fee_reserve;
    let allocations = vec![
        GenesisAllocation::new(owner, fee_reserve, 0)
            .map_err(|error| format!("invalid treasury fee reserve: {error:?}"))?,
        GenesisAllocation::new(owner, spendable, 0)
            .map_err(|error| format!("invalid treasury spendable allocation: {error:?}"))?,
    ];
    let economy = GenesisEconomy::new(definition, allocations, security_reserve)
        .map_err(|error| format!("invalid genesis economy: {error:?}"))?;
    CashLedger::from_genesis(&economy)
        .map_err(|error| format!("cash genesis transition failed: {error:?}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let output = args.next().ok_or(
        "usage: cash-genesis-tool <output> <chain-id-hex> <treasury-principal-hex> <genesis-supply> <security-reserve>",
    )?;
    let chain = ChainId::new(parse_digest(&args.next().ok_or("missing chain ID")?, "chain ID")?);
    let owner_argument = args.next().ok_or("missing treasury principal")?;
    let genesis_supply: u128 = args.next().ok_or("missing genesis supply")?.parse()?;
    let security_reserve: u128 = args.next().ok_or("missing security reserve")?.parse()?;
    let operator_seed = args
        .next()
        .map(|argument| {
            argument
                .strip_prefix("--operator-seed=")
                .map(std::path::PathBuf::from)
                .ok_or("unexpected trailing argument")
        })
        .transpose()?;
    if args.next().is_some() {
        return Err("unexpected trailing argument".into());
    }
    let signing_key = operator_seed.as_deref().map(load_operator_key).transpose()?;
    let owner = if owner_argument == "operator" {
        let key = signing_key.as_ref().ok_or("operator owner requires --operator-seed")?;
        operator_principal(key.verifying_key().encode().as_slice())
    } else {
        PrincipalId::new(parse_digest(&owner_argument, "treasury principal")?)
    };
    let ledger = ledger(chain, owner, genesis_supply, security_reserve)?;
    let mut ingress = activechain_wallet_core::TransactionIngress::from_ledger(ledger.clone())
        .map_err(|_| "cash ingress construction failed")?;
    if let Some(key) = signing_key {
        ingress
            .bootstrap_genesis_authorization_key(owner, key.verifying_key().encode().into())
            .map_err(|_| "cash genesis authorization bootstrap failed")?;
    }
    let bytes = encode_envelope(&ingress).map_err(|_| "cash ingress encoding failed")?;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(Path::new(&output))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!("cash_cell_count={}", ledger.cells().as_slice().len());
    println!("cash_genesis_supply={genesis_supply}");
    println!("cash_security_reserve={security_reserve}");
    println!("cash_genesis_owner={}", hex(owner.into_digest().as_bytes()));
    Ok(())
}

fn load_operator_key(path: &Path) -> Result<SigningKey<MlDsa44>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("operator seed must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("operator seed must not be group/world accessible".into());
        }
    }
    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err("operator seed must contain exactly 32 bytes".into());
    }
    let mut seed = [0; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::<MlDsa44>::from_seed(&Seed::from(seed)))
}

fn operator_principal(public_key: &[u8]) -> PrincipalId {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-KANALEN-FAUCET-OPERATOR-V1");
    hasher.update(public_key);
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    PrincipalId::new(Digest384::new(output))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    #[test]
    fn cash_genesis_is_canonical_chain_bound_and_conserving() {
        let chain = ChainId::new(Digest384::new([1; 48]));
        let owner = PrincipalId::new(Digest384::new([2; 48]));
        let value = ledger(chain, owner, 1_000, 100).unwrap();
        value.verify_invariants().unwrap();
        assert_eq!(value.definition().chain_id(), chain);
        assert_eq!(value.supply().genesis_supply(), 1_000);
        assert_eq!(value.supply().security_reserve_balance(), 100);
        assert_eq!(value.cells().as_slice().len(), 2);
        assert_eq!(value.cells().as_slice()[0].cell().owner(), owner);
        assert!(value.cells().as_slice().iter().all(|cell| cell.cell().owner() == owner));
        assert_eq!(
            value.cells().as_slice().iter().map(|cell| cell.cell().amount()).sum::<u128>(),
            900
        );
        let encoded = encode_envelope(&value).unwrap();
        assert_eq!(decode_envelope::<CashLedger>(&encoded), Ok(value.clone()));
        let ingress = activechain_wallet_core::TransactionIngress::from_ledger(value).unwrap();
        let encoded = encode_envelope(&ingress).unwrap();
        assert_eq!(
            decode_envelope::<activechain_wallet_core::TransactionIngress>(&encoded)
                .unwrap()
                .ledger()
                .definition()
                .chain_id(),
            chain
        );
    }

    #[test]
    fn cash_genesis_rejects_zero_malformed_and_exhaustive_reserves() {
        assert!(parse_digest(&"00".repeat(48), "value").is_err());
        assert!(parse_digest(&"AA".repeat(48), "value").is_err());
        assert!(parse_digest("01", "value").is_err());
        assert!(
            ledger(
                ChainId::new(Digest384::new([1; 48])),
                PrincipalId::new(Digest384::new([2; 48])),
                100,
                100,
            )
            .is_err()
        );
    }
}
