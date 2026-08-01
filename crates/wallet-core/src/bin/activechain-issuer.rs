use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_protocol_types::{
    AssetId, Digest384, FungibleAssetDefinition, FungibleAssetLifecycle,
    FungibleAssetLifecycleAction, FungibleAssetLifecycleActionV1, FungibleAssetPolicyV1,
    FungibleCorporateActionKind, FungibleCorporateActionV1, FungibleIssuerApprovalV1,
    FungibleIssuerOperation, FungibleIssuerRegistrationV1, FungibleSupplyAttestationV1,
    PrincipalId,
};

fn hex_digest(value: &str) -> Result<Digest384, String> {
    if value.len() != 96 {
        return Err("digest must contain exactly 96 lowercase hex characters".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Digest384::new(bytes))
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("digest contains non-lowercase-hex input".into()),
    }
}

fn operation(value: &str) -> Result<FungibleIssuerOperation, String> {
    match value {
        "mint" => Ok(FungibleIssuerOperation::Mint),
        "burn" => Ok(FungibleIssuerOperation::Burn),
        "redemption" => Ok(FungibleIssuerOperation::Redemption),
        _ => Err("operation must be mint, burn, or redemption".into()),
    }
}

fn lifecycle_action(value: &str) -> Result<FungibleAssetLifecycleAction, String> {
    match value {
        "pause" => Ok(FungibleAssetLifecycleAction::Pause),
        "resume" => Ok(FungibleAssetLifecycleAction::Resume),
        "retire" => Ok(FungibleAssetLifecycleAction::Retire),
        _ => Err("lifecycle action must be pause, resume, or retire".into()),
    }
}

fn corporate_action(value: &str) -> Result<FungibleCorporateActionKind, String> {
    match value {
        "distribution" => Ok(FungibleCorporateActionKind::Distribution),
        "split" => Ok(FungibleCorporateActionKind::Split),
        "consolidation" => Ok(FungibleCorporateActionKind::Consolidation),
        "coupon" => Ok(FungibleCorporateActionKind::Coupon),
        "maturity" => Ok(FungibleCorporateActionKind::Maturity),
        "record-date-vote" => Ok(FungibleCorporateActionKind::RecordDateVote),
        "redemption-offer" => Ok(FungibleCorporateActionKind::RedemptionOffer),
        _ => Err("corporate action must be distribution, split, consolidation, coupon, maturity, record-date-vote, or redemption-offer".into()),
    }
}

fn usage() -> &'static str {
    "usage:\n  activechain-issuer definition <asset> <issuer> <symbol> <decimals> <supply-cap> <policy>\n  activechain-issuer policy <asset> <issuer> <authority-set> <cap> <issued>\n  activechain-issuer approval <asset> <policy> <authority-set> <approval> <operation> <amount> <supply-before> <effective-height> <expires-height>\n  activechain-issuer attestation <asset> <policy> <issuer> <supply> <finalized-height> <approval>\n  activechain-issuer registration <asset> <issuer> <authority-set> <policy> <effective-height> <expires-height>\n  activechain-issuer lifecycle <asset> <policy> <authority-set> <approval> <reason> <pause|resume|retire> <effective-height> <expires-height>\n  activechain-issuer corporate-action <asset> <issuer> <policy> <authority-set> <approval> <terms> <kind> <record-height> <effective-height> <expires-height> <amount-per-unit> <ratio-numerator> <ratio-denominator>\n  activechain-issuer dry-run-supply <policy-envelope> <approval-envelope> <finalized-height>"
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn envelope<T: CanonicalType>(value: &str, name: &str) -> Result<T, String> {
    if value.len() % 2 != 0 {
        return Err(format!("{name} envelope must contain an even number of hex characters"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?);
    }
    decode_envelope(&bytes).map_err(|_| format!("invalid canonical {name} envelope"))
}

fn run(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("definition") if args.len() == 7 => {
            let definition = FungibleAssetDefinition::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                args[3].as_bytes().to_vec(),
                args[4].parse().map_err(|_| "decimals must be an unsigned integer")?,
                args[5].parse().map_err(|_| "supply-cap must be an unsigned integer")?,
                hex_digest(&args[6])?,
            )
            .map_err(|_| "invalid asset definition values")?;
            Ok(hex_bytes(
                &encode_envelope(&definition).map_err(|_| "asset definition encoding failed")?,
            ))
        }
        Some("policy") if args.len() == 6 => {
            let asset = AssetId::new(hex_digest(&args[1])?);
            let issuer = PrincipalId::new(hex_digest(&args[2])?);
            let policy = FungibleAssetPolicyV1::new(
                asset,
                issuer,
                Digest384::ZERO,
                Digest384::ZERO,
                Digest384::ZERO,
                hex_digest(&args[3])?,
                args[4].parse().map_err(|_| "cap must be an unsigned integer")?,
                args[5].parse().map_err(|_| "issued must be an unsigned integer")?,
                FungibleAssetLifecycle::Registered,
            )
            .map_err(|_| "invalid policy values")?;
            Ok(hex_bytes(policy.commitment().map_err(|_| "policy encoding failed")?.as_bytes()))
        }
        Some("approval") if args.len() == 10 => {
            let approval = FungibleIssuerApprovalV1::new(
                AssetId::new(hex_digest(&args[1])?),
                hex_digest(&args[2])?,
                hex_digest(&args[3])?,
                hex_digest(&args[4])?,
                operation(&args[5])?,
                args[6].parse().map_err(|_| "amount must be an unsigned integer")?,
                args[7].parse().map_err(|_| "supply-before must be an unsigned integer")?,
                args[8].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[9].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid approval values")?;
            let bytes = encode_envelope(&approval).map_err(|_| "approval encoding failed")?;
            Ok(hex_bytes(&bytes))
        }
        Some("attestation") if args.len() == 7 => {
            let attestation = FungibleSupplyAttestationV1::new(
                AssetId::new(hex_digest(&args[1])?),
                hex_digest(&args[2])?,
                PrincipalId::new(hex_digest(&args[3])?),
                args[4].parse().map_err(|_| "supply must be an unsigned integer")?,
                args[5].parse().map_err(|_| "finalized-height must be an unsigned integer")?,
                hex_digest(&args[6])?,
            )
            .map_err(|_| "invalid attestation values")?;
            Ok(hex_bytes(
                &encode_envelope(&attestation).map_err(|_| "attestation encoding failed")?,
            ))
        }
        Some("registration") if args.len() == 7 => {
            let registration = FungibleIssuerRegistrationV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                hex_digest(&args[3])?,
                hex_digest(&args[4])?,
                args[5].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[6].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid registration values")?;
            Ok(hex_bytes(
                &encode_envelope(&registration).map_err(|_| "registration encoding failed")?,
            ))
        }
        Some("lifecycle") if args.len() == 9 => {
            let action = FungibleAssetLifecycleActionV1::new(
                AssetId::new(hex_digest(&args[1])?),
                hex_digest(&args[2])?,
                hex_digest(&args[3])?,
                hex_digest(&args[4])?,
                hex_digest(&args[5])?,
                lifecycle_action(&args[6])?,
                args[7].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[8].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid lifecycle action values")?;
            Ok(hex_bytes(
                &encode_envelope(&action).map_err(|_| "lifecycle action encoding failed")?,
            ))
        }
        Some("corporate-action") if args.len() == 14 => {
            let action = FungibleCorporateActionV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                hex_digest(&args[3])?,
                hex_digest(&args[4])?,
                hex_digest(&args[5])?,
                hex_digest(&args[6])?,
                corporate_action(&args[7])?,
                args[8].parse().map_err(|_| "record-height must be an unsigned integer")?,
                args[9].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[10].parse().map_err(|_| "expires-height must be an unsigned integer")?,
                args[11].parse().map_err(|_| "amount-per-unit must be an unsigned integer")?,
                args[12].parse().map_err(|_| "ratio-numerator must be an unsigned integer")?,
                args[13].parse().map_err(|_| "ratio-denominator must be an unsigned integer")?,
            )
            .map_err(|_| "invalid corporate action values")?;
            Ok(hex_bytes(
                &encode_envelope(&action).map_err(|_| "corporate action encoding failed")?,
            ))
        }
        Some("dry-run-supply") if args.len() == 4 => {
            let policy: FungibleAssetPolicyV1 = envelope(&args[1], "policy")?;
            let approval: FungibleIssuerApprovalV1 = envelope(&args[2], "approval")?;
            let height =
                args[3].parse().map_err(|_| "finalized-height must be an unsigned integer")?;
            let next = match approval.operation() {
                FungibleIssuerOperation::Mint => {
                    policy.apply_approved_mint(policy.issuer(), &approval, height)
                }
                operation @ (FungibleIssuerOperation::Burn
                | FungibleIssuerOperation::Redemption) => {
                    policy.apply_approved_burn(&approval, operation, height)
                }
            }
            .map_err(|_| "issuer supply dry-run rejected")?;
            Ok(hex_bytes(&encode_envelope(&next).map_err(|_| "next policy encoding failed")?))
        }
        _ => Err(usage().into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> String {
        "11".repeat(48)
    }

    #[test]
    fn policy_command_is_deterministic_and_rejects_bad_hex() {
        let args = vec!["policy".into(), d(), d(), d(), "100".into(), "10".into()];
        assert_eq!(run(&args).unwrap(), run(&args).unwrap());
        let mut malformed = args;
        malformed[1] = "zz".into();
        assert!(run(&malformed).is_err());
    }

    #[test]
    fn definition_command_is_deterministic_and_rejects_untrusted_symbol_shape() {
        let args =
            vec!["definition".into(), d(), d(), "TEUR".into(), "2".into(), "1000000".into(), d()];
        assert_eq!(run(&args).unwrap(), run(&args).unwrap());
        let mut malformed = args;
        malformed[3] = "tEUR".into();
        assert!(run(&malformed).is_err());
    }

    #[test]
    fn approval_command_rejects_expired_window() {
        let args = vec![
            "approval".into(),
            d(),
            d(),
            d(),
            d(),
            "mint".into(),
            "1".into(),
            "0".into(),
            "10".into(),
            "10".into(),
        ];
        assert!(run(&args).is_err());
    }

    #[test]
    fn attestation_command_is_deterministic_and_strict() {
        let args = vec!["attestation".into(), d(), d(), d(), "10".into(), "7".into(), d()];
        assert_eq!(run(&args).unwrap(), run(&args).unwrap());
        let mut malformed = args;
        malformed[6] = "GG".into();
        assert!(run(&malformed).is_err());
    }

    #[test]
    fn registration_command_rejects_inverted_window() {
        let args = vec!["registration".into(), d(), d(), d(), d(), "10".into(), "10".into()];
        assert!(run(&args).is_err());
    }

    #[test]
    fn lifecycle_command_binds_action_and_rejects_unknown_or_expired_values() {
        let args = vec![
            "lifecycle".into(),
            d(),
            d(),
            d(),
            d(),
            d(),
            "pause".into(),
            "10".into(),
            "20".into(),
        ];
        assert_eq!(run(&args).unwrap(), run(&args).unwrap());
        let mut unknown = args.clone();
        unknown[6] = "freeze".into();
        assert!(run(&unknown).is_err());
        let mut expired = args;
        expired[8] = "10".into();
        assert!(run(&expired).is_err());
    }

    #[test]
    fn corporate_action_command_is_deterministic_and_kind_strict() {
        let args = vec![
            "corporate-action".into(),
            d(),
            d(),
            d(),
            d(),
            d(),
            d(),
            "split".into(),
            "10".into(),
            "20".into(),
            "30".into(),
            "0".into(),
            "2".into(),
            "1".into(),
        ];
        assert_eq!(run(&args).unwrap(), run(&args).unwrap());
        let mut wrong_kind = args.clone();
        wrong_kind[7] = "dividend-ish".into();
        assert!(run(&wrong_kind).is_err());
        let mut wrong_economics = args;
        wrong_economics[11] = "1".into();
        assert!(run(&wrong_economics).is_err());
    }

    fn policy_and_approval(
        operation: FungibleIssuerOperation,
        amount: u128,
    ) -> (FungibleAssetPolicyV1, FungibleIssuerApprovalV1) {
        let asset = AssetId::new(hex_digest(&d()).unwrap());
        let issuer = PrincipalId::new(Digest384::new([0x22; 48]));
        let authority = Digest384::new([0x33; 48]);
        let policy = FungibleAssetPolicyV1::new(
            asset,
            issuer,
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            authority,
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            asset,
            policy.commitment().unwrap(),
            authority,
            Digest384::new([0x44; 48]),
            operation,
            amount,
            100,
            10,
            20,
        )
        .unwrap();
        (policy, approval)
    }

    #[test]
    fn dry_run_supply_applies_exact_approval_without_mutating_input() {
        let (policy, approval) = policy_and_approval(FungibleIssuerOperation::Mint, 25);
        let policy_hex = hex_bytes(&encode_envelope(&policy).unwrap());
        let args = vec![
            "dry-run-supply".into(),
            policy_hex.clone(),
            hex_bytes(&encode_envelope(&approval).unwrap()),
            "15".into(),
        ];
        let next: FungibleAssetPolicyV1 = envelope(&run(&args).unwrap(), "policy").unwrap();
        assert_eq!(next.supply_issued(), 125);
        assert_eq!(policy.supply_issued(), 100);
        assert_eq!(args[1], policy_hex);
    }

    #[test]
    fn dry_run_supply_rejects_stale_changed_and_malformed_inputs() {
        let (policy, approval) = policy_and_approval(FungibleIssuerOperation::Redemption, 25);
        let valid = vec![
            "dry-run-supply".into(),
            hex_bytes(&encode_envelope(&policy).unwrap()),
            hex_bytes(&encode_envelope(&approval).unwrap()),
            "15".into(),
        ];
        let next: FungibleAssetPolicyV1 = envelope(&run(&valid).unwrap(), "policy").unwrap();
        assert_eq!(next.supply_issued(), 75);

        let mut stale = valid.clone();
        stale[3] = "20".into();
        assert_eq!(run(&stale), Err("issuer supply dry-run rejected".into()));

        let changed_policy = FungibleAssetPolicyV1::new(
            policy.asset_id(),
            policy.issuer(),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            policy.authority_set(),
            policy.supply_cap(),
            99,
            policy.lifecycle(),
        )
        .unwrap();
        let mut changed = valid.clone();
        changed[1] = hex_bytes(&encode_envelope(&changed_policy).unwrap());
        assert_eq!(run(&changed), Err("issuer supply dry-run rejected".into()));

        let mut malformed = valid;
        malformed[2] = "abc".into();
        assert!(run(&malformed).unwrap_err().contains("even number"));
    }
}
