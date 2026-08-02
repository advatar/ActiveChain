use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_cash_kernel::FungibleCoinCell;
use activechain_principal::{LifecycleAuthorization, PrincipalCommand, apply_lifecycle_command};
use activechain_protocol_types::{
    AssetId, Digest384, FungibleAssetDefinition, FungibleAssetLifecycle,
    FungibleAssetLifecycleAction, FungibleAssetLifecycleActionV1, FungibleAssetPolicyV1,
    FungibleControllerRotationV1, FungibleControllerStateV1, FungibleCorporateActionKind,
    FungibleCorporateActionRegistryV1, FungibleCorporateActionV1,
    FungibleExceptionalControlActionV1, FungibleExceptionalControlKind,
    FungibleExceptionalControlPolicyV1, FungibleHolderControlStateV1, FungibleIssuerApprovalV1,
    FungibleIssuerOperation, FungibleIssuerRegistrationV1, FungibleSupplyAttestationV1,
    NonFungibleIssuerApprovalV1, NonFungibleMintItemV1, NonFungibleMintManifestV1,
    NonFungibleSeriesV1, NonFungibleTokenRegistryV1, Principal, PrincipalId, RecoveryRequest,
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

fn declared(value: &str) -> Result<bool, String> {
    match value {
        "declared" => Ok(true),
        "absent" => Ok(false),
        _ => Err("control declaration must be declared or absent".into()),
    }
}

fn exceptional_control(value: &str) -> Result<FungibleExceptionalControlKind, String> {
    match value {
        "freeze" => Ok(FungibleExceptionalControlKind::Freeze),
        "unfreeze" => Ok(FungibleExceptionalControlKind::Unfreeze),
        "clawback" => Ok(FungibleExceptionalControlKind::Clawback),
        _ => Err("exceptional control must be freeze, unfreeze, or clawback".into()),
    }
}

fn usage() -> &'static str {
    "usage:\n  activechain-issuer definition <asset> <issuer> <symbol> <decimals> <supply-cap> <policy>\n  activechain-issuer policy <asset> <issuer> <authority-set> <cap> <issued>\n  activechain-issuer approval <asset> <policy> <authority-set> <approval> <operation> <amount> <supply-before> <effective-height> <expires-height>\n  activechain-issuer attestation <asset> <policy> <issuer> <supply> <finalized-height> <approval>\n  activechain-issuer registration <asset> <issuer> <authority-set> <policy> <effective-height> <expires-height>\n  activechain-issuer lifecycle <asset> <policy> <authority-set> <approval> <reason> <pause|resume|retire> <effective-height> <expires-height>\n  activechain-issuer corporate-action <asset> <issuer> <policy> <authority-set> <approval> <terms> <kind> <record-height> <effective-height> <expires-height> <amount-per-unit> <ratio-numerator> <ratio-denominator>\n  activechain-issuer dry-run-supply <policy-envelope> <approval-envelope> <finalized-height>\n  activechain-issuer dry-run-corporate-action <policy-envelope> <registry-envelope> <action-envelope> <finalized-height>\n  activechain-issuer nft-series <asset> <issuer> <max-supply> <minted> <metadata-schema>\n  activechain-issuer nft-registry <asset> [token-id ...]\n  activechain-issuer nft-manifest <asset> <issuer> (<token-id> <owner> <metadata>)+\n  activechain-issuer nft-approval <series-envelope> <authority-set> <approval> <manifest-envelope> <effective-height> <expires-height>\n  activechain-issuer dry-run-nft <series-envelope> <registry-envelope> <authority-set> <approval-envelope> <manifest-envelope> <finalized-height>\n  activechain-issuer controller-state <policy-envelope> <revision>\n  activechain-issuer controller-rotation <policy-envelope> <state-envelope> <replacement-authority> <approval> <effective-height> <expires-height>\n  activechain-issuer dry-run-controller-rotation <policy-envelope> <state-envelope> <rotation-envelope> <finalized-height>"
}

fn control_usage() -> &'static str {
    "  activechain-issuer control-policy <asset> <issuer> <authority-set> <declared|absent freeze> <declared|absent clawback>\n  activechain-issuer holder-control-state <asset> <holder>\n  activechain-issuer control-action <policy-envelope> <state-envelope> <recipient> <approval> <reason> <freeze|unfreeze|clawback> <amount> <effective-height> <expires-height>\n  activechain-issuer dry-run-control <definition-envelope> <policy-envelope> <state-envelope> <action-envelope> <finalized-height> [coin-cell-envelope]"
}

fn recovery_usage() -> &'static str {
    "  activechain-issuer recovery-initiation <principal-envelope> <policy-envelope> <state-envelope> <proposed-controller-policy> <replacement-authority> <recovery-evidence> <recovery-bond> <initiation-height> <challenge-deadline> <rotation-approval> <rotation-expires-height>"
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn envelope<T: CanonicalType>(value: &str, name: &str) -> Result<T, String> {
    if !value.len().is_multiple_of(2) {
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
        Some("dry-run-corporate-action") if args.len() == 5 => {
            let policy: FungibleAssetPolicyV1 = envelope(&args[1], "policy")?;
            let mut registry: FungibleCorporateActionRegistryV1 =
                envelope(&args[2], "corporate action registry")?;
            let action: FungibleCorporateActionV1 = envelope(&args[3], "corporate action")?;
            let height =
                args[4].parse().map_err(|_| "finalized-height must be an unsigned integer")?;
            let action_id = registry
                .admit(
                    &action,
                    policy.asset_id(),
                    policy.commitment().map_err(|_| "policy encoding failed")?,
                    policy.authority_set(),
                    height,
                )
                .map_err(|_| "corporate action dry-run rejected")?;
            Ok(format!(
                "{}:{}",
                hex_bytes(action_id.as_bytes()),
                hex_bytes(
                    &encode_envelope(&registry)
                        .map_err(|_| "corporate action registry encoding failed")?
                )
            ))
        }
        Some("nft-series") if args.len() == 6 => {
            let series = NonFungibleSeriesV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                args[3].parse().map_err(|_| "max-supply must be an unsigned integer")?,
                args[4].parse().map_err(|_| "minted must be an unsigned integer")?,
                hex_digest(&args[5])?,
            )
            .map_err(|_| "invalid NFT series values")?;
            Ok(hex_bytes(&encode_envelope(&series).map_err(|_| "NFT series encoding failed")?))
        }
        Some("nft-registry") if args.len() >= 2 => {
            let token_ids =
                args[2..].iter().map(|value| hex_digest(value)).collect::<Result<Vec<_>, _>>()?;
            let registry =
                NonFungibleTokenRegistryV1::new(AssetId::new(hex_digest(&args[1])?), token_ids)
                    .map_err(|_| "invalid NFT registry values")?;
            Ok(hex_bytes(&encode_envelope(&registry).map_err(|_| "NFT registry encoding failed")?))
        }
        Some("nft-manifest") if args.len() >= 6 && (args.len() - 3).is_multiple_of(3) => {
            let mut items = Vec::with_capacity((args.len() - 3) / 3);
            for values in args[3..].chunks_exact(3) {
                items.push(
                    NonFungibleMintItemV1::new(
                        hex_digest(&values[0])?,
                        PrincipalId::new(hex_digest(&values[1])?),
                        hex_digest(&values[2])?,
                    )
                    .map_err(|_| "invalid NFT mint item")?,
                );
            }
            let manifest = NonFungibleMintManifestV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                items,
            )
            .map_err(|_| "invalid NFT mint manifest")?;
            Ok(hex_bytes(&encode_envelope(&manifest).map_err(|_| "NFT manifest encoding failed")?))
        }
        Some("nft-approval") if args.len() == 7 => {
            let series: NonFungibleSeriesV1 = envelope(&args[1], "NFT series")?;
            let manifest: NonFungibleMintManifestV1 = envelope(&args[4], "NFT manifest")?;
            let approval = NonFungibleIssuerApprovalV1::new(
                series.asset_id(),
                series.issuer(),
                hex_digest(&args[2])?,
                series.commitment().map_err(|_| "NFT series encoding failed")?,
                hex_digest(&args[3])?,
                manifest.commitment().map_err(|_| "NFT manifest encoding failed")?,
                u64::try_from(manifest.item_count())
                    .map_err(|_| "NFT manifest count is too large")?,
                series.minted(),
                args[5].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[6].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid NFT approval values")?;
            Ok(hex_bytes(&encode_envelope(&approval).map_err(|_| "NFT approval encoding failed")?))
        }
        Some("dry-run-nft") if args.len() == 7 => {
            let series: NonFungibleSeriesV1 = envelope(&args[1], "NFT series")?;
            let registry: NonFungibleTokenRegistryV1 = envelope(&args[2], "NFT registry")?;
            let approval: NonFungibleIssuerApprovalV1 = envelope(&args[4], "NFT approval")?;
            let manifest: NonFungibleMintManifestV1 = envelope(&args[5], "NFT manifest")?;
            let height =
                args[6].parse().map_err(|_| "finalized-height must be an unsigned integer")?;
            let (next_series, next_registry, _) = registry
                .apply_approved_mint(
                    &series,
                    series.issuer(),
                    hex_digest(&args[3])?,
                    &approval,
                    &manifest,
                    height,
                )
                .map_err(|_| "issuer NFT dry-run rejected")?;
            Ok(format!(
                "{}:{}",
                hex_bytes(
                    &encode_envelope(&next_series)
                        .map_err(|_| "next NFT series encoding failed")?
                ),
                hex_bytes(
                    &encode_envelope(&next_registry)
                        .map_err(|_| "next NFT registry encoding failed")?
                )
            ))
        }
        Some("controller-state") if args.len() == 3 => {
            let policy: FungibleAssetPolicyV1 = envelope(&args[1], "policy")?;
            let revision = args[2].parse().map_err(|_| "revision must be an unsigned integer")?;
            let state = FungibleControllerStateV1::from_policy(&policy, revision)
                .map_err(|_| "invalid controller state")?;
            Ok(hex_bytes(&encode_envelope(&state).map_err(|_| "controller state encoding failed")?))
        }
        Some("controller-rotation") if args.len() == 7 => {
            let policy: FungibleAssetPolicyV1 = envelope(&args[1], "policy")?;
            let state: FungibleControllerStateV1 = envelope(&args[2], "controller state")?;
            let effective_height =
                args[5].parse().map_err(|_| "effective-height must be an unsigned integer")?;
            let rotation = FungibleControllerRotationV1::new(
                policy.asset_id(),
                policy.issuer(),
                state.commitment().map_err(|_| "controller state encoding failed")?,
                policy.authority_set(),
                hex_digest(&args[3])?,
                hex_digest(&args[4])?,
                state.revision(),
                effective_height,
                args[6].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid controller rotation")?;
            state
                .apply_rotation(&policy, &rotation, effective_height)
                .map_err(|_| "controller rotation does not bind policy state")?;
            Ok(hex_bytes(
                &encode_envelope(&rotation).map_err(|_| "controller rotation encoding failed")?,
            ))
        }
        Some("dry-run-controller-rotation") if args.len() == 5 => {
            let policy: FungibleAssetPolicyV1 = envelope(&args[1], "policy")?;
            let state: FungibleControllerStateV1 = envelope(&args[2], "controller state")?;
            let rotation: FungibleControllerRotationV1 = envelope(&args[3], "controller rotation")?;
            let height =
                args[4].parse().map_err(|_| "finalized-height must be an unsigned integer")?;
            let (next_policy, next_state) = state
                .apply_rotation(&policy, &rotation, height)
                .map_err(|_| "controller rotation dry-run rejected")?;
            Ok(format!(
                "{}:{}",
                hex_bytes(
                    &encode_envelope(&next_policy).map_err(|_| "next policy encoding failed")?
                ),
                hex_bytes(
                    &encode_envelope(&next_state)
                        .map_err(|_| "next controller state encoding failed")?
                )
            ))
        }
        Some("recovery-initiation") if args.len() == 12 => {
            let principal: Principal = envelope(&args[1], "principal")?;
            let policy: FungibleAssetPolicyV1 = envelope(&args[2], "policy")?;
            let state: FungibleControllerStateV1 = envelope(&args[3], "controller state")?;
            let proposed_controller_policy = hex_digest(&args[4])?;
            let replacement_authority = hex_digest(&args[5])?;
            let recovery_evidence = hex_digest(&args[6])?;
            let recovery_bond =
                args[7].parse().map_err(|_| "recovery-bond must be an unsigned integer")?;
            let initiation_height =
                args[8].parse().map_err(|_| "initiation-height must be an unsigned integer")?;
            let challenge_deadline =
                args[9].parse().map_err(|_| "challenge-deadline must be an unsigned integer")?;
            let rotation_expires = args[11]
                .parse()
                .map_err(|_| "rotation-expires-height must be an unsigned integer")?;
            if principal.principal_id() != policy.issuer()
                || principal.authenticator_set_root() != policy.authority_set()
                || proposed_controller_policy == Digest384::ZERO
                || recovery_evidence == Digest384::ZERO
                || recovery_bond == 0
            {
                return Err(
                    "issuer recovery context does not bind principal and asset policy".into()
                );
            }
            let authorization = LifecycleAuthorization::recovery(
                principal.principal_id(),
                principal.sequence(),
                principal.recovery_policy_hash(),
            );
            let output = apply_lifecycle_command(
                &principal,
                PrincipalCommand::InitiateRecovery {
                    expected_sequence: principal.sequence(),
                    proposed_controller_policy_hash: proposed_controller_policy,
                    proposed_authenticator_set_root: replacement_authority,
                    recovery_evidence_commitment: recovery_evidence,
                    challenge_deadline,
                    recovery_bond,
                },
                Some(&authorization),
                initiation_height,
            )
            .map_err(|_| "issuer recovery initiation rejected")?;
            let request: RecoveryRequest =
                output.recovery_request().ok_or("issuer recovery did not produce a request")?;
            let rotation = FungibleControllerRotationV1::new(
                policy.asset_id(),
                policy.issuer(),
                state.commitment().map_err(|_| "controller state encoding failed")?,
                policy.authority_set(),
                replacement_authority,
                hex_digest(&args[10])?,
                state.revision(),
                challenge_deadline,
                rotation_expires,
            )
            .map_err(|_| "invalid recovery controller rotation")?;
            state
                .apply_rotation(&policy, &rotation, challenge_deadline)
                .map_err(|_| "recovery rotation does not bind policy state")?;
            Ok(format!(
                "{}:{}:{}",
                hex_bytes(
                    &encode_envelope(&output.principal())
                        .map_err(|_| "pending principal encoding failed")?
                ),
                hex_bytes(
                    &encode_envelope(&request).map_err(|_| "recovery request encoding failed")?
                ),
                hex_bytes(
                    &encode_envelope(&rotation)
                        .map_err(|_| "controller rotation encoding failed")?
                )
            ))
        }
        Some("control-policy") if args.len() == 6 => {
            let policy = FungibleExceptionalControlPolicyV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
                hex_digest(&args[3])?,
                declared(&args[4])?,
                declared(&args[5])?,
            )
            .map_err(|_| "invalid exceptional control policy")?;
            Ok(hex_bytes(&encode_envelope(&policy).map_err(|_| "control policy encoding failed")?))
        }
        Some("holder-control-state") if args.len() == 3 => {
            let state = FungibleHolderControlStateV1::new(
                AssetId::new(hex_digest(&args[1])?),
                PrincipalId::new(hex_digest(&args[2])?),
            )
            .map_err(|_| "invalid holder control state")?;
            Ok(hex_bytes(
                &encode_envelope(&state).map_err(|_| "holder control state encoding failed")?,
            ))
        }
        Some("control-action") if args.len() == 10 => {
            let policy: FungibleExceptionalControlPolicyV1 =
                envelope(&args[1], "exceptional control policy")?;
            let state: FungibleHolderControlStateV1 = envelope(&args[2], "holder control state")?;
            if policy.asset_id() != state.asset_id() {
                return Err("control policy and holder state use different assets".into());
            }
            let action = FungibleExceptionalControlActionV1::new(
                policy.asset_id(),
                state.holder(),
                PrincipalId::new(hex_digest(&args[3])?),
                policy.commitment().map_err(|_| "control policy encoding failed")?,
                policy.authority_set(),
                hex_digest(&args[4])?,
                hex_digest(&args[5])?,
                exceptional_control(&args[6])?,
                args[7].parse().map_err(|_| "amount must be an unsigned integer")?,
                state.revision(),
                args[8].parse().map_err(|_| "effective-height must be an unsigned integer")?,
                args[9].parse().map_err(|_| "expires-height must be an unsigned integer")?,
            )
            .map_err(|_| "invalid exceptional control action")?;
            Ok(hex_bytes(&encode_envelope(&action).map_err(|_| "control action encoding failed")?))
        }
        Some("dry-run-control") if args.len() == 6 || args.len() == 7 => {
            let definition: FungibleAssetDefinition = envelope(&args[1], "asset definition")?;
            let policy: FungibleExceptionalControlPolicyV1 =
                envelope(&args[2], "exceptional control policy")?;
            let state: FungibleHolderControlStateV1 = envelope(&args[3], "holder control state")?;
            let action: FungibleExceptionalControlActionV1 =
                envelope(&args[4], "exceptional control action")?;
            let height =
                args[5].parse().map_err(|_| "finalized-height must be an unsigned integer")?;
            if action.kind() == FungibleExceptionalControlKind::Clawback {
                if args.len() != 7 {
                    return Err("clawback dry-run requires one canonical Coin Cell".into());
                }
                let cell: FungibleCoinCell = envelope(&args[6], "fungible Coin Cell")?;
                let (next_cell, next_state) = cell
                    .apply_declared_clawback(&definition, &policy, &state, &action, height)
                    .map_err(|_| "exceptional control dry-run rejected")?;
                Ok(format!(
                    "{}:{}",
                    hex_bytes(
                        &encode_envelope(&next_cell).map_err(|_| "Coin Cell encoding failed")?
                    ),
                    hex_bytes(
                        &encode_envelope(&next_state)
                            .map_err(|_| "holder control state encoding failed")?
                    )
                ))
            } else {
                if args.len() != 6 {
                    return Err("freeze or unfreeze dry-run does not accept a Coin Cell".into());
                }
                let next_state = state
                    .apply(&definition, &policy, &action, height)
                    .map_err(|_| "exceptional control dry-run rejected")?;
                Ok(hex_bytes(
                    &encode_envelope(&next_state)
                        .map_err(|_| "holder control state encoding failed")?,
                ))
            }
        }
        _ => Err(format!("{}\n{}\n{}", usage(), control_usage(), recovery_usage())),
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
    use activechain_cash_kernel::CoinCellOrigin;
    use activechain_protocol_types::{FreezeState, PrincipalKind, TransactionId};

    fn d() -> String {
        "11".repeat(48)
    }

    fn h(byte: u8) -> String {
        format!("{byte:02x}").repeat(48)
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

    #[test]
    fn corporate_action_dry_run_is_exact_once_and_policy_bound() {
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
        let action = FungibleCorporateActionV1::new(
            asset,
            issuer,
            policy.commitment().unwrap(),
            authority,
            Digest384::new([0x44; 48]),
            Digest384::new([0x55; 48]),
            FungibleCorporateActionKind::Distribution,
            10,
            20,
            30,
            5,
            1,
            1,
        )
        .unwrap();
        let empty = FungibleCorporateActionRegistryV1::default();
        let args = vec![
            "dry-run-corporate-action".into(),
            hex_bytes(&encode_envelope(&policy).unwrap()),
            hex_bytes(&encode_envelope(&empty).unwrap()),
            hex_bytes(&encode_envelope(&action).unwrap()),
            "20".into(),
        ];
        let output = run(&args).unwrap();
        let (action_id, registry_hex) = output.split_once(':').unwrap();
        assert_eq!(action_id, hex_bytes(action.action_id().unwrap().as_bytes()));
        let registry: FungibleCorporateActionRegistryV1 =
            envelope(registry_hex, "corporate action registry").unwrap();
        assert_eq!(registry.action_ids(), &[action.action_id().unwrap()]);

        let mut replay = args.clone();
        replay[2] = registry_hex.into();
        assert_eq!(run(&replay), Err("corporate action dry-run rejected".into()));
        let mut stale = args;
        stale[4] = "30".into();
        assert_eq!(run(&stale), Err("corporate action dry-run rejected".into()));
    }

    #[test]
    fn declared_holder_control_cli_builds_and_dry_runs_exact_actions() {
        let asset = h(0x21);
        let issuer = h(0x22);
        let authority = h(0x23);
        let holder = h(0x24);
        let recipient = h(0x25);
        let policy_hex = run(&[
            "control-policy".into(),
            asset.clone(),
            issuer.clone(),
            authority,
            "declared".into(),
            "declared".into(),
        ])
        .unwrap();
        let policy: FungibleExceptionalControlPolicyV1 =
            envelope(&policy_hex, "exceptional control policy").unwrap();
        let definition = FungibleAssetDefinition::new(
            AssetId::new(hex_digest(&asset).unwrap()),
            PrincipalId::new(hex_digest(&issuer).unwrap()),
            b"TEST".to_vec(),
            2,
            1_000,
            policy.commitment().unwrap(),
        )
        .unwrap();
        let definition_hex = hex_bytes(&encode_envelope(&definition).unwrap());
        let state_hex =
            run(&["holder-control-state".into(), asset.clone(), holder.clone()]).unwrap();
        let freeze_hex = run(&[
            "control-action".into(),
            policy_hex.clone(),
            state_hex.clone(),
            holder.clone(),
            h(0x26),
            h(0x27),
            "freeze".into(),
            "0".into(),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        let frozen_hex = run(&[
            "dry-run-control".into(),
            definition_hex.clone(),
            policy_hex.clone(),
            state_hex.clone(),
            freeze_hex,
            "10".into(),
        ])
        .unwrap();
        let frozen: FungibleHolderControlStateV1 =
            envelope(&frozen_hex, "holder control state").unwrap();
        assert!(frozen.frozen());
        assert_eq!(frozen.revision(), 1);

        let clawback_hex = run(&[
            "control-action".into(),
            policy_hex.clone(),
            state_hex.clone(),
            recipient.clone(),
            h(0x28),
            h(0x29),
            "clawback".into(),
            "42".into(),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        assert_eq!(
            run(&[
                "dry-run-control".into(),
                definition_hex.clone(),
                policy_hex.clone(),
                state_hex.clone(),
                clawback_hex.clone(),
                "10".into(),
            ]),
            Err("clawback dry-run requires one canonical Coin Cell".into())
        );
        let cell = FungibleCoinCell::new(
            CoinCellOrigin::new(TransactionId::new(Digest384::new([0x30; 48])), 0),
            policy.asset_id(),
            PrincipalId::new(hex_digest(&holder).unwrap()),
            42,
            7,
        )
        .unwrap();
        let output = run(&[
            "dry-run-control".into(),
            definition_hex,
            policy_hex,
            state_hex,
            clawback_hex,
            "10".into(),
            hex_bytes(&encode_envelope(&cell).unwrap()),
        ])
        .unwrap();
        let (cell_hex, state_hex) = output.split_once(':').unwrap();
        let next_cell: FungibleCoinCell = envelope(cell_hex, "fungible Coin Cell").unwrap();
        let next_state: FungibleHolderControlStateV1 =
            envelope(state_hex, "holder control state").unwrap();
        assert_eq!(next_cell.owner().digest(), &hex_digest(&recipient).unwrap());
        assert_eq!(next_cell.amount(), 42);
        assert_eq!(next_state.revision(), 1);
    }

    #[test]
    fn holder_control_cli_rejects_undeclared_and_malformed_controls() {
        assert!(
            run(&["control-policy".into(), d(), d(), d(), "maybe".into(), "absent".into(),])
                .is_err()
        );
        assert!(exceptional_control("seize").is_err());
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

    #[test]
    fn nft_cli_builds_and_dry_runs_exact_manifest() {
        let asset = h(1);
        let issuer = h(2);
        let authority = h(3);
        let series_hex = run(&[
            "nft-series".into(),
            asset.clone(),
            issuer.clone(),
            "5".into(),
            "0".into(),
            h(4),
        ])
        .unwrap();
        let registry_hex = run(&["nft-registry".into(), asset.clone()]).unwrap();
        let manifest_hex =
            run(&["nft-manifest".into(), asset, issuer, h(10), h(20), h(30), h(11), h(21), h(31)])
                .unwrap();
        let approval_hex = run(&[
            "nft-approval".into(),
            series_hex.clone(),
            authority.clone(),
            h(40),
            manifest_hex.clone(),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        let output = run(&[
            "dry-run-nft".into(),
            series_hex,
            registry_hex,
            authority,
            approval_hex,
            manifest_hex,
            "10".into(),
        ])
        .unwrap();
        let (series, registry) = output.split_once(':').unwrap();
        assert_eq!(envelope::<NonFungibleSeriesV1>(series, "series").unwrap().minted(), 2);
        assert!(envelope::<NonFungibleTokenRegistryV1>(registry, "registry").is_ok());
    }

    #[test]
    fn nft_cli_rejects_duplicate_ids_and_stale_dry_run() {
        let duplicate =
            vec!["nft-manifest".into(), h(1), h(2), h(10), h(20), h(30), h(10), h(21), h(31)];
        assert_eq!(run(&duplicate), Err("invalid NFT mint manifest".into()));

        let series = run(&["nft-series".into(), h(1), h(2), "1".into(), "0".into(), h(4)]).unwrap();
        let registry = run(&["nft-registry".into(), h(1)]).unwrap();
        let manifest = run(&["nft-manifest".into(), h(1), h(2), h(10), h(20), h(30)]).unwrap();
        let approval = run(&[
            "nft-approval".into(),
            series.clone(),
            h(3),
            h(40),
            manifest.clone(),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        assert_eq!(
            run(&["dry-run-nft".into(), series, registry, h(3), approval, manifest, "20".into(),]),
            Err("issuer NFT dry-run rejected".into())
        );
    }

    #[test]
    fn controller_rotation_cli_builds_and_dry_runs_exact_revision() {
        let (policy, _) = policy_and_approval(FungibleIssuerOperation::Mint, 1);
        let policy_hex = hex_bytes(&encode_envelope(&policy).unwrap());
        let state_hex = run(&["controller-state".into(), policy_hex.clone(), "7".into()]).unwrap();
        let rotation_hex = run(&[
            "controller-rotation".into(),
            policy_hex.clone(),
            state_hex.clone(),
            h(55),
            h(56),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        let output = run(&[
            "dry-run-controller-rotation".into(),
            policy_hex,
            state_hex,
            rotation_hex.clone(),
            "15".into(),
        ])
        .unwrap();
        let (next_policy_hex, next_state_hex) = output.split_once(':').unwrap();
        let next_policy: FungibleAssetPolicyV1 = envelope(next_policy_hex, "policy").unwrap();
        let next_state: FungibleControllerStateV1 =
            envelope(next_state_hex, "controller state").unwrap();
        assert_eq!(next_policy.authority_set(), Digest384::new([55; 48]));
        assert_eq!(next_state.revision(), 8);
        assert_eq!(
            run(&[
                "dry-run-controller-rotation".into(),
                next_policy_hex.into(),
                next_state_hex.into(),
                rotation_hex,
                "15".into(),
            ]),
            Err("controller rotation dry-run rejected".into())
        );
    }

    #[test]
    fn controller_rotation_cli_rejects_unchanged_authority_and_expiry() {
        let (policy, _) = policy_and_approval(FungibleIssuerOperation::Mint, 1);
        let policy_hex = hex_bytes(&encode_envelope(&policy).unwrap());
        let state_hex = run(&["controller-state".into(), policy_hex.clone(), "0".into()]).unwrap();
        assert_eq!(
            run(&[
                "controller-rotation".into(),
                policy_hex.clone(),
                state_hex.clone(),
                hex_bytes(policy.authority_set().as_bytes()),
                h(56),
                "10".into(),
                "20".into(),
            ]),
            Err("invalid controller rotation".into())
        );
        let rotation = run(&[
            "controller-rotation".into(),
            policy_hex.clone(),
            state_hex.clone(),
            h(55),
            h(56),
            "10".into(),
            "20".into(),
        ])
        .unwrap();
        assert_eq!(
            run(&[
                "dry-run-controller-rotation".into(),
                policy_hex,
                state_hex,
                rotation,
                "20".into(),
            ]),
            Err("controller rotation dry-run rejected".into())
        );
    }

    #[test]
    fn recovery_initiation_binds_principal_challenge_and_post_challenge_rotation() {
        let (policy, _) = policy_and_approval(FungibleIssuerOperation::Mint, 1);
        let principal = Principal::new(
            policy.issuer(),
            PrincipalKind::Organization,
            Digest384::new([0x44; 48]),
            Digest384::new([0x45; 48]),
            policy.authority_set(),
            7,
            FreezeState::Active,
            Digest384::new([0x46; 48]),
            100,
            1,
            5,
        )
        .unwrap();
        let state = FungibleControllerStateV1::from_policy(&policy, 3).unwrap();
        let principal_hex = hex_bytes(&encode_envelope(&principal).unwrap());
        let policy_hex = hex_bytes(&encode_envelope(&policy).unwrap());
        let state_hex = hex_bytes(&encode_envelope(&state).unwrap());
        let output = run(&[
            "recovery-initiation".into(),
            principal_hex.clone(),
            policy_hex.clone(),
            state_hex.clone(),
            h(50),
            h(55),
            h(52),
            "100".into(),
            "10".into(),
            "20".into(),
            h(53),
            "30".into(),
        ])
        .unwrap();
        let parts = output.split(':').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let pending: Principal = envelope(parts[0], "principal").unwrap();
        let request: RecoveryRequest = envelope(parts[1], "recovery request").unwrap();
        let rotation: FungibleControllerRotationV1 =
            envelope(parts[2], "controller rotation").unwrap();
        assert_eq!(pending.principal_id(), policy.issuer());
        assert_eq!(pending.sequence(), 8);
        assert_eq!(pending.freeze_state(), FreezeState::RecoveryPending);
        assert_eq!(request.expected_sequence(), 7);
        assert_eq!(request.proposed_controller_policy_hash(), Digest384::new([50; 48]));
        assert_eq!(request.proposed_authenticator_set_root(), Digest384::new([55; 48]));
        assert_eq!(request.challenge_deadline(), 20);
        assert_eq!(request.recovery_bond(), 100);
        assert_eq!(rotation.replacement_authority_set(), Digest384::new([55; 48]));
        assert_eq!(rotation.effective_height(), 20);
        assert_eq!(rotation.expires_height(), 30);
        assert!(state.apply_rotation(&policy, &rotation, 19).is_err());
        assert!(state.apply_rotation(&policy, &rotation, 20).is_ok());

        assert_eq!(
            run(&[
                "recovery-initiation".into(),
                principal_hex,
                policy_hex,
                state_hex,
                h(50),
                h(55),
                h(52),
                "100".into(),
                "20".into(),
                "20".into(),
                h(53),
                "30".into(),
            ]),
            Err("issuer recovery initiation rejected".into())
        );
    }

    #[test]
    fn recovery_initiation_rejects_wrong_issuer_authority_and_empty_evidence() {
        let (policy, _) = policy_and_approval(FungibleIssuerOperation::Mint, 1);
        let state = FungibleControllerStateV1::from_policy(&policy, 0).unwrap();
        let wrong = Principal::new(
            PrincipalId::new(Digest384::new([0x99; 48])),
            PrincipalKind::Organization,
            Digest384::new([0x44; 48]),
            Digest384::new([0x45; 48]),
            policy.authority_set(),
            0,
            FreezeState::Active,
            Digest384::new([0x46; 48]),
            100,
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            run(&[
                "recovery-initiation".into(),
                hex_bytes(&encode_envelope(&wrong).unwrap()),
                hex_bytes(&encode_envelope(&policy).unwrap()),
                hex_bytes(&encode_envelope(&state).unwrap()),
                h(50),
                h(51),
                "00".repeat(48),
                "100".into(),
                "10".into(),
                "20".into(),
                h(53),
                "30".into(),
            ]),
            Err("issuer recovery context does not bind principal and asset policy".into())
        );
    }
}
