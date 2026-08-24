//! Applies one finalized DCN evidence settlement to the deterministic accounting ledger.
//!
//! The command independently verifies the native Actum finality envelope before mutating the
//! durable accounting state. It emits canonical settlement/reputation envelopes and the digest
//! that must be anchored under `dcn.generation-attestation.settlement-state.v1`.

use activechain_application_primitives::{
    AccountBalanceV1, AnchorFinalizedEvidenceV1, DurableEvidenceSettlementLedger,
    EvidenceFinalityReferenceV1, EvidenceSettlementLedger, SettlementAssuranceClassV1,
    SettlementInstructionV1,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, TransactionId};
use activechain_verifier_api::verify_anchor_finalized_evidence;
use serde_json::json;
use std::{env, fs, path::Path, process::ExitCode, time::Instant};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 10 => initialize(&args[1..]),
        Some("settle") if args.len() == 22 => settle(&args[1..]),
        Some("query-evidence") if args.len() == 3 => query_evidence(&args[1..]),
        Some("query-settlement") if args.len() == 3 => query_settlement(&args[1..]),
        Some("query-account") if args.len() == 3 => query_account(&args[1..]),
        Some("query-reputation") if args.len() == 3 => query_reputation(&args[1..]),
        _ => Err(usage().to_owned()),
    }
}

fn initialize(args: &[String]) -> Result<String, String> {
    let path = Path::new(&args[0]);
    let chain = ChainId::new(parse_digest384(&args[1])?);
    let unit = parse_digest384(&args[2])?;
    let authority = PrincipalId::new(parse_digest384(&args[3])?);
    let payer = PrincipalId::new(parse_digest384(&args[4])?);
    let payer_balance = parse_u128(&args[5], "payer balance")?;
    let executor = PrincipalId::new(parse_digest384(&args[6])?);
    let executor_balance = parse_u128(&args[7], "executor balance")?;
    let expected_total = parse_u128(&args[8], "expected total")?;
    let ledger = EvidenceSettlementLedger::new(
        chain,
        unit,
        authority,
        vec![
            AccountBalanceV1::new(payer, unit, payer_balance).map_err(debug_error)?,
            AccountBalanceV1::new(executor, unit, executor_balance).map_err(debug_error)?,
        ],
    )
    .map_err(debug_error)?;
    if ledger.total_balance().map_err(debug_error)? != expected_total {
        return Err("initial accounting total does not match expected conservation total".into());
    }
    let state_commitment = ledger.state_commitment().map_err(debug_error)?;
    DurableEvidenceSettlementLedger::create(path, ledger).map_err(debug_error)?;
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.init-result.v1",
        "status": "initialized",
        "stateCommitment": hex(state_commitment.as_bytes()),
        "total": expected_total.to_string(),
    })
    .to_string())
}

fn settle(args: &[String]) -> Result<String, String> {
    let started = Instant::now();
    let ledger_path = Path::new(&args[0]);
    let evidence_bytes =
        fs::read(&args[1]).map_err(|error| format!("could not read finality evidence: {error}"))?;
    let anchor_commitment = parse_sha256(&args[2])?;
    let statement_reference = parse_digest384(&args[3])?;
    let transaction = TransactionId::new(parse_digest384(&args[4])?);
    let finalized_height = parse_u64(&args[5], "finalized height")?;
    let finalized_block = parse_digest384(&args[6])?;
    let chain = ChainId::new(parse_digest384(&args[7])?);
    let genesis = parse_digest384(&args[8])?;
    let authority = PrincipalId::new(parse_digest384(&args[9])?);
    let payer = PrincipalId::new(parse_digest384(&args[10])?);
    let executor = PrincipalId::new(parse_digest384(&args[11])?);
    let agreement = parse_digest384(&args[12])?;
    let capability = parse_digest384(&args[13])?;
    let authorization_scope = parse_sha256(&args[14])?;
    let amount = parse_u128(&args[15], "amount")?;
    let unit = parse_digest384(&args[16])?;
    let logical_time = parse_u64(&args[17], "logical time")?;
    let record_path = Path::new(&args[18]);
    let reputation_path = Path::new(&args[19]);
    let state_anchor_path = Path::new(&args[20]);

    let finality = EvidenceFinalityReferenceV1::new(
        chain,
        genesis,
        anchor_commitment,
        statement_reference,
        transaction,
        finalized_height,
        finalized_block,
        1,
        1,
    )
    .map_err(debug_error)?;
    let instruction = SettlementInstructionV1::new(
        finality,
        authority,
        payer,
        executor,
        agreement,
        capability,
        authorization_scope,
        SettlementAssuranceClassV1::Cryptographic,
        amount,
        unit,
        1,
        1,
        logical_time,
    )
    .map_err(debug_error)?;
    let expected_statement = instruction.finality().expected_statement().map_err(debug_error)?;
    let statement_envelope =
        encode_envelope(&expected_statement).map_err(|_| "could not encode evidence statement")?;
    let verified = verify_anchor_finalized_evidence(
        &evidence_bytes,
        &statement_envelope,
        chain,
        genesis,
        1,
        1,
    )
    .map_err(|error| format!("native evidence finality revalidation failed: {error:?}"))?;
    if verified.transaction() != transaction
        || verified.finalized_height() != finalized_height
        || verified.finalized_block() != finalized_block
    {
        return Err("native evidence finality identity was substituted".into());
    }
    let evidence: AnchorFinalizedEvidenceV1 =
        decode_envelope(&evidence_bytes).map_err(|_| "native evidence envelope is malformed")?;
    let finality_verified_ms = started.elapsed().as_millis();
    let mut ledger = DurableEvidenceSettlementLedger::open(ledger_path).map_err(debug_error)?;
    let settlement_started = Instant::now();
    let outcome = ledger
        .settle(instruction, &evidence, authority, |_, _, tx, height, block| {
            tx == verified.transaction()
                && height == verified.finalized_height()
                && block == verified.finalized_block()
        })
        .map_err(debug_error)?;
    let settlement_ms = settlement_started.elapsed().as_millis();
    write_new_or_exact(
        record_path,
        &encode_envelope(&outcome.record).map_err(|_| "could not encode settlement record")?,
    )?;
    write_new_or_exact(
        reputation_path,
        &encode_envelope(&outcome.reputation_event)
            .map_err(|_| "could not encode reputation event")?,
    )?;
    let state_anchor = ledger.ledger().settlement_anchor_statement().map_err(debug_error)?;
    let state_anchor_envelope =
        encode_envelope(&state_anchor).map_err(|_| "could not encode state anchor")?;
    write_new_or_exact(state_anchor_path, &state_anchor_envelope)?;
    let payer_balance = ledger.ledger().balance(payer).ok_or("payer account disappeared")?;
    let executor_balance =
        ledger.ledger().balance(executor).ok_or("executor account disappeared")?;
    let state_commitment = ledger.ledger().state_commitment().map_err(debug_error)?;
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.result.v1",
        "status": "settled",
        "duplicate": outcome.duplicate,
        "settlementId": hex(outcome.record.settlement_id().as_bytes()),
        "idempotencyId": hex(outcome.record.idempotency_id().as_bytes()),
        "evidenceAnchorCommitment": format!("sha256:{}", hex(&anchor_commitment)),
        "evidenceTransaction": hex(transaction.digest().as_bytes()),
        "finalizedHeight": finalized_height,
        "finalizedBlock": hex(finalized_block.as_bytes()),
        "amount": amount.to_string(),
        "unit": hex(unit.as_bytes()),
        "payer": hex(payer.digest().as_bytes()),
        "payerBalance": payer_balance.balance().to_string(),
        "executor": hex(executor.digest().as_bytes()),
        "executorBalance": executor_balance.balance().to_string(),
        "accountingCommitment": hex(outcome.record.resulting_accounting_commitment().as_bytes()),
        "stateCommitment": hex(state_commitment.as_bytes()),
        "stateAnchorDigest": hex(state_anchor.digest()),
        "stateAnchorReference": hex(state_anchor.submission_reference().map_err(debug_error)?.as_bytes()),
        "reputationEventId": hex(outcome.reputation_event.event_id().as_bytes()),
        "finalityRevalidationMs": finality_verified_ms,
        "settlementExecutionMs": settlement_ms,
    })
    .to_string())
}

fn query_evidence(args: &[String]) -> Result<String, String> {
    let ledger = DurableEvidenceSettlementLedger::open(&args[0]).map_err(debug_error)?;
    let commitment = parse_sha256(&args[1])?;
    let settlements = ledger
        .ledger()
        .settlements_for_evidence(&commitment)
        .into_iter()
        .map(|record| hex(record.settlement_id().as_bytes()))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.query.v1",
        "query": "evidence",
        "evidenceAnchorCommitment": format!("sha256:{}", hex(&commitment)),
        "settlementIds": settlements,
    })
    .to_string())
}

fn query_settlement(args: &[String]) -> Result<String, String> {
    let ledger = DurableEvidenceSettlementLedger::open(&args[0]).map_err(debug_error)?;
    let settlement_id = parse_digest384(&args[1])?;
    let record = ledger.ledger().settlement(settlement_id).ok_or("settlement was not found")?;
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.query.v1",
        "query": "settlement",
        "settlementId": hex(record.settlement_id().as_bytes()),
        "evidenceAnchorCommitment": format!(
            "sha256:{}",
            hex(record.instruction().finality().evidence_anchor_commitment())
        ),
        "payer": hex(record.instruction().payer().digest().as_bytes()),
        "executor": hex(record.instruction().executor().digest().as_bytes()),
        "amount": record.instruction().amount().to_string(),
        "sequence": record.sequence(),
    })
    .to_string())
}

fn query_account(args: &[String]) -> Result<String, String> {
    let ledger = DurableEvidenceSettlementLedger::open(&args[0]).map_err(debug_error)?;
    let owner = PrincipalId::new(parse_digest384(&args[1])?);
    let balance = ledger.ledger().balance(owner).ok_or("account was not found")?;
    let settlements = ledger
        .ledger()
        .settlements_for_account(owner)
        .into_iter()
        .map(|record| hex(record.settlement_id().as_bytes()))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.query.v1",
        "query": "account",
        "owner": hex(owner.digest().as_bytes()),
        "balance": balance.balance().to_string(),
        "unit": hex(balance.unit().as_bytes()),
        "settlementIds": settlements,
    })
    .to_string())
}

fn query_reputation(args: &[String]) -> Result<String, String> {
    let ledger = DurableEvidenceSettlementLedger::open(&args[0]).map_err(debug_error)?;
    let executor = PrincipalId::new(parse_digest384(&args[1])?);
    let events = ledger
        .ledger()
        .reputation_events_for_executor(executor)
        .into_iter()
        .map(|event| {
            json!({
                "eventId": hex(event.event_id().as_bytes()),
                "settlementId": hex(event.settlement_id().as_bytes()),
                "capability": hex(event.capability().as_bytes()),
                "policyVersion": event.policy_version(),
                "settlementCompleted": event.settlement_completed(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "actum.dcn-evidence-settlement.query.v1",
        "query": "reputation",
        "executor": hex(executor.digest().as_bytes()),
        "events": events,
    })
    .to_string())
}

fn write_new_or_exact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) => Err(format!("existing artifact differs: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::write(path, bytes)
            .map_err(|error| format!("could not write {}: {error}", path.display())),
        Err(error) => Err(format!("could not inspect {}: {error}", path.display())),
    }
}

fn parse_digest384(value: &str) -> Result<Digest384, String> {
    if value.len() != 96 || !value.bytes().all(is_lower_hex) {
        return Err("expected 96 lowercase hexadecimal characters".into());
    }
    let mut bytes = [0_u8; 48];
    decode_hex_into(value, &mut bytes)?;
    let value = Digest384::new(bytes);
    if value == Digest384::ZERO { Err("digest cannot be zero".into()) } else { Ok(value) }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("sha256:").ok_or("expected canonical sha256 commitment")?;
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return Err("expected canonical sha256 commitment".into());
    }
    let mut bytes = [0_u8; 32];
    decode_hex_into(value, &mut bytes)?;
    if bytes == [0; 32] { Err("commitment cannot be zero".into()) } else { Ok(bytes) }
}

fn decode_hex_into(value: &str, output: &mut [u8]) -> Result<(), String> {
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(())
}

fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal character".into()),
    }
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be a positive u64"))
}

fn parse_u128(value: &str, name: &str) -> Result<u128, String> {
    value
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be a positive u128"))
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage() -> &'static str {
    "usage:\n  actum-evidence-settle init <ledger> <chain> <unit> <authority> <payer> \
     <payer-balance> <executor> <executor-balance> <expected-total>\n  \
     actum-evidence-settle settle <ledger> <native-evidence> <sha256-anchor> \
     <statement-reference> <evidence-transaction> <height> <block> <chain> <genesis> \
     <authority> <payer> <executor> <agreement> <capability> <sha256-scope> <amount> \
     <unit> <logical-time> <record-out> <reputation-out> <state-anchor-out>\n  \
     actum-evidence-settle query-evidence <ledger> <sha256-anchor>\n  \
     actum-evidence-settle query-settlement <ledger> <settlement-id>\n  \
     actum-evidence-settle query-account <ledger> <principal>\n  \
     actum-evidence-settle query-reputation <ledger> <executor>"
}
