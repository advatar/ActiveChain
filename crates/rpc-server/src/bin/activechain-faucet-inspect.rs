//! Reports the durable state of every faucet reservation.
//!
//! A reservation is written before settlement is attempted, so the two files
//! this reads answer different questions and must be read together:
//!
//! * the faucet snapshot says what was *promised* to a recipient;
//! * the operator settlement journal says what was *authorized*.
//!
//! A record present in the first and absent from the second was never signed
//! and never published, so no transfer for it can exist. That is the fact an
//! operator needs before deciding whether a stuck reservation may be closed,
//! and it is not derivable from either file alone.
//!
//! ```text
//! activechain-faucet-inspect <faucet.snapshot> <faucet-settlement.journal>
//! ```
//!
//! Read-only. It never writes to either file; the node resolves reservations
//! itself at startup.

use activechain_protocol_types::{Digest384, PrincipalId};
use activechain_rpc_server::{inspect_records, journal_references, query};
use activechain_rpc_types::{FaucetState, RpcRequest, RpcResponse};
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut arguments = env::args().skip(1);
    let (Some(snapshot), Some(journal)) = (arguments.next(), arguments.next()) else {
        return Err(
            "usage: activechain-faucet-inspect <faucet.snapshot> <faucet-settlement.journal> \
             [<rpc-address> <treasury-owner-hex>]"
                .to_owned(),
        );
    };
    let records = inspect_records(&PathBuf::from(&snapshot))
        .map_err(|error| format!("could not read faucet snapshot: {error:?}"))?;
    let prepared = journal_references(&PathBuf::from(&journal))
        .map_err(|error| format!("could not read settlement journal: {error:?}"))?;

    let mut report = format!(
        "{} faucet record(s), {} durably authorized settlement(s)\n",
        records.len(),
        prepared.len()
    );
    let mut open = 0_usize;
    for record in &records {
        let authorized = prepared.contains(&record.reference);
        let state = match (record.state, record.transaction_id.is_some()) {
            (FaucetState::Pending, false) => {
                open += 1;
                // The distinction the whole exercise turns on: whether an
                // operator may close this record, or must replay it.
                if authorized { "OPEN (authorized, replayable)" } else { "OPEN (never authorized)" }
            }
            (FaucetState::Pending, true) => "submitted, awaiting finality",
            (FaucetState::Finalized, _) => "finalized",
            (FaucetState::Rejected, _) => "rejected",
        };
        report.push_str(&format!(
            "  reference {} recipient {} amount {} created_at {} idempotency {} -> {}\n",
            hex(record.reference.as_bytes()),
            prefix(record.recipient.into_digest().as_bytes()),
            record.amount,
            record.created_at,
            prefix(record.idempotency_key.as_bytes()),
            state
        ));
    }
    report.push_str(&format!("{open} reservation(s) awaiting resolution\n"));

    // Reservations only explain half of a stuck faucet. Authorization needs at
    // least two treasury Coin Cells -- one held back as the fee reserve, one or
    // more spent as transfer inputs -- and a treasury down to a single cell
    // fails every request with a bare InvalidTransition that names neither the
    // treasury nor the shortfall.
    if let (Some(address), Some(owner)) = (arguments.next(), arguments.next()) {
        report.push_str(&treasury_report(&address, &owner)?);
    }
    Ok(report)
}

fn treasury_report(address: &str, owner: &str) -> Result<String, String> {
    let owner = PrincipalId::new(decode_digest(owner)?);
    let mut cells = Vec::new();
    let mut after = None;
    loop {
        let response = query(
            address,
            &RpcRequest::ListOwnerCoinCells {
                owner,
                after,
                limit: activechain_rpc_types::MAX_RPC_PAGE_SIZE,
            },
        )
        .map_err(|error| format!("could not query treasury cells: {error:?}"))?;
        let page = match response {
            RpcResponse::Page(page) => page,
            RpcResponse::Error(error) => return Err(format!("node refused the query: {error:?}")),
            _ => return Err("node returned an unexpected response".to_owned()),
        };
        cells.extend(page.records().iter().map(|record| record.key()));
        match page.next() {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }
    let mut report = format!(
        "treasury {} holds {} Coin Cell(s)",
        prefix(owner.into_digest().as_bytes()),
        cells.len()
    );
    if cells.len() < 2 {
        report.push_str(
            " -- BELOW THE MINIMUM. Authorization reserves the largest cell for\n  \
             the fee and spends the rest, so it needs at least two. Every faucet\n  \
             request will fail with InvalidTransition until the treasury is split.",
        );
    }
    report.push('\n');
    Ok(report)
}

fn decode_digest(value: &str) -> Result<Digest384, String> {
    if value.len() != 96 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("owner must be 96 hex characters".to_owned());
    }
    let mut digest = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| "owner must be ASCII hex".to_owned())?,
            16,
        )
        .map_err(|_| "owner must be hex".to_owned())?;
    }
    Ok(Digest384::new(digest))
}

/// Recipients are wallet identities, so they are reported as a prefix — enough
/// to correlate with a node log, not enough to enumerate holders from a report.
fn prefix(bytes: &[u8]) -> String {
    hex(&bytes[..8.min(bytes.len())])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}
