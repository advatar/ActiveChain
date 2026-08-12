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

use activechain_rpc_server::{inspect_records, journal_references};
use activechain_rpc_types::FaucetState;
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
            "usage: activechain-faucet-inspect <faucet.snapshot> <faucet-settlement.journal>"
                .to_owned(),
        );
    };
    if arguments.next().is_some() {
        return Err("unexpected argument".to_owned());
    }
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
    Ok(report)
}

/// Recipients are wallet identities, so they are reported as a prefix — enough
/// to correlate with a node log, not enough to enumerate holders from a report.
fn prefix(bytes: &[u8]) -> String {
    hex(&bytes[..8.min(bytes.len())])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}
