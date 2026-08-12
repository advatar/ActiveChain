//! Drives many sequential faucet grants against a live node and checks the
//! invariants that a single grant cannot demonstrate.
//!
//! One successful grant proves almost nothing about a faucet. The failure that
//! wedged Kanalen only appeared on the *second* request, because an ordinary
//! transfer costs the treasury a Coin Cell and the treasury had exactly two.
//! What has to be shown is that the treasury stays spendable across a long run
//! of grants, that recipients end up holding verified Coin Cells, and that
//! refusals are honest about why.
//!
//! ```text
//! activechain-faucet-rehearsal <rpc-address> <treasury-owner-hex> <grants>
//! ```
//!
//! Each grant goes to a fresh recipient, because the recipient cooldown is
//! measured in hours and reusing one would test the cooldown rather than the
//! treasury. Grants are paced against finality: the authorizer selects treasury
//! cells from the last finalized snapshot, so issuing faster than the chain
//! finalizes would keep reselecting the same cells.

use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use activechain_rpc_server::query;
use activechain_rpc_types::{FaucetRequestV1, RpcRequest, RpcResponse};
use std::{env, process::ExitCode, thread::sleep, time::Duration};

/// A round is published every 30s, so the treasury view a grant sees only
/// advances that often.
const POLL: Duration = Duration::from_secs(5);
const GRANT_TIMEOUT: Duration = Duration::from_secs(180);

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

struct Outcome {
    granted: usize,
    refused: Vec<(usize, String)>,
    treasury_floor: usize,
}

fn run() -> Result<String, String> {
    let mut arguments = env::args().skip(1);
    let (Some(address), Some(owner), Some(count)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err(
            "usage: activechain-faucet-rehearsal <rpc-address> <treasury-owner-hex> <grants>"
                .to_owned(),
        );
    };
    let grants: usize = count.parse().map_err(|_| "grant count must be a number".to_owned())?;
    // Recipients and idempotency keys must be unique per *run*, not merely per
    // index. Deriving them from the index alone made a second run replay the
    // first run's requests, which the faucet correctly answered from its
    // durable records without settling anything -- indistinguishable, from the
    // outside, from a treasury that had stopped working.
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock predates the epoch".to_owned())?
        .as_nanos();
    let treasury = PrincipalId::new(decode_digest(&owner)?);
    let status = status(&address)?;

    let mut outcome = Outcome { granted: 0, refused: Vec::new(), treasury_floor: usize::MAX };
    let mut recipients = Vec::with_capacity(grants);

    for index in 0..grants {
        let held = owner_cells(&address, treasury)?.len();
        outcome.treasury_floor = outcome.treasury_floor.min(held);
        if held < 2 {
            return Err(format!(
                "treasury fell to {held} Coin Cell(s) after {} grant(s); it can no longer \
                 construct a transfer and the run cannot continue",
                outcome.granted
            ));
        }
        let recipient = derive_principal(b"rehearsal-recipient", run, index);
        let request = FaucetRequestV1::new(
            status.0,
            status.1,
            recipient,
            derive_digest(b"rehearsal-idempotency", run, index),
            derive_digest(b"rehearsal-source", run, index),
            0,
            Vec::new(),
        )
        .map_err(|error| format!("could not build request {index}: {error:?}"))?;

        match grant(&address, &request)? {
            Ok(()) => {
                outcome.granted += 1;
                recipients.push(recipient);
                // Wait for the grant to actually cost the treasury a cell
                // before asking for the next one. The authorizer selects cells
                // from the last finalized snapshot, so issuing faster than the
                // chain finalizes would reselect the same input and fee reserve
                // and collide. The wait doubles as the per-grant proof that
                // settlement really happened rather than merely being accepted.
                let deadline = std::time::Instant::now() + GRANT_TIMEOUT;
                loop {
                    if owner_cells(&address, treasury)?.len() < held {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "grant {index} was accepted but the treasury still holds {held} \
                             cell(s) after {}s; settlement did not reach the ledger",
                            GRANT_TIMEOUT.as_secs()
                        ));
                    }
                    sleep(POLL);
                }
            }
            Err(reason) => outcome.refused.push((index, reason)),
        }
        println!(
            "grant {index}: treasury {held} cell(s) before, {} granted, {} refused",
            outcome.granted,
            outcome.refused.len()
        );
    }

    // Recipients only hold verified cells once the grants finalize, so settle
    // up at the end rather than stalling a round on every single grant.
    let mut funded = 0;
    let deadline = std::time::Instant::now() + GRANT_TIMEOUT;
    while std::time::Instant::now() < deadline {
        funded = recipients
            .iter()
            .filter(|recipient| {
                owner_cells(&address, **recipient).is_ok_and(|cells| !cells.is_empty())
            })
            .count();
        if funded == recipients.len() {
            break;
        }
        sleep(POLL);
    }

    let treasury_now = owner_cells(&address, treasury)?.len();
    let mut report = format!(
        "{} grant(s) issued, {} refused, {funded}/{} recipient(s) holding verified Coin Cells\n\
         treasury now {treasury_now} cell(s), lowest observed {}\n",
        outcome.granted,
        outcome.refused.len(),
        recipients.len(),
        outcome.treasury_floor
    );
    for (index, reason) in &outcome.refused {
        report.push_str(&format!("  grant {index} refused: {reason}\n"));
    }
    if funded != recipients.len() {
        return Err(format!("{report}only {funded} recipient(s) ended up funded"));
    }
    Ok(report)
}

/// Returns `Ok(Ok(()))` for an accepted grant and `Ok(Err(reason))` for a
/// refusal the node named, so a refusal is data rather than a failed run.
fn grant(address: &str, request: &FaucetRequestV1) -> Result<Result<(), String>, String> {
    let response =
        query(address, &RpcRequest::RequestFaucet { request: Box::new(request.clone()) })
            .map_err(|error| format!("faucet request failed: {error:?}"))?;
    match response {
        RpcResponse::FaucetReceipt(_) => Ok(Ok(())),
        RpcResponse::FaucetRejected(rejection) => Ok(Err(format!("{:?}", rejection.code()))),
        RpcResponse::Error(error) => Ok(Err(format!("untyped error {error:?}"))),
        _ => Err("node returned an unexpected response".to_owned()),
    }
}

fn status(address: &str) -> Result<(ChainId, Digest384), String> {
    match query(address, &RpcRequest::Status)
        .map_err(|error| format!("status failed: {error:?}"))?
    {
        RpcResponse::Status(status) => Ok((status.chain_id(), status.genesis_commitment())),
        _ => Err("node returned an unexpected status response".to_owned()),
    }
}

fn owner_cells(address: &str, owner: PrincipalId) -> Result<Vec<Digest384>, String> {
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
        .map_err(|error| format!("could not list Coin Cells: {error:?}"))?;
        let page = match response {
            RpcResponse::Page(page) => page,
            RpcResponse::Error(error) => return Err(format!("node refused the query: {error:?}")),
            _ => return Err("node returned an unexpected response".to_owned()),
        };
        cells.extend(page.records().iter().map(|record| record.key()));
        match page.next() {
            Some(cursor) => after = Some(cursor),
            None => return Ok(cells),
        }
    }
}

fn derive_digest(domain: &[u8], run: u128, index: usize) -> Digest384 {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    let mut shake = Shake256::default();
    shake.update(domain);
    shake.update(&run.to_be_bytes());
    shake.update(&(index as u64).to_be_bytes());
    let mut digest = [0_u8; 48];
    shake.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

fn derive_principal(domain: &[u8], run: u128, index: usize) -> PrincipalId {
    PrincipalId::new(derive_digest(domain, run, index))
}

fn decode_digest(value: &str) -> Result<Digest384, String> {
    if value.len() != 96 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("treasury owner must be 96 hex characters".to_owned());
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
