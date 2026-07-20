use activechain_protocol_types::{Digest384, PrincipalId};
use activechain_wallet_core::FaucetService;
use std::env;

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [TABLE[(byte >> 4) as usize] as char, TABLE[(byte & 0x0f) as usize] as char]
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("grant") {
        return Err(
            "usage: activechain-faucet grant <genesis-byte> <recipient-byte> <amount>".into()
        );
    }
    let genesis: u8 = args.next().ok_or("missing genesis byte")?.parse()?;
    let recipient: u8 = args.next().ok_or("missing recipient byte")?.parse()?;
    let amount: u128 = args.next().ok_or("missing amount")?.parse()?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut service = FaucetService::default();
    let grant = service
        .claim(
            Digest384::new([genesis; 48]),
            PrincipalId::new(Digest384::new([recipient; 48])),
            amount,
        )
        .map_err(|error| format!("faucet claim rejected: {error:?}"))?;
    println!("genesis_hash={}", hex(grant.genesis_hash.as_bytes()));
    println!("recipient={}", hex(grant.recipient.into_digest().as_bytes()));
    println!("amount={}", grant.amount);
    println!("claim_id={}", hex(grant.claim_id.as_bytes()));
    Ok(())
}
