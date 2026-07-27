use activechain_canonical_codec::encode_envelope;
use activechain_protocol_types::{
    AssetId, Digest384, FungibleAssetLifecycle, FungibleAssetPolicyV1, FungibleIssuerApprovalV1,
    FungibleIssuerOperation, PrincipalId,
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

fn usage() -> &'static str {
    "usage:\n  activechain-issuer policy <asset> <issuer> <authority-set> <cap> <issued>\n  activechain-issuer approval <asset> <policy> <authority-set> <approval> <operation> <amount> <supply-before> <effective-height> <expires-height>"
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
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
}
