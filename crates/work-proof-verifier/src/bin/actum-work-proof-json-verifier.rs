use activechain_work_proof_verifier::json_adapter::{
    MAX_JSON_VERIFIER_REQUEST_BYTES, verify_json_request,
};
use std::io::{self, Read, Write};

fn main() {
    let maximum = u64::try_from(MAX_JSON_VERIFIER_REQUEST_BYTES).unwrap_or(u64::MAX);
    let mut input = Vec::new();
    let _ = io::stdin().take(maximum.saturating_add(1)).read_to_end(&mut input);
    let result = verify_json_request(&input);
    let encoded = serde_json::to_vec(&result).unwrap_or_else(|_| {
        br#"{"schema":"actum.work-proof.verify.result.v1","code":"MALFORMED","verified":false,"profile":"actum.non-overlap.risc0.v1"}"#.to_vec()
    });
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(&encoded);
    let _ = stdout.write_all(b"\n");
}
