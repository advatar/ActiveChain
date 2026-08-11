use activechain_work_proof_verifier::{MAX_SUBPROCESS_FRAME_BYTES, verify_ipc_request};
use std::io::{Read, Write};

fn main() {
    let mut frame = Vec::new();
    if std::io::stdin()
        .take((MAX_SUBPROCESS_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut frame)
        .is_err()
        || frame.len() > MAX_SUBPROCESS_FRAME_BYTES
    {
        std::process::exit(2);
    }
    let code = verify_ipc_request(&frame);
    if std::io::stdout().write_all(&[code]).is_err() || code != 0 {
        std::process::exit(i32::from(code.max(1)));
    }
}
