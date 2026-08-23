use activechain_work_proof_prover::{ProverError, request_proof_over_socket, serve_sidecar};
use serde::Serialize;
use std::{env, io::Write as _, path::Path};

#[derive(Serialize)]
struct FailureResponse {
    status: &'static str,
}

fn main() {
    if env::args().nth(1).as_deref() == Some("--serve") {
        let mut arguments = env::args().skip(2);
        let Some(config) = arguments.next() else {
            std::process::exit(2);
        };
        if arguments.next().is_some() || serve_sidecar(Path::new(&config)).is_err() {
            std::process::exit(1);
        }
        return;
    }
    let result = run();
    let output = match result {
        Ok(response) => Ok(response),
        Err(ProverError::Invalid | ProverError::Conflict) => {
            serde_json::to_vec(&FailureResponse { status: "invalid" })
        }
        Err(ProverError::Unavailable) => {
            serde_json::to_vec(&FailureResponse { status: "unavailable" })
        }
    };
    match output {
        Ok(output) => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&output);
            let _ = stdout.write_all(b"\n");
        }
        Err(_) => {
            println!("{{\"status\":\"unavailable\"}}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Vec<u8>, ProverError> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("--input") {
        return Err(ProverError::Invalid);
    }
    let input = arguments.next().ok_or(ProverError::Invalid)?;
    if arguments.next().as_deref() != Some("--request-id") {
        return Err(ProverError::Invalid);
    }
    let request_id = arguments.next().ok_or(ProverError::Invalid)?;
    if arguments.next().is_some() {
        return Err(ProverError::Invalid);
    }
    let socket = env::var("ACTUM_WORK_PROVER_SOCKET").map_err(|_| ProverError::Unavailable)?;
    if !Path::new(&socket).is_absolute() || !Path::new(&input).is_absolute() {
        return Err(ProverError::Invalid);
    }
    request_proof_over_socket(Path::new(&socket), Path::new(&input), &request_id)
}
