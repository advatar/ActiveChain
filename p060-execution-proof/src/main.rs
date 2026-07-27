use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use p060::{Action, Block, Opcode, Receipt, prove, verify_model_receipt, verify_receipt};
use serde::Serialize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 5 => {
            let pre_state = args[2].parse::<u64>()?;
            let block = parse_actions(&args[3])?;
            let receipt = prove(pre_state, &block)?;
            let encoded = receipt.encode()?;
            fs::write(&args[4], &encoded)?;
            println!(
                "wrote {} bytes ({} proof bytes), post_state={}",
                encoded.len(),
                receipt.proof.len(),
                receipt.post_state
            );
        }
        Some("verify") if args.len() == 3 => {
            let bytes = fs::read(&args[2])?;
            let report = verify_receipt(&bytes, None)?;
            println!(
                "valid: actions={}, trace={}, proof_bytes={}, conjectured_bits={}, proven_ldr_bits={}, proven_udr_bits={}, post_state={}",
                report.action_count,
                report.trace_length,
                report.proof_bytes,
                report.conjectured_soundness_bits,
                report.proven_ldr_bits,
                report.proven_udr_bits,
                report.post_state
            );
        }
        Some("model-verify") if args.len() == 3 => {
            let bytes = fs::read(&args[2])?;
            let post_state = verify_model_receipt(&bytes)?;
            println!("model-valid: post_state={post_state}");
        }
        Some("inspect") if args.len() == 3 => {
            let bytes = fs::read(&args[2])?;
            let receipt = Receipt::decode(&bytes)?;
            println!("protocol_version={}", receipt.header.protocol_version);
            println!("verifier_version={}", receipt.header.verifier_version);
            println!("suite_id=0x{:08x}", receipt.header.suite_id);
            println!("program_id={}", hex::encode(receipt.header.program_id));
            println!(
                "pre_state_root={}",
                hex::encode(receipt.header.pre_state_root)
            );
            println!("block_id={}", hex::encode(receipt.header.block_id));
            println!(
                "post_state_root={}",
                hex::encode(receipt.header.post_state_root)
            );
            println!("pre_state={}", receipt.pre_state);
            println!("post_state={}", receipt.post_state);
            println!("actions={}", receipt.block.actions.len());
            println!("proof_bytes={}", receipt.proof.len());
        }
        Some("vector") if args.len() == 3 => write_vector(Path::new(&args[2]))?,
        Some("check-vectors") if args.len() == 3 => check_vectors(Path::new(&args[2]))?,
        Some("bench") if args.len() == 4 => {
            let actions = args[2].parse::<usize>()?;
            let runs = args[3].parse::<usize>()?;
            benchmark(actions, runs)?;
        }
        _ => {
            eprintln!(
                "usage:\n  p060 prove <pre-state> <add:N,mul:N|-> <receipt.bin>\n  p060 verify <receipt.bin>\n  p060 model-verify <receipt.bin>\n  p060 inspect <receipt.bin>\n  p060 vector <output-dir>\n  p060 check-vectors <vector-dir>\n  p060 bench <action-count> <verify-runs>"
            );
            return Err("invalid arguments".into());
        }
    }
    Ok(())
}

fn parse_actions(value: &str) -> Result<Block, Box<dyn std::error::Error>> {
    if value == "-" || value.is_empty() {
        return Ok(Block::new(Vec::new())?);
    }
    let mut actions = Vec::new();
    for token in value.split(',') {
        let (name, operand) = token
            .split_once(':')
            .ok_or("action must be add:N or mul:N")?;
        let operand = operand.parse::<u64>()?;
        actions.push(match name {
            "add" => Action::add(operand),
            "mul" => Action::mul(operand),
            _ => return Err(format!("unknown action {name}").into()),
        });
    }
    Ok(Block::new(actions)?)
}

#[derive(Serialize)]
struct VectorManifest {
    name: &'static str,
    pre_state: u64,
    post_state: u64,
    action_count: usize,
    receipt_bytes: usize,
    proof_bytes: usize,
    receipt_shake256_384: String,
    block_id: String,
    post_state_root: String,
}

fn write_vector(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let block = Block::new(vec![Action::add(7), Action::mul(9), Action::add(11)])?;
    let receipt = prove(5, &block)?;
    let bytes = receipt.encode()?;
    verify_receipt(&bytes, None)?;
    fs::create_dir_all(directory)?;
    fs::write(directory.join("positive-v1.receipt"), &bytes)?;
    fs::write(directory.join("positive-v1.block"), block.encode()?)?;
    let digest = p060::hash::boundary_hash(b"test-vector-receipt", &bytes);
    let manifest = VectorManifest {
        name: "positive-v1",
        pre_state: 5,
        post_state: receipt.post_state,
        action_count: block.actions.len(),
        receipt_bytes: bytes.len(),
        proof_bytes: receipt.proof.len(),
        receipt_shake256_384: hex::encode(digest),
        block_id: hex::encode(receipt.header.block_id),
        post_state_root: hex::encode(receipt.header.post_state_root),
    };
    fs::write(
        directory.join("positive-v1.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!("wrote vector to {}", directory.display());
    Ok(())
}

fn check_vectors(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let positive = fs::read(directory.join("positive-v1.receipt"))?;
    verify_receipt(&positive, None)?;

    let mut malformed = positive.clone();
    malformed[0] ^= 0xff;
    if verify_receipt(&malformed, None).is_ok() {
        return Err("malformed-v1 vector was accepted".into());
    }
    let manifest = fs::read_to_string(directory.join("malformed-v1.json"))?;
    if !manifest.contains("\"expected\": \"reject\"") {
        return Err("malformed-v1 manifest does not declare rejection".into());
    }
    println!("vectors valid: positive accepted, malformed rejected");
    Ok(())
}

#[derive(Serialize)]
struct BenchmarkResult {
    machine: String,
    rustc: String,
    actions: usize,
    trace_length: usize,
    proof_bytes: usize,
    receipt_bytes: usize,
    prove_millis: f64,
    verify_runs: usize,
    verify_millis_min: f64,
    verify_millis_mean: f64,
    verify_millis_max: f64,
    conjectured_soundness_bits: u32,
    proven_ldr_bits: u32,
    proven_udr_bits: u32,
}

fn benchmark(action_count: usize, runs: usize) -> Result<(), Box<dyn std::error::Error>> {
    if runs == 0 {
        return Err("verify-runs must be positive".into());
    }
    let actions = (0..action_count)
        .map(|i| Action {
            opcode: if i % 4 == 3 { Opcode::Mul } else { Opcode::Add },
            operand: if i % 4 == 3 { 3 } else { (i as u64) + 1 },
        })
        .collect();
    let block = Block::new(actions)?;
    let prove_start = Instant::now();
    let receipt = prove(17, &block)?;
    let prove_millis = prove_start.elapsed().as_secs_f64() * 1000.0;
    let bytes = receipt.encode()?;
    let mut timings = Vec::with_capacity(runs);
    let mut last_report = None;
    for _ in 0..runs {
        let start = Instant::now();
        let report = verify_receipt(&bytes, None)?;
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
        last_report = Some(report);
    }
    let report = last_report.unwrap();
    let result = BenchmarkResult {
        machine: machine_name(),
        rustc: rustc_version(),
        actions: action_count,
        trace_length: report.trace_length,
        proof_bytes: report.proof_bytes,
        receipt_bytes: report.receipt_bytes,
        prove_millis,
        verify_runs: runs,
        verify_millis_min: timings.iter().copied().fold(f64::INFINITY, f64::min),
        verify_millis_mean: timings.iter().sum::<f64>() / timings.len() as f64,
        verify_millis_max: timings.iter().copied().fold(0.0, f64::max),
        conjectured_soundness_bits: report.conjectured_soundness_bits,
        proven_ldr_bits: report.proven_ldr_bits,
        proven_udr_bits: report.proven_udr_bits,
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn machine_name() -> String {
    command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
        .or_else(|| command_output("uname", &["-m"]))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn rustc_version() -> String {
    command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_owned())
}
