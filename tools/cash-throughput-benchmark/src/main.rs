use activechain_cash_throughput_benchmark::{BenchmarkConfig, run};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .map(|value| value.parse::<u32>().expect("iterations must be a positive u32"))
        .unwrap_or(3);
    let report = run(BenchmarkConfig::new(iterations).expect("iterations must be nonzero"))
        .expect("proof-finalized cash benchmark failed");
    println!("{}", serde_json::to_string_pretty(&report).expect("report serialization failed"));
}
