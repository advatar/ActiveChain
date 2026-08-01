use activechain_storage_soak::{SoakConfig, run_soak};
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match parse().and_then(|(directory, config)| run_soak(&directory, config)) {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("storage soak failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse() -> Result<(PathBuf, SoakConfig), activechain_storage_soak::SoakError> {
    let mut arguments = env::args().skip(1);
    let directory =
        arguments.next().map(PathBuf::from).ok_or(activechain_storage_soak::SoakError::Bounds)?;
    let mut config = SoakConfig::default();
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(activechain_storage_soak::SoakError::Bounds)?;
        match flag.as_str() {
            "--partition-bytes" => {
                config.partition_bytes =
                    value.parse().map_err(|_| activechain_storage_soak::SoakError::Bounds)?;
            }
            "--segment-bytes" => {
                config.segment_bytes =
                    value.parse().map_err(|_| activechain_storage_soak::SoakError::Bounds)?;
            }
            "--segments" => {
                config.segments =
                    value.parse().map_err(|_| activechain_storage_soak::SoakError::Bounds)?;
            }
            _ => return Err(activechain_storage_soak::SoakError::Bounds),
        }
    }
    Ok((directory, config.validate()?))
}
