fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let Some(directory) = arguments.next() else {
        eprintln!("usage: activechain-mcp-rehearsal <disposable-directory>");
        std::process::exit(2);
    };
    if arguments.next().is_some() {
        eprintln!("unexpected extra argument");
        std::process::exit(2);
    }
    match activechain_mcp_rehearsal::run_rehearsal(std::path::Path::new(&directory)) {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => {
            eprintln!("rehearsal failed: {error:?}");
            std::process::exit(1);
        }
    }
}
