use std::io::{self, BufRead, Write};

use activechain_mcp_server::{McpSession, ReadOnlyBackend};

struct UnconfiguredBackend;

impl ReadOnlyBackend for UnconfiguredBackend {
    fn get_status(&self) -> Result<serde_json::Value, activechain_mcp_server::BackendError> {
        Err(activechain_mcp_server::BackendError::Unavailable)
    }
    fn list_assets(
        &self,
        _: Option<&str>,
        _: u16,
    ) -> Result<serde_json::Value, activechain_mcp_server::BackendError> {
        Err(activechain_mcp_server::BackendError::Unavailable)
    }
    fn verify_record(
        &self,
        _: &str,
    ) -> Result<serde_json::Value, activechain_mcp_server::BackendError> {
        Err(activechain_mcp_server::BackendError::Unavailable)
    }
    fn get_pending_approvals(
        &self,
        _: u16,
    ) -> Result<serde_json::Value, activechain_mcp_server::BackendError> {
        Err(activechain_mcp_server::BackendError::Unavailable)
    }
    fn resolve_receipt(
        &self,
        _: &str,
    ) -> Result<serde_json::Value, activechain_mcp_server::BackendError> {
        Err(activechain_mcp_server::BackendError::Unavailable)
    }
}

fn main() -> io::Result<()> {
    let mut session = McpSession::new(UnconfiguredBackend);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().split(b'\n') {
        let line = line?;
        if let Some(response) = session.handle_line(&line)
            && !response.is_empty()
        {
            stdout.write_all(&response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
