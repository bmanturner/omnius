//! Process-boundary stdio fixture target for MCP conformance acceptance tests.

use std::{
    env,
    error::Error,
    io::{self, Read, Write},
};

use omnius_mcp_conformance::{Transport, execute_fixture_target};

const MAX_REQUEST_BYTES: u64 = 64 * 1_024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("stdio") || arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected stdio mode").into());
    }

    let mut request = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request)?;
    if u64::try_from(request.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request exceeded bound").into());
    }
    let response = execute_fixture_target(Transport::Stdio, &request)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture request failed"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&response)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
