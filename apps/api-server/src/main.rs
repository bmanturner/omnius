//! PostgreSQL-backed reference API server binary.

use std::process::ExitCode;

use clap::Parser as _;
use omnius_api_server::{Cli, RunOutcome, execute};

#[tokio::main]
async fn main() -> ExitCode {
    omnius_runtime::redact_all_panics();
    let cli = Cli::parse();

    match Box::pin(execute(cli)).await {
        Ok(RunOutcome::Graceful) => ExitCode::SUCCESS,
        Ok(RunOutcome::Forced) => ExitCode::from(130),
        Err(error) => {
            eprintln!("service failed code={} detail={error}", error.code());
            ExitCode::FAILURE
        }
    }
}
