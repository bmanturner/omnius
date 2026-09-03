//! Cargo subcommand entry point for generated service lifecycle management.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(omnius_generator::cargo_service::main_entry())
}
