//! Captures reproducible compiler and release metadata.

use std::{env, error::Error, io, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed=RSK_GIT_REVISION");
    println!("cargo::rerun-if-env-changed=RSK_BUILD_TIME");
    for key in ["RSK_GIT_REVISION", "RSK_BUILD_TIME"] {
        if let Ok(value) = env::var(key) {
            if value.contains(['\n', '\r']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{key} contains a line break"),
                )
                .into());
            }
            println!("cargo::rustc-env={key}={value}");
        }
    }

    let rustc = env::var_os("RUSTC")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "RUSTC is not set"))?;
    let output = Command::new(rustc).arg("--version").output()?;
    if !output.status.success() {
        return Err(io::Error::other("rustc --version failed").into());
    }
    let version = String::from_utf8(output.stdout)?;
    println!("cargo::rustc-env=RSK_RUSTC_VERSION={}", version.trim());
    Ok(())
}
