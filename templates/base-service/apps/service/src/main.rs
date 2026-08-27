use std::{
    env,
    error::Error,
    fs,
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    process::ExitCode,
    time::Duration,
};

use serde::Deserialize;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let mode = arguments.next().unwrap_or_else(|| "server".to_owned());
    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many arguments").into());
    }
    match mode.as_str() {
        "server" => serve().await,
        "profile-info" | "version" => profile_info(),
        "healthcheck" => healthcheck(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mode must be server, profile-info, version, or healthcheck",
        )
        .into()),
    }
}
async fn serve() -> Result<(), Box<dyn Error>> {
    let configured_address = load_bind_address()?;
    let listener = tokio::net::TcpListener::bind(configured_address).await?;
    let address = listener.local_addr()?;
    println!("listening on http://{address}");
    axum::serve(listener, service::router()?)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            eprintln!("failed to install interrupt signal: {error}");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => eprintln!("failed to install termination signal: {error}"),
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("failed to install interrupt signal: {error}");
    }
}

fn profile_info() -> Result<(), Box<dyn Error>> {
    let metadata = service::build_metadata()?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &metadata)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn healthcheck() -> Result<(), Box<dyn Error>> {
    let address = if let Ok(address) = env::var("OMNIUS_HEALTH_ADDRESS") {
        address.parse()?
    } else {
        load_bind_address()?
    };
    let mut stream = TcpStream::connect(address)?;
    let timeout = Some(Duration::from_secs(2));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    stream.write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = [0_u8; 1024];
    let length = stream.read(&mut response)?;
    let success = response[..length].starts_with(b"HTTP/1.1 200")
        || response[..length].starts_with(b"HTTP/1.0 200");
    if !success {
        return Err(io::Error::other("readiness endpoint did not return HTTP 200").into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct LocalConfig {
    server: ServerConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    bind: SocketAddr,
}

fn load_bind_address() -> Result<SocketAddr, Box<dyn Error>> {
    if let Ok(address) = env::var("OMNIUS_BIND") {
        return Ok(address.parse()?);
    }
    let source = if let Ok(path) = env::var("OMNIUS_CONFIG") {
        fs::read_to_string(path)?
    } else {
        include_str!("../../../config/local.toml").to_owned()
    };
    let config: LocalConfig = toml::from_str(&source)?;
    Ok(config.server.bind)
}
