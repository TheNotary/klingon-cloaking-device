mod config;

use clap::Parser;
use kcd_proto::{
    split_knock, KnockPacket, DEFAULT_AUTH_PORT, DEFAULT_KNOCK_CHUNKS, DEFAULT_KNOCK_PORT,
    HANDSHAKE_AUTHORIZED, HANDSHAKE_DENIED, HANDSHAKE_READY, PROTOCOL_VERSION,
};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls_pemfile::certs;
use std::{
    io::{BufReader, IsTerminal, Write as _},
    net::ToSocketAddrs,
    process,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader},
    net::UdpSocket,
    time::sleep,
};
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "klingon-cloaking-device",
    about = "Port-knock IP whitelisting client"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Send a knock sequence and authenticate to whitelist your IP.
    Authorize(AuthorizeArgs),
}

#[derive(clap::Args)]
struct AuthorizeArgs {
    /// Klingon Cloaking Device server IP or hostname (required unless ~/.kcd/config exists).
    #[arg(long)]
    server: Option<String>,

    /// UDP port for the knock sequence.
    #[arg(long, default_value_t = DEFAULT_KNOCK_PORT)]
    knock_port: u16,

    /// TCP port for TLS authentication.
    #[arg(long, default_value_t = DEFAULT_AUTH_PORT)]
    auth_port: u16,

    /// Knock password (split into UDP datagrams; required unless ~/.kcd/config exists).
    #[arg(long, env = "KCD_KNOCK_PASSWORD")]
    knock_password: Option<String>,

    /// Access password (sent over TLS; required unless ~/.kcd/config exists).
    #[arg(long, env = "KCD_ACCESS_PASSWORD")]
    access_password: Option<String>,

    /// Hostname for TLS server name verification (overrides --server for cert checks).
    #[arg(long)]
    hostname: Option<String>,

    /// Path to a PEM CA certificate to verify the server.
    #[arg(long)]
    ca_cert: Option<String>,

    /// Skip TLS certificate verification (use with self-signed certs).
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Number of chunks to split the knock password into.
    #[arg(long, default_value_t = DEFAULT_KNOCK_CHUNKS)]
    knock_chunks: u8,
}

/// A TLS verifier that accepts any certificate (for --insecure mode).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_config(
    ca_cert: Option<&str>,
    insecure: bool,
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    if insecure {
        warn!("TLS certificate verification is disabled (--insecure). This mode is vulnerable to MITM attacks.");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    if let Some(ca_path) = ca_cert {
        let ca_file = std::fs::File::open(ca_path)?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()?;

        if ca_certs.is_empty() {
            return Err(format!("No certificates found in CA PEM file: {ca_path}").into());
        }

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    // Use system default root certificates.
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Authorize(args) => {
            if let Err(e) = authorize(args).await {
                error!("{e}");
                process::exit(1);
            }
        }
    }
}

async fn authorize(args: AuthorizeArgs) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref server) = args.server {
        // Explicit args mode: --server was provided, require passwords too.
        let knock_password = args.knock_password.as_deref().ok_or(
            "--knock-password (or KCD_KNOCK_PASSWORD) is required when --server is specified",
        )?;
        let access_password = args.access_password.as_deref().ok_or(
            "--access-password (or KCD_ACCESS_PASSWORD) is required when --server is specified",
        )?;

        authorize_single(
            server,
            args.hostname.as_deref(),
            args.knock_port,
            args.auth_port,
            knock_password,
            access_password,
            args.ca_cert.as_deref(),
            args.insecure,
            args.knock_chunks,
        )
        .await?;

        // Offer to save config on first successful auth
        maybe_save_config(
            server,
            args.hostname.as_deref(),
            args.knock_port,
            args.auth_port,
            knock_password,
            access_password,
            args.insecure,
            args.knock_chunks,
        );

        Ok(())
    } else {
        // Config mode: load ~/.kcd/config
        let cfg = config::load_config()?
            .ok_or("No --server specified and no config file found at ~/.kcd/config")?;
        if cfg.servers.is_empty() {
            return Err("Config file ~/.kcd/config contains no server entries".into());
        }

        let mut failures: Vec<(String, String)> = Vec::new();
        for entry in &cfg.servers {
            let knock_port = entry.knock_port.unwrap_or(DEFAULT_KNOCK_PORT);
            let auth_port = entry.auth_port.unwrap_or(DEFAULT_AUTH_PORT);
            let knock_chunks = entry.knock_chunks.unwrap_or(DEFAULT_KNOCK_CHUNKS);

            info!("Authorizing against server '{}'...", entry.name);
            if let Err(e) = authorize_single(
                &entry.address,
                entry.hostname.as_deref(),
                knock_port,
                auth_port,
                &entry.knock_password,
                &entry.access_password,
                None,
                entry.insecure_skip_tls_verify,
                knock_chunks,
            )
            .await
            {
                error!("Server '{}' failed: {e}", entry.name);
                failures.push((entry.name.clone(), e.to_string()));
            } else {
                info!("Server '{}': AUTHORIZED", entry.name);
            }
        }

        if failures.is_empty() {
            info!("All {} server(s) authorized successfully.", cfg.servers.len());
            Ok(())
        } else {
            let total = cfg.servers.len();
            let failed = failures.len();
            for (name, err) in &failures {
                error!("  {name}: {err}");
            }
            Err(format!("{failed}/{total} server(s) failed authorization").into())
        }
    }
}

fn maybe_save_config(
    server: &str,
    hostname: Option<&str>,
    knock_port: u16,
    auth_port: u16,
    knock_password: &str,
    access_password: &str,
    insecure: bool,
    knock_chunks: u8,
) {
    // Only offer if no config file exists yet
    let config_exists = config::config_path()
        .map(|p| p.exists())
        .unwrap_or(false);
    if config_exists {
        return;
    }

    let should_save = if std::io::stdin().is_terminal() {
        print!("Save server to ~/.kcd/config? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => {
                let trimmed = input.trim().to_lowercase();
                trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
            }
            Err(_) => false,
        }
    } else {
        // Non-TTY: default to no to avoid hanging in scripts
        false
    };

    if !should_save {
        return;
    }

    let name = hostname.unwrap_or(server).to_string();
    let entry = config::ServerEntry {
        name,
        address: server.to_string(),
        hostname: hostname.map(|h| h.to_string()),
        knock_password: knock_password.to_string(),
        access_password: access_password.to_string(),
        insecure_skip_tls_verify: insecure,
        knock_port: if knock_port != DEFAULT_KNOCK_PORT {
            Some(knock_port)
        } else {
            None
        },
        auth_port: if auth_port != DEFAULT_AUTH_PORT {
            Some(auth_port)
        } else {
            None
        },
        knock_chunks: if knock_chunks != DEFAULT_KNOCK_CHUNKS {
            Some(knock_chunks)
        } else {
            None
        },
    };

    let cfg = config::KcdConfig {
        servers: vec![entry],
    };

    match config::save_config(&cfg) {
        Ok(()) => info!("Created ~/.kcd/config with server credentials."),
        Err(e) => warn!("Failed to save config: {e}"),
    }
}

async fn authorize_single(
    server: &str,
    hostname: Option<&str>,
    knock_port: u16,
    auth_port: u16,
    knock_password: &str,
    access_password: &str,
    ca_cert: Option<&str>,
    insecure: bool,
    knock_chunks: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    if knock_chunks == 0 {
        return Err("knock-chunks must be greater than 0".into());
    }
    if knock_password.is_empty() {
        return Err("knock-password must not be empty".into());
    }
    if access_password.is_empty() {
        return Err("access-password must not be empty".into());
    }

    // --- Phase 1: UDP knock ---
    let knock_addr = format!("{server}:{knock_port}");
    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    let chunks = split_knock(knock_password.as_bytes(), knock_chunks);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    info!(
        "Sending knock sequence ({} packets) to {knock_addr}...",
        chunks.len()
    );

    for (i, chunk) in chunks.iter().enumerate() {
        let pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: i as u8,
            total: knock_chunks,
            timestamp,
            payload: chunk.clone(),
        };
        sock.send_to(&pkt.to_bytes(), &knock_addr).await?;
        if i + 1 < chunks.len() {
            sleep(Duration::from_millis(100)).await;
        }
    }

    info!("Knock sequence sent. Waiting 5 seconds...");
    sleep(Duration::from_secs(5)).await;

    // --- Phase 2: TCP/TLS auth ---
    let auth_addr = format!("{server}:{auth_port}");
    let resolved = auth_addr
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve auth address")?;

    let tls_config = build_tls_config(ca_cert, insecure)?;
    let connector = TlsConnector::from(tls_config);
    let tls_host = hostname.unwrap_or(server);
    let server_name = ServerName::try_from(tls_host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("klingon-cloaking-device".to_string()).unwrap());

    info!("Connecting to {auth_addr}...");
    let tcp_stream = tokio::net::TcpStream::connect(resolved).await?;
    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = TokioBufReader::new(reader);

    // Read "Ready\n"
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let response = line.trim();
    if response != HANDSHAKE_READY.trim() {
        return Err(format!("Unexpected server response: {response}").into());
    }
    info!("Server ready. Sending access password...");

    // Send access password
    writer
        .write_all(format!("{access_password}\n").as_bytes())
        .await?;

    // Read result
    line.clear();
    reader.read_line(&mut line).await?;
    let result = line.trim();

    match result {
        s if s == HANDSHAKE_AUTHORIZED.trim() => {
            info!("AUTHORIZED \u{2014} your IP has been whitelisted.");
            Ok(())
        }
        s if s == HANDSHAKE_DENIED.trim() => Err("DENIED \u{2014} access password was incorrect.".into()),
        other => Err(format!("Unexpected response: {other}").into()),
    }
}
