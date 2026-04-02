use clap::Parser;
use kcd_proto::{
    split_knock, KnockPacket, DEFAULT_AUTH_PORT, DEFAULT_KNOCK_CHUNKS, DEFAULT_KNOCK_PORT,
    PROTOCOL_VERSION,
};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls_pemfile::certs;
use std::{
    io::BufReader,
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
    /// Klingon Cloaking Device server IP or hostname.
    #[arg(long)]
    server: String,

    /// UDP port for the knock sequence.
    #[arg(long, default_value_t = DEFAULT_KNOCK_PORT)]
    knock_port: u16,

    /// TCP port for TLS authentication.
    #[arg(long, default_value_t = DEFAULT_AUTH_PORT)]
    auth_port: u16,

    /// Knock password (split into UDP datagrams).
    #[arg(long, env = "KCD_KNOCK_PASSWORD")]
    knock_password: String,

    /// Access password (sent over TLS).
    #[arg(long, env = "KCD_ACCESS_PASSWORD")]
    access_password: String,

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

fn build_tls_config(args: &AuthorizeArgs) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    if args.insecure {
        warn!("TLS certificate verification is disabled (--insecure). This mode is vulnerable to MITM attacks.");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    if let Some(ref ca_path) = args.ca_cert {
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
    if args.knock_chunks == 0 {
        return Err("knock-chunks must be greater than 0".into());
    }
    if args.knock_password.is_empty() {
        return Err("knock-password must not be empty".into());
    }
    if args.access_password.is_empty() {
        return Err("access-password must not be empty".into());
    }

    // --- Phase 1: UDP knock ---
    let knock_addr = format!("{}:{}", args.server, args.knock_port);
    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    let chunks = split_knock(args.knock_password.as_bytes(), args.knock_chunks);
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
            total: args.knock_chunks,
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
    let auth_addr = format!("{}:{}", args.server, args.auth_port);
    let resolved = auth_addr
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve auth address")?;

    let tls_config = build_tls_config(&args)?;
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(args.server.clone())
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
    if response != "Ready" {
        return Err(format!("Unexpected server response: {response}").into());
    }
    info!("Server ready. Sending access password...");

    // Send access password
    writer
        .write_all(format!("{}\n", args.access_password).as_bytes())
        .await?;

    // Read result
    line.clear();
    reader.read_line(&mut line).await?;
    let result = line.trim();

    match result {
        "AUTHORIZED" => {
            info!("AUTHORIZED — your IP has been whitelisted.");
            Ok(())
        }
        "DENIED" => Err("DENIED — access password was incorrect.".into()),
        other => Err(format!("Unexpected response: {other}").into()),
    }
}
