use crate::AppState;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::{
    fs,
    io::BufReader,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time;
use tracing::{info, warn};

pub(crate) fn load_tls_config_from_paths(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    info!("Loading TLS cert from {:?}, key from {:?}", cert_path, key_path);

    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;

    let certs_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    info!("TLS certificate chain: {} cert(s) loaded", certs_chain.len());

    // Use private_key() which auto-detects PKCS#8, PKCS#1 (RSA), and SEC1 (EC) PEM formats.
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or("No private key found in PEM file (expected PKCS#8, PKCS#1, or SEC1/EC)")?;
    info!("TLS private key loaded successfully");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs_chain, key.into())?;

    info!("TLS configuration built successfully");
    Ok(Arc::new(config))
}

/// Poll cert/key files for changes and reload TLS config when modified.
/// Uses mtime polling because inotify is unreliable on volume-mounted Secrets
/// (kubelet uses symlink swaps that don't always trigger MODIFY events).
pub(crate) async fn run_cert_watcher(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(30));
    let mut last_mtime: Option<(SystemTime, SystemTime)> = None;

    // Seed with initial mtimes.
    if let (Ok(cert_meta), Ok(key_meta)) = (
        fs::metadata(&state.cert_path),
        fs::metadata(&state.key_path),
    ) {
        last_mtime = Some((
            cert_meta.modified().unwrap_or(UNIX_EPOCH),
            key_meta.modified().unwrap_or(UNIX_EPOCH),
        ));
    }

    info!("TLS cert watcher started (polling every 30s)");

    loop {
        interval.tick().await;

        let (cert_meta, key_meta) = match (
            fs::metadata(&state.cert_path),
            fs::metadata(&state.key_path),
        ) {
            (Ok(c), Ok(k)) => (c, k),
            _ => continue,
        };

        let current_mtime = (
            cert_meta.modified().unwrap_or(UNIX_EPOCH),
            key_meta.modified().unwrap_or(UNIX_EPOCH),
        );

        if last_mtime.as_ref() == Some(&current_mtime) {
            continue;
        }

        // Debounce: wait for both files to stabilize.
        time::sleep(Duration::from_secs(1)).await;

        match load_tls_config_from_paths(&state.cert_path, &state.key_path) {
            Ok(new_config) => {
                state.tls_config.store(new_config);
                last_mtime = Some(current_mtime);
                info!("TLS certificate reloaded successfully");
            }
            Err(e) => {
                warn!("TLS certificate reload failed (keeping old config): {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::load_tls_config_from_paths;
    use std::io::Write;

    #[test]
    fn load_tls_config_with_valid_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let subject_alt_names = vec!["localhost".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert_pem.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_pem.as_bytes())
            .unwrap();

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_ok(), "Expected valid TLS config, got: {:?}", config.err());
    }

    #[test]
    fn load_tls_config_with_invalid_pem_returns_error() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::write(&cert_path, b"not a cert").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_err());
    }

    #[test]
    fn load_tls_config_with_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("nonexistent.crt");
        let key_path = dir.path().join("nonexistent.key");

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_err());
    }

    #[test]
    fn load_tls_config_with_ec_key() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert.pem().as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_pair.serialize_pem().as_bytes())
            .unwrap();

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_ok(), "EC key should load; got: {:?}", config.err());
    }
}
