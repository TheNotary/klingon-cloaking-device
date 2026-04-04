#![allow(dead_code)]

use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::io::Write;
use tempfile::NamedTempFile;

/// Generated TLS artifacts for a test server.
pub struct TestTlsCerts {
    /// Temp file containing the PEM-encoded certificate.
    pub cert_file: NamedTempFile,
    /// Temp file containing the PEM-encoded private key.
    pub key_file: NamedTempFile,
    /// PEM-encoded certificate bytes (for client CA verification).
    pub cert_pem: Vec<u8>,
}

/// Generate a self-signed TLS certificate for testing.
///
/// The certificate is valid for `localhost` and `127.0.0.1`.
pub fn generate_test_certs() -> TestTlsCerts {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("Failed to generate self-signed cert");

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    let mut cert_file = NamedTempFile::new().expect("Failed to create cert tempfile");
    cert_file.write_all(&cert_pem).expect("Failed to write cert");
    cert_file.flush().expect("Failed to flush cert");

    let mut key_file = NamedTempFile::new().expect("Failed to create key tempfile");
    key_file.write_all(&key_pem).expect("Failed to write key");
    key_file.flush().expect("Failed to flush key");

    TestTlsCerts {
        cert_file,
        key_file,
        cert_pem,
    }
}
