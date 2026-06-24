//! Demo: load the test CA, issue a user certificate, and print it.
//!
//! ```sh
//! cargo run --example issue_cert
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use mayfly_server::ca::{CaService, CertificateRequest};
use mayfly_server::clock::SystemClock;
use ssh_key::certificate::Certificate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test");
    let ca = CaService::load(&key_path, "mayfly-test-passphrase", "mayfly-ca", Arc::new(SystemClock))?;

    println!("CA public key:\n{}", ca.get_ca_public_key()?);

    // A throwaway subject key to be signed.
    let subject = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)?;
    let request = CertificateRequest {
        github_login: "vasugarg".to_string(),
        hostname: "web-01".to_string(),
        public_key: subject.public_key().to_openssh()?,
        ttl_seconds: 300,
    };

    let response = ca.sign_certificate(&request)?;
    println!("\n--- CertificateResponse ---");
    println!("{}", serde_json::to_string_pretty(&response)?);

    let cert = Certificate::from_openssh(&response.certificate)?;
    println!("\n--- Parsed certificate ---");
    println!("type:        {:?}", cert.cert_type());
    println!("principals:  {:?}", cert.valid_principals());
    println!("serial:      {}", cert.serial());
    println!("key_id:      {}", cert.key_id());
    println!("extensions:  {:?}", cert.extensions().keys().collect::<Vec<_>>());
    Ok(())
}
