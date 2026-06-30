//! Demo: load the test CA, issue a user certificate, and print it.
//!
//! ```sh
//! cargo run --example issue_cert
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use mayfly_server::ca::{CaManager, CertificateRequest};
use mayfly_server::clock::SystemClock;
use ssh_key::certificate::Certificate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test");
    let ca = CaManager::from_single_encrypted_file(
        &key_path,
        "mayfly-test-passphrase",
        "mayfly-ca",
        Arc::new(SystemClock),
    )
    .await?;

    println!("CA public key:\n{}", ca.primary_public_key()?);
    println!("Bundle fingerprint: {}", ca.bundle_fingerprint());

    // A throwaway subject key to be signed.
    let subject =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)?;
    let request = CertificateRequest {
        principal: "vasugarg".to_string(),
        hostname: "web-01".to_string(),
        public_key: subject.public_key().to_openssh()?,
        ttl_seconds: 300,
    };

    let response = ca.sign_certificate(&request).await?;
    println!("\n--- CertificateResponse ---");
    println!("{}", serde_json::to_string_pretty(&response)?);

    let cert = Certificate::from_openssh(&response.certificate)?;
    println!("\n--- Parsed certificate ---");
    println!("type:        {:?}", cert.cert_type());
    println!("principals:  {:?}", cert.valid_principals());
    println!("serial:      {}", cert.serial());
    println!("key_id:      {}", cert.key_id());
    println!(
        "extensions:  {:?}",
        cert.extensions().keys().collect::<Vec<_>>()
    );
    Ok(())
}
