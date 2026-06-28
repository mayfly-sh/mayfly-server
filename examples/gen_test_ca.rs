//! Generate the encrypted Ed25519 test CA key fixture used by the CA tests.
//!
//! Run once to (re)create `testdata/ca_test` and `testdata/ca_test.pub`:
//!
//! ```sh
//! cargo run --example gen_test_ca
//! ```
//!
//! The fixture is generated purely with the `ssh-key` crate (no `ssh-keygen`).
//! The passphrase below is only for tests and is intentionally committed.

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

const PASSPHRASE: &str = "mayfly-test-passphrase";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let encrypted = key.encrypt(&mut OsRng, PASSPHRASE)?;

    std::fs::create_dir_all("testdata")?;
    std::fs::write(
        "testdata/ca_test",
        encrypted.to_openssh(LineEnding::LF)?.as_bytes(),
    )?;
    std::fs::write(
        "testdata/ca_test.pub",
        encrypted.public_key().to_openssh()?.as_bytes(),
    )?;

    println!("wrote testdata/ca_test and testdata/ca_test.pub");
    Ok(())
}
