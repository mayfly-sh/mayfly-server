//! Canonical-string construction and Ed25519 signature verification.
//!
//! This is the byte-for-byte definition of what an agent signs and what the
//! server verifies. The agent crate carries a mirror of [`canonical_string`]
//! and [`body_sha256_hex`]; the two MUST stay identical or every request will
//! fail to verify. The protocol is deliberately simple and explicit:
//!
//! ```text
//! <SIGNING_DOMAIN>\n
//! <machine_id>\n
//! <timestamp>\n          (Unix seconds, decimal)
//! <nonce>\n              (opaque, e.g. 32 lowercase hex chars)
//! <method>\n             (HTTP method, uppercase)
//! <path>\n               (request path, no query string)
//! <body_sha256>          (lowercase hex SHA-256 of the raw body)
//! ```
//!
//! The leading [`SIGNING_DOMAIN`] label is domain separation: it ensures a
//! signature produced for this protocol can never be replayed as a valid
//! signature in any other context that happens to sign the same fields.
//!
//! Signatures are raw Ed25519 over the UTF-8 bytes of the canonical string,
//! transported as standard (padded) Base64 in the `X-Mayfly-Signature` header.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};
use ssh_key::PublicKey;

/// Domain-separation label and protocol version, prepended to every canonical
/// string. Bump the suffix to invalidate all previously-issued signatures.
pub const SIGNING_DOMAIN: &str = "mayfly-agent-auth-v1";

/// Header carrying the machine identifier.
pub const HEADER_MACHINE_ID: &str = "x-mayfly-machine-id";
/// Header carrying the Unix-seconds timestamp.
pub const HEADER_TIMESTAMP: &str = "x-mayfly-timestamp";
/// Header carrying the per-request nonce.
pub const HEADER_NONCE: &str = "x-mayfly-nonce";
/// Header carrying the Base64-encoded Ed25519 signature.
pub const HEADER_SIGNATURE: &str = "x-mayfly-signature";

/// Lowercase hex SHA-256 of a request body (`""` hashes the empty input).
pub fn body_sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Build the canonical string that is signed by the agent and verified by the
/// server. See the module docs for the exact layout.
pub fn canonical_string(
    machine_id: &str,
    timestamp: i64,
    nonce: &str,
    method: &str,
    path: &str,
    body_hash_hex: &str,
) -> String {
    format!(
        "{SIGNING_DOMAIN}\n{machine_id}\n{timestamp}\n{nonce}\n{method}\n{path}\n{body_hash_hex}"
    )
}

/// Why a signature failed to verify. Every variant maps to `401 Unauthorized`
/// at the HTTP layer; the distinction exists for tests and structured logging,
/// never to tell a client *why* (which would aid forgery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The stored public key is not a parseable OpenSSH key.
    MalformedPublicKey,
    /// The stored public key is not an Ed25519 key.
    NotEd25519,
    /// The signature header was not valid Base64 or not 64 bytes.
    MalformedSignature,
    /// The signature did not verify against the canonical string.
    Invalid,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::MalformedPublicKey => "malformed public key",
            Self::NotEd25519 => "public key is not ed25519",
            Self::MalformedSignature => "malformed signature",
            Self::Invalid => "signature verification failed",
        };
        f.write_str(msg)
    }
}

/// Parse an OpenSSH Ed25519 public key into a dalek [`VerifyingKey`].
fn verifying_key(public_key_openssh: &str) -> Result<VerifyingKey, SignatureError> {
    let key = PublicKey::from_openssh(public_key_openssh)
        .map_err(|_| SignatureError::MalformedPublicKey)?;
    let ed = key.key_data().ed25519().ok_or(SignatureError::NotEd25519)?;
    VerifyingKey::from_bytes(&ed.0).map_err(|_| SignatureError::MalformedPublicKey)
}

/// Verify a Base64 Ed25519 `signature` over `canonical` using the machine's
/// stored OpenSSH public key.
///
/// Uses [`VerifyingKey::verify_strict`], which rejects signatures under
/// small-order / non-canonical public keys, closing Ed25519 malleability gaps.
/// Ed25519 verification is itself the constant-time comparison primitive here;
/// no separate byte comparison of the signature is performed (or needed).
pub fn verify_signature(
    public_key_openssh: &str,
    canonical: &str,
    signature_b64: &str,
) -> Result<(), SignatureError> {
    let key = verifying_key(public_key_openssh)?;

    let raw = BASE64
        .decode(signature_b64.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let bytes: [u8; SIGNATURE_LENGTH] = raw
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let signature = Signature::from_bytes(&bytes);

    key.verify_strict(canonical.as_bytes(), &signature)
        .map_err(|_| SignatureError::Invalid)
}

/// Sign a canonical string with a raw 32-byte Ed25519 seed, returning the
/// standard-Base64 signature for the `X-Mayfly-Signature` header.
///
/// The server never signs in production; this is the reference signer used by
/// tests and tooling that act as an agent, and it guarantees the server's
/// verifier is exercised against the exact bytes a real agent would produce.
pub fn sign_canonical(seed: &[u8; 32], canonical: &str) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(seed);
    let signature = signing_key.sign(canonical.as_bytes());
    BASE64.encode(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Build an OpenSSH public key string for a dalek signing key, mirroring
    /// what `ssh-keygen`/the agent would emit.
    fn openssh_public(seed: &[u8; 32]) -> String {
        let signing = SigningKey::from_bytes(seed);
        let verifying = signing.verifying_key();
        let key_data = ssh_key::public::Ed25519PublicKey(verifying.to_bytes());
        ssh_key::PublicKey::from(ssh_key::public::KeyData::Ed25519(key_data))
            .to_openssh()
            .expect("openssh encode")
    }

    fn canonical() -> String {
        canonical_string(
            "srv_abc",
            1_700_000_000,
            "0123456789abcdef0123456789abcdef",
            "POST",
            "/api/v1/agent/heartbeat",
            &body_sha256_hex(b"{}"),
        )
    }

    #[test]
    fn body_hash_matches_known_vector() {
        // SHA-256 of the empty string.
        assert_eq!(
            body_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn canonical_string_layout_is_exact() {
        let c = canonical_string("m", 5, "n", "POST", "/p", "deadbeef");
        assert_eq!(c, "mayfly-agent-auth-v1\nm\n5\nn\nPOST\n/p\ndeadbeef");
        assert_eq!(c.lines().count(), 7);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let seed = [7u8; 32];
        let pubkey = openssh_public(&seed);
        let c = canonical();
        let sig = sign_canonical(&seed, &c);
        assert!(verify_signature(&pubkey, &c, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_canonical() {
        let seed = [7u8; 32];
        let pubkey = openssh_public(&seed);
        let sig = sign_canonical(&seed, &canonical());
        let tampered = canonical_string(
            "srv_abc",
            1_700_000_000,
            "0123456789abcdef0123456789abcdef",
            "POST",
            "/api/v1/agent/heartbeat",
            &body_sha256_hex(b"{\"evil\":true}"),
        );
        assert_eq!(
            verify_signature(&pubkey, &tampered, &sig),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer_seed = [7u8; 32];
        let other_pubkey = openssh_public(&[9u8; 32]);
        let c = canonical();
        let sig = sign_canonical(&signer_seed, &c);
        assert_eq!(
            verify_signature(&other_pubkey, &c, &sig),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let pubkey = openssh_public(&[7u8; 32]);
        assert_eq!(
            verify_signature(&pubkey, &canonical(), "not-base64-!!!"),
            Err(SignatureError::MalformedSignature)
        );
        assert_eq!(
            verify_signature(&pubkey, &canonical(), "QUJD"),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn verify_rejects_malformed_public_key() {
        assert_eq!(
            verify_signature("not a key", &canonical(), "QUJD"),
            Err(SignatureError::MalformedPublicKey)
        );
    }

    #[test]
    fn verify_rejects_non_ed25519_key() {
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDExample test";
        // Either malformed (not parseable) or not-ed25519 is acceptable; both
        // are hard failures.
        assert!(verify_signature(rsa, &canonical(), "QUJD").is_err());
    }
}
