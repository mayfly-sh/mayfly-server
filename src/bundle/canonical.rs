//! Version-specific canonicalization of a [`SignedBundle`] for signing.
//!
//! The Bundle Signing Key signs **these bytes**, never serialized JSON. JSON is
//! not canonical (key order, whitespace, unicode escaping, and number
//! formatting all vary by serializer), so signing it would make verification
//! brittle and, worse, ambiguous. Instead we define one explicit byte layout
//! per bundle version and use it on both sides.
//!
//! ## v1 layout
//!
//! A newline-delimited, domain-separated record. Every signed field appears
//! exactly once, in a fixed order, followed by the key list sorted by `key_id`:
//!
//! ```text
//! mayfly-ca-bundle-v1\n
//! generation:<u32>\n
//! created_at:<rfc3339>\n
//! expires_at:<rfc3339>\n
//! fingerprint:<sha256:...>\n
//! algorithm:<ed25519>\n
//! keys:\n
//! <key_id>\t<public_key>\n      (repeated, sorted by key_id)
//! ```
//!
//! The leading domain label doubles as the version tag: it changes whenever the
//! layout changes, so a signature for one version can never verify under
//! another (downgrade/cross-version protection).
//!
//! Field values are safe to place inline without escaping: `generation` is an
//! integer; `created_at`/`expires_at` are RFC 3339; `fingerprint` is
//! `sha256:<hex>`; `key_id` is validated to printable identifier characters
//! (no tabs/newlines); and OpenSSH public keys are single-line base64 with a
//! type prefix. The canonicalizer still rejects values containing the field
//! delimiters (`\n`, `\t`) defensively, so a malformed input fails closed
//! rather than producing an ambiguous message.

use crate::bundle::models::{BundleError, BundleKey, BUNDLE_VERSION};

/// The v1 domain-separation label / version tag.
const V1_DOMAIN: &str = "mayfly-ca-bundle-v1";

/// Inputs to the canonical message. Borrowed so callers can build the bytes
/// without cloning the bundle.
pub struct CanonicalInput<'a> {
    /// Schema version (must be `v1`).
    pub bundle_version: &'a str,
    /// Monotonic generation.
    pub generation: u32,
    /// RFC 3339 creation instant (verbatim from the bundle).
    pub created_at: &'a str,
    /// RFC 3339 expiry instant (verbatim from the bundle).
    pub expires_at: &'a str,
    /// Content fingerprint.
    pub fingerprint: &'a str,
    /// Signature algorithm identifier.
    pub algorithm: &'a str,
    /// Enabled CA keys. Need not be pre-sorted; the canonicalizer sorts.
    pub keys: &'a [BundleKey],
}

/// Produce the canonical signing bytes for the given version, dispatching to
/// the version-specific layout. Unknown versions fail closed.
pub fn canonical_message(input: &CanonicalInput<'_>) -> Result<Vec<u8>, BundleError> {
    match input.bundle_version {
        BUNDLE_VERSION => canonical_v1(input),
        other => Err(BundleError::UnsupportedVersion(other.to_string())),
    }
}

/// The v1 canonical byte layout (see module docs). Fails closed on delimiter
/// injection in any field.
fn canonical_v1(input: &CanonicalInput<'_>) -> Result<Vec<u8>, BundleError> {
    fn safe(value: &str) -> Result<&str, BundleError> {
        if value.contains('\n') || value.contains('\t') {
            return Err(BundleError::Malformed(
                "canonical field contains a delimiter".to_string(),
            ));
        }
        Ok(value)
    }

    let mut out = String::with_capacity(256 + input.keys.len() * 96);
    out.push_str(V1_DOMAIN);
    out.push('\n');
    out.push_str("generation:");
    out.push_str(&input.generation.to_string());
    out.push('\n');
    out.push_str("created_at:");
    out.push_str(safe(input.created_at)?);
    out.push('\n');
    out.push_str("expires_at:");
    out.push_str(safe(input.expires_at)?);
    out.push('\n');
    out.push_str("fingerprint:");
    out.push_str(safe(input.fingerprint)?);
    out.push('\n');
    out.push_str("algorithm:");
    out.push_str(safe(input.algorithm)?);
    out.push('\n');
    out.push_str("keys:\n");

    // Sort by key_id for a stable, order-independent representation.
    let mut keys: Vec<&BundleKey> = input.keys.iter().collect();
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    for key in keys {
        out.push_str(safe(&key.key_id)?);
        out.push('\t');
        out.push_str(safe(&key.public_key)?);
        out.push('\n');
    }

    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, pk: &str) -> BundleKey {
        BundleKey {
            key_id: id.to_string(),
            public_key: pk.to_string(),
            fingerprint: format!("SHA256:{id}"),
        }
    }

    fn input<'a>(keys: &'a [BundleKey]) -> CanonicalInput<'a> {
        CanonicalInput {
            bundle_version: BUNDLE_VERSION,
            generation: 42,
            created_at: "2026-06-29T00:00:00Z",
            expires_at: "2026-06-29T01:00:00Z",
            fingerprint: "sha256:abc",
            algorithm: "ed25519",
            keys,
        }
    }

    #[test]
    fn layout_is_exact() {
        let keys = [key("ca-01", "ssh-ed25519 AAA")];
        let bytes = canonical_message(&input(&keys)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(
            text,
            "mayfly-ca-bundle-v1\n\
             generation:42\n\
             created_at:2026-06-29T00:00:00Z\n\
             expires_at:2026-06-29T01:00:00Z\n\
             fingerprint:sha256:abc\n\
             algorithm:ed25519\n\
             keys:\n\
             ca-01\tssh-ed25519 AAA\n"
        );
    }

    #[test]
    fn key_order_does_not_affect_output() {
        let ordered = [key("ca-01", "AAA"), key("ca-02", "BBB")];
        let shuffled = [key("ca-02", "BBB"), key("ca-01", "AAA")];
        assert_eq!(
            canonical_message(&input(&ordered)).unwrap(),
            canonical_message(&input(&shuffled)).unwrap()
        );
    }

    #[test]
    fn stable_across_repeated_calls() {
        let keys = [key("ca-01", "AAA"), key("ca-02", "BBB")];
        let a = canonical_message(&input(&keys)).unwrap();
        let b = canonical_message(&input(&keys)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_generation_changes_bytes() {
        let keys = [key("ca-01", "AAA")];
        let mut other = input(&keys);
        other.generation = 43;
        assert_ne!(
            canonical_message(&input(&keys)).unwrap(),
            canonical_message(&other).unwrap()
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let keys = [key("ca-01", "AAA")];
        let mut bad = input(&keys);
        bad.bundle_version = "v2";
        assert!(matches!(
            canonical_message(&bad),
            Err(BundleError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn delimiter_injection_fails_closed() {
        let keys = [key("ca\n01", "AAA")];
        assert!(matches!(
            canonical_message(&input(&keys)),
            Err(BundleError::Malformed(_))
        ));
    }
}
