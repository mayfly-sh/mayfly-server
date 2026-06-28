//! Version-specific canonicalization of a [`SignedBundle`] for signing.
//!
//! The Bundle Signing Key signs **these bytes**, never the serialized response
//! JSON (which is not canonical: key order, whitespace, unicode escaping, and
//! number formatting all vary by serializer). Instead we define one explicit,
//! deterministic byte layout per bundle version and produce it identically on
//! both the server (signing) and the agent (verifying).
//!
//! ## v1 layout (stable forever)
//!
//! A single-line JSON document with members emitted in a fixed (alphabetical)
//! order, keys sorted by `key_id`, and every string escaped by
//! [`json_escape_into`]. Encoded as UTF-8. The exact, byte-for-byte layout is:
//!
//! ```text
//! {"bundle_version":<u32>,"created_at":"<rfc3339>","expires_at":"<rfc3339>",\
//! "fingerprint":"<sha256:...>","generation":<u32>,\
//! "keys":[{"key_id":"<id>","public_key":"<openssh>"},...]}
//! ```
//!
//! This mirrors the agent's `canonical_signing_payload` byte-for-byte (see
//! `mayfly-agent/src/protocol/ca_bundle.rs`). The `bundle_version` field binds
//! the signature to the schema version, giving downgrade/cross-version
//! protection. Note that the signature algorithm and the signing key itself are
//! deliberately *not* part of the signed bytes (they are part of the envelope
//! and gated before verification), matching the agent.

use crate::bundle::models::{BundleError, BundleKey, BUNDLE_VERSION};

/// Inputs to the canonical message. Borrowed so callers can build the bytes
/// without cloning the bundle.
pub struct CanonicalInput<'a> {
    /// Schema version (must be [`BUNDLE_VERSION`]).
    pub bundle_version: u32,
    /// Monotonic generation.
    pub generation: u32,
    /// RFC 3339 creation instant (verbatim from the bundle).
    pub created_at: &'a str,
    /// RFC 3339 expiry instant (verbatim from the bundle).
    pub expires_at: &'a str,
    /// Content fingerprint.
    pub fingerprint: &'a str,
    /// Enabled CA keys. Need not be pre-sorted; the canonicalizer sorts.
    pub keys: &'a [BundleKey],
}

/// Produce the canonical signing bytes for the given version, dispatching to
/// the version-specific layout. Unknown versions fail closed.
pub fn canonical_message(input: &CanonicalInput<'_>) -> Result<Vec<u8>, BundleError> {
    if input.bundle_version != BUNDLE_VERSION {
        return Err(BundleError::UnsupportedVersion(
            input.bundle_version.to_string(),
        ));
    }
    Ok(canonical_v1(input).into_bytes())
}

/// The v1 canonical byte layout (see module docs). Strings are JSON-escaped, so
/// no field can inject the document's structural characters.
fn canonical_v1(input: &CanonicalInput<'_>) -> String {
    let mut sorted: Vec<&BundleKey> = input.keys.iter().collect();
    sorted.sort_by(|a, b| a.key_id.cmp(&b.key_id));

    let mut out = String::with_capacity(128 + input.keys.len() * 96);
    out.push_str("{\"bundle_version\":");
    out.push_str(&input.bundle_version.to_string());
    out.push_str(",\"created_at\":\"");
    json_escape_into(input.created_at, &mut out);
    out.push_str("\",\"expires_at\":\"");
    json_escape_into(input.expires_at, &mut out);
    out.push_str("\",\"fingerprint\":\"");
    json_escape_into(input.fingerprint, &mut out);
    out.push_str("\",\"generation\":");
    out.push_str(&input.generation.to_string());
    out.push_str(",\"keys\":");
    append_keys_array(&sorted, &mut out);
    out.push('}');
    out
}

/// Append `[{"key_id":..,"public_key":..},..]` for already-sorted keys.
fn append_keys_array(sorted: &[&BundleKey], out: &mut String) {
    out.push('[');
    for (i, key) in sorted.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"key_id\":\"");
        json_escape_into(&key.key_id, out);
        out.push_str("\",\"public_key\":\"");
        json_escape_into(&key.public_key, out);
        out.push_str("\"}");
    }
    out.push(']');
}

/// Append `s` to `out`, escaped as a JSON string body (no surrounding quotes).
///
/// This matches `serde_json`'s escaping (and the agent's `json_escape_into`)
/// for the inputs a bundle carries: control characters use the short escapes
/// where defined and `\u00XX` (lowercase hex) otherwise.
fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
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
            keys,
        }
    }

    /// GOLDEN: the exact bytes the server signs for a known bundle. This literal
    /// is shared verbatim with the agent's
    /// `canonical_signing_payload_layout_is_exact_and_stable` test, proving both
    /// repositories canonicalize the same bundle to identical bytes.
    #[test]
    fn golden_layout_is_exact_and_matches_agent() {
        let keys = [key("ca-01", "ssh-ed25519 AAAA")];
        let bytes = canonical_message(&CanonicalInput {
            bundle_version: 1,
            generation: 42,
            created_at: "2026-01-01T00:00:00Z",
            expires_at: "2026-02-01T00:00:00Z",
            fingerprint: "sha256:ab",
            keys: &keys,
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"bundle_version\":1,\"created_at\":\"2026-01-01T00:00:00Z\",\
\"expires_at\":\"2026-02-01T00:00:00Z\",\"fingerprint\":\"sha256:ab\",\
\"generation\":42,\"keys\":[{\"key_id\":\"ca-01\",\"public_key\":\"ssh-ed25519 AAAA\"}]}"
        );
    }

    #[test]
    fn multiple_keys_are_sorted_by_key_id() {
        let keys = [
            key("ca-02", "ssh-ed25519 BBBB"),
            key("ca-01", "ssh-ed25519 AAAA"),
        ];
        let bytes = canonical_message(&input(&keys)).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"bundle_version\":1,\"created_at\":\"2026-06-29T00:00:00Z\",\
\"expires_at\":\"2026-06-29T01:00:00Z\",\"fingerprint\":\"sha256:abc\",\
\"generation\":42,\"keys\":[{\"key_id\":\"ca-01\",\"public_key\":\"ssh-ed25519 AAAA\"},\
{\"key_id\":\"ca-02\",\"public_key\":\"ssh-ed25519 BBBB\"}]}"
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
        bad.bundle_version = 2;
        assert!(matches!(
            canonical_message(&bad),
            Err(BundleError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn structural_characters_in_values_are_escaped() {
        // A value containing a quote/backslash/newline must be escaped, not able
        // to alter the document structure.
        let keys = [key("ca\"\\\n01", "ssh-ed25519 AAAA")];
        let bytes = canonical_message(&input(&keys)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\\\"\\\\\\n01"));
    }
}
