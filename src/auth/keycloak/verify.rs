//! JWT verification with strict algorithm pinning (no alg-confusion).

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use crate::auth::provider::AuthProviderError;

use super::claims::KeycloakClaims;
use super::config::KeycloakProviderConfig;
use super::oidc::OidcDiscovery;

/// Verify a Keycloak access token (JWT) and return its claims.
///
/// Steps: decode the header → resolve the signing key by `kid` → **pin the
/// algorithm to the JWK's key type** (asymmetric only; `HS*`/`none` rejected, so
/// an attacker cannot downgrade to an HMAC the server would verify with public
/// key bytes) → verify the signature and validate `iss` (against the discovery
/// issuer), `aud` (when configured), and `exp`/`nbf` with clock-skew leeway.
pub fn verify_access_token(
    token: &str,
    jwk: &Jwk,
    discovery: &OidcDiscovery,
    config: &KeycloakProviderConfig,
) -> Result<KeycloakClaims, AuthProviderError> {
    let header = decode_header(token).map_err(|e| AuthProviderError::Decode(e.to_string()))?;

    let expected_alg = algorithm_for_jwk(jwk)?;
    if header.alg != expected_alg {
        // The token's declared algorithm must match the key's algorithm; this
        // closes algorithm-confusion (e.g. an RSA public key abused as an HMAC
        // secret, or a key substituted for a different family).
        return Err(AuthProviderError::Unauthorized);
    }

    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|e| AuthProviderError::Decode(e.to_string()))?;

    let mut validation = Validation::new(expected_alg);
    validation.algorithms = vec![expected_alg];
    validation.set_issuer(std::slice::from_ref(&discovery.issuer));
    match &config.audience {
        Some(aud) => validation.set_audience(std::slice::from_ref(aud)),
        None => validation.validate_aud = false,
    }
    validation.leeway = config.clock_skew_secs;
    validation.validate_nbf = true;

    decode::<KeycloakClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(map_jwt_error)
}

/// Map a JWK to its (asymmetric) signing algorithm, rejecting symmetric/none.
fn algorithm_for_jwk(jwk: &Jwk) -> Result<Algorithm, AuthProviderError> {
    // Prefer the key's declared algorithm when present.
    if let Some(key_alg) = jwk.common.key_algorithm {
        return key_algorithm_to_algorithm(key_alg);
    }
    // Otherwise infer a safe default from the key family.
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(_) => Ok(Algorithm::ES256),
        // Octet (HMAC) and OKP keys are not accepted for access-token signing.
        _ => Err(AuthProviderError::Unauthorized),
    }
}

/// Convert a JWK `alg` to a verification [`Algorithm`], allowing only the
/// asymmetric families Mayfly accepts for OIDC access tokens.
fn key_algorithm_to_algorithm(alg: KeyAlgorithm) -> Result<Algorithm, AuthProviderError> {
    match alg {
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        // HS256/384/512 (and anything else) are rejected explicitly.
        _ => Err(AuthProviderError::Unauthorized),
    }
}

/// Map a `jsonwebtoken` error to a coarse provider error. Token-rejection causes
/// (bad signature, expired, wrong issuer/audience) become `Unauthorized`;
/// structural problems become `Decode`.
fn map_jwt_error(err: jsonwebtoken::errors::Error) -> AuthProviderError {
    match err.kind() {
        ErrorKind::InvalidSignature
        | ErrorKind::ExpiredSignature
        | ErrorKind::ImmatureSignature
        | ErrorKind::InvalidIssuer
        | ErrorKind::InvalidAudience
        | ErrorKind::InvalidAlgorithm
        | ErrorKind::MissingRequiredClaim(_) => AuthProviderError::Unauthorized,
        _ => AuthProviderError::Decode(err.to_string()),
    }
}
