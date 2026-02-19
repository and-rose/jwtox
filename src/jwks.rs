use serde::{Deserialize, Serialize};

use crate::jwt;
use jwt::Algorithm;

/// The key type enum holds type-specific key parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum KeyParameters {
    /// RSA keys (e.g., for RS256)
    #[serde(rename = "RSA")]
    Rsa {
        n: String, // Base64URL modulus
        e: String, // Base64URL exponent
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<String>, // Base64URL private exponent
    },
    /// EC keys (e.g., for ES256)
    #[serde(rename = "EC")]
    Ec {
        crv: String,
        x: String,
        y: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<String>,
    },
}

/// The JWK with both common and type-specific fields
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(flatten)]
    pub params: KeyParameters,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Algorithm>,
    // Add other common fields or extensions as needed
}

/// JWK Set
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// OpenID Connect Discovery Document
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfig {
    pub jwks_uri: String,
}
