use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value;

pub struct JwtBuilder {
    claims: Value,
    extra_headers: Option<Header>,
    algorithm: Algorithm,
    key: Vec<u8>,
}

impl JwtBuilder {
    /// Create a new JWT builder with HS256 algorithm
    pub fn hs256(claims: Value, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            claims,
            algorithm: Algorithm::HS256,
            key: secret.into(),
            extra_headers: None,
        }
    }

    /// Create a new JWT builder with RS256 algorithm
    pub fn rs256(claims: Value, private_key: impl Into<Vec<u8>>) -> Self {
        Self {
            claims,
            algorithm: Algorithm::RS256,
            key: private_key.into(),
            extra_headers: None,
        }
    }

    /// Add multiple extra header fields from a JSON object
    /// Accepts json!({ "key": "value", ... }) or a HashMap
    pub fn with_headers(mut self, headers: Header) -> Self {
        self.extra_headers = Some(headers);
        self
    }

    /// Build and encode the JWT
    pub fn build(self) -> String {
        let mut header = Header::new(self.algorithm);

        if let Some(extra) = self.extra_headers {
            header.cty = extra.cty;
            header.jku = extra.jku;
            header.jwk = extra.jwk;
            header.kid = extra.kid;
            header.x5u = extra.x5u;
            header.x5c = extra.x5c;
            header.x5t = extra.x5t;
            header.x5t_s256 = extra.x5t_s256;
            header.crit = extra.crit;
            header.enc = extra.enc;
            header.zip = extra.zip;
            header.url = extra.url;
            header.nonce = extra.nonce;
        }

        // Use the correct EncodingKey based on the algorithm
        let encoding_key = match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(&self.key)
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                EncodingKey::from_rsa_der(&self.key)
            }
            Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_der(&self.key),
            Algorithm::EdDSA => EncodingKey::from_ed_der(&self.key),
            _ => panic!("Unsupported algorithm"),
        };

        encode(&header, &self.claims, &encoding_key).unwrap()
    }
}
