use base64::prelude::*;
use hmac::{Hmac, Mac};
use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str::FromStr;
use thiserror::Error;

use crate::jwks::{Jwk, KeyParameters};

#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error("JWT is malformed")]
    JwtMalformed,
    #[error("Invalid base64")]
    InvalidBase64(base64::DecodeError),
    #[error("Invalid UTF-8")]
    InvalidUtf8(std::string::FromUtf8Error),
    #[error("Invalid header")]
    InvalidHeader,
    #[error("Failed to serialize payload")]
    SerializePayload,
    #[error("Failed to parse int")]
    ParseInt(std::num::ParseIntError),
    #[error("Algorithm not supported")]
    AlgorithmNotSupported,
    #[error("iss claim is missing or not a url")]
    IssClaimMissingOrNotUrl,
    #[error("kid header is missing")]
    KidHeaderMissing,
    #[error("Unable to match key with kid")]
    KidNotFound,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum Algorithm {
    HS256,
    RS256,
}

#[derive(Deserialize, Serialize)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub struct Signature {
    pub encoded: String,
    pub signature: Vec<u8>,
}

pub struct Jwt {
    pub encoded: String,
    pub header: Header,
    pub payload: serde_json::Value,
    pub signature: Signature,
}

type HmacSha256 = Hmac<Sha256>;

impl Jwt {
    pub fn try_get_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.payload.get(key)
    }

    pub fn verify_signature(&self, key: &str) -> bool {
        let mut parts = self.encoded.split('.');
        let header = parts.next().unwrap_or("");
        let payload = parts.next().unwrap_or("");

        let data = format!("{}.{}", header, payload);
        match self.header.alg {
            Algorithm::HS256 => {
                let mut mac = HmacSha256::new_from_slice(key.as_bytes())
                    .expect("HMAC can take key of any size");
                // let v_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
                // hmac::verify(&v_key, data.as_bytes(), self.signature.signature.as_slice()).is_ok()

                mac.update(data.as_bytes());
                mac.verify_slice(&self.signature.signature).is_ok()
            }
            _ => false,
        }
    }

    pub fn verify_signature_with_jwk(&self, jwk: Jwk) -> bool {
        match self.header.alg {
            Algorithm::RS256 => {
                if let Jwk {
                    params: KeyParameters::Rsa { n, e, .. },
                    ..
                } = jwk
                {
                    let n_decoded = BASE64_URL_SAFE_NO_PAD
                        .decode(n.as_bytes())
                        .expect("Failed to decode n");
                    let e_decoded = BASE64_URL_SAFE_NO_PAD
                        .decode(e.as_bytes())
                        .expect("Failed to decode e");

                    let public_key = RsaPublicKey::new(
                        BigUint::from_bytes_be(&n_decoded),
                        BigUint::from_bytes_be(&e_decoded),
                    )
                    .expect("Failed to create RSA public key");

                    let parts = self.encoded.splitn(3, '.');
                    let signing_input = parts.take(2).collect::<Vec<&str>>().join(".");

                    let sig = RsaSignature::try_from(self.signature.signature.as_slice());
                    let Ok(sig) = sig else { return false };

                    VerifyingKey::<Sha256>::new(public_key)
                        .verify(signing_input.as_bytes(), &sig)
                        .is_ok()
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl FromStr for Jwt {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            return Err(Error::JwtMalformed);
        }

        let (header, payload, signature) = (parts[0], parts[1], parts[2]);

        let decoded_header = BASE64_URL_SAFE_NO_PAD
            .decode(header.as_bytes())
            .map_err(Error::InvalidBase64)?;
        let header_str = String::from_utf8(decoded_header).map_err(Error::InvalidUtf8)?;
        let header: Header = serde_json::from_str(&header_str).map_err(|_| Error::InvalidHeader)?;

        let decoded_payload = BASE64_URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(Error::InvalidBase64)?;
        let payload_str = String::from_utf8(decoded_payload).map_err(Error::InvalidUtf8)?;
        let payload = serde_json::from_str(&payload_str).map_err(|_| Error::SerializePayload)?;

        let signature_decoded = BASE64_URL_SAFE_NO_PAD
            .decode(signature.as_bytes())
            .map_err(Error::InvalidBase64)?;

        let signature = Signature {
            encoded: signature.to_string(),
            signature: signature_decoded,
        };

        Ok(Jwt {
            encoded: s.to_string(),
            header,
            payload,
            signature,
        })
    }
}
