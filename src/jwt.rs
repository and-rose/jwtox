use base64::prelude::*;
use ring::{hmac, signature};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

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
}

#[derive(Deserialize, Serialize)]
enum Algorithm {
    HS256,
    RS256,
}

#[derive(Deserialize, Serialize)]
pub struct Header {
    alg: Algorithm,
    typ: String,
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
                let v_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
                hmac::verify(&v_key, data.as_bytes(), self.signature.signature.as_slice()).is_ok()
            }
            Algorithm::RS256 => {
                // Put headers back on key
                let key = format!(
                    "-----BEGIN PRIVATE KEY-----\n {}\n-----END PRIVATE KEY -----",
                    key
                );
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    key.as_bytes(),
                );

                public_key
                    .verify(data.as_bytes(), self.signature.signature.as_slice())
                    .is_ok()
            }
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
