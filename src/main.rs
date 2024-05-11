use base64::prelude::*;
use chrono::DateTime;
use clap::Parser;
use colored::Colorize;
use hmac::{digest, Hmac, Mac};
use sha2::Sha256;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// There was no header section found in the token.
    HeaderNotFound,
    /// There was no payload section found in the token.
    PayloadNotFound,
    /// There was no signature section found in the token.
    SignatureNotFound,
    /// There was more than 3 sections found in the token.
    TooManySections,
    /// The encoded bytes is not valid base64
    InvalidBase64(base64::DecodeError),
    /// The byte string is not valid utf-8, but it should be.
    InvalidUtf8(std::string::FromUtf8Error),
    /// The header is not in a valid format.
    InvalidHeader,
    /// The length of the secret is invalid.
    HashSecret(digest::InvalidLength),
    /// An error occured while deserializing or serializing the payload.
    SerializePayload,
    /// An error occured while parsing an integer.
    ParseIntError(std::num::ParseIntError),
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct JWTOXArgs {
    /// The JWT token to decode
    jwt_string: String,

    /// Do not calculate the dates for iat, exp, and nbf
    #[clap(long = "no-calc", short = 'c')]
    no_calc: bool,

    /// No color output
    #[clap(long = "no-color", short = 'n')]
    no_color: bool,

    /// Only print the header as JSON
    #[clap(long = "header-only", short = 'H', conflicts_with = "payload_only")]
    header_only: bool,

    /// Only print the payload as JSON
    #[clap(long = "payload-only", short = 'p', conflicts_with = "header_only")]
    payload_only: bool,

    /// The secret to use for signature verification
    #[clap(long = "secret", short = 's')]
    secret: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum Algorithm {
    HS256,
    RS256,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Header {
    alg: Algorithm,
    typ: String,
}

struct Jwt {
    encoded: String,
    header: Header,
    payload: serde_json::Value,
    signature: String,
}

impl Jwt {
    fn try_get_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.payload.get(key)
    }

    fn verify_signature(&self, secret: &str) -> bool {
        let mut parts = self.encoded.split('.');
        let header = parts.next().expect("Header not found");
        let payload = parts.next().expect("Payload not found");

        let data = format!("{}.{}", header, payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());

        let signature = BASE64_URL_SAFE_NO_PAD
            .decode(self.signature.as_bytes())
            .expect("Failed to decode signature");

        let bytes = mac.finalize();
        let result = &bytes.into_bytes()[..];

        result == signature
    }
}

impl FromStr for Jwt {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('.');
        let header = parts.next().ok_or(Error::HeaderNotFound)?;
        let payload = parts.next().ok_or(Error::PayloadNotFound)?;
        let signature = parts.next().ok_or(Error::SignatureNotFound)?;

        if parts.next().is_some() {
            return Err(Error::TooManySections);
        }

        let header = BASE64_URL_SAFE_NO_PAD
            .decode(header.as_bytes())
            .map_err(Error::InvalidBase64)?;

        let header = String::from_utf8(header).map_err(Error::InvalidUtf8)?;

        let header: Header = serde_json::from_str(&header).map_err(|_| Error::InvalidHeader)?;

        let payload = BASE64_URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(Error::InvalidBase64)?;

        let payload = String::from_utf8(payload).map_err(Error::InvalidUtf8)?;

        let payload = serde_json::from_str(&payload).map_err(|_| Error::SerializePayload)?;

        Ok(Jwt {
            encoded: s.to_string(),
            header,
            payload,
            signature: signature.to_string(),
        })
    }
}

fn secs_str_to_date(secs: &str) -> Result<DateTime<chrono::Utc>, Error> {
    let millis = secs.parse::<i64>().map_err(Error::ParseIntError)?;
    let date = DateTime::from_timestamp(millis, 0).expect("Failed to parse int");
    Ok(date)
}

fn print_header(header: &Header) {
    let header_json = serde_json::to_string_pretty(header).expect("Failed to serialize header");
    println!("\n{}", "* Header".bold().cyan());
    println!("{}", header_json.cyan());
}

fn print_payload(payload: &serde_json::Value) {
    let payload_json = serde_json::to_string_pretty(payload).expect("Failed to serialize payload");
    println!("\n{}", "* Payload".bold().yellow());
    println!("{}", payload_json.yellow());
}

fn print_signature(signature: &str, valid: Option<bool>) {
    match valid {
        Some(true) => println!("\n{}", "* Signature ✓".bold().magenta()),
        Some(false) => println!("\n{}", "* Signature ✗".bold().magenta()),
        None => println!("\n{}", "* Signature".bold().magenta()),
    }
    println!("{}", signature.magenta());
}

fn print_claim_dates(jwt: &Jwt) -> Result<(), Error> {
    for &claim_name in &["exp", "iat", "nbf"] {
        if let Some(claim_value) = jwt.try_get_claim(claim_name) {
            let date = secs_str_to_date(&claim_value.to_string())?;
            println!(
                "   {}: {} {}",
                claim_name.to_string().yellow(),
                claim_value.to_string().yellow(),
                date
            );
        }
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = JWTOXArgs::parse();

    let encoded_jwt = args.jwt_string;

    let jwt = encoded_jwt.parse::<Jwt>()?;

    if args.no_color {
        colored::control::set_override(false);
    }

    let header = serde_json::to_string_pretty(&jwt.header).expect("Failed to serialize header");
    let payload = serde_json::to_string_pretty(&jwt.payload).expect("Failed to serialize payload");

    if args.header_only {
        println!("{}", header);
        return Ok(());
    }

    if args.payload_only {
        println!("{}", payload);
        return Ok(());
    }

    print_header(&jwt.header);
    print_payload(&jwt.payload);

    if !args.no_calc {
        print_claim_dates(&jwt)?;
    }

    if let Some(secret) = args.secret {
        let valid = jwt.verify_signature(&secret);
        print_signature(&jwt.signature, Some(valid));
    } else {
        print_signature(&jwt.signature, None);
    }

    Ok(())
}
