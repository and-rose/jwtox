mod cli;
mod http_cache;
mod jwks;
mod jwt;

use chrono::DateTime;
use chrono_humanize::HumanTime;
use clap::{CommandFactory, Parser};
use colored::Colorize;
use jwt::{Error, Header, Jwt};
use reqwest::Client;
use std::io::BufRead;
use url::Url;

use cli::JWTOXArgs;
use http_cache::HttpCache;
use jwks::Jwks;

const JWT_ICON: char = '✻';

fn secs_str_to_date(secs: &str) -> Result<DateTime<chrono::Utc>, Error> {
    let millis = secs.parse::<i64>().map_err(Error::ParseInt)?;
    let date = DateTime::from_timestamp(millis, 0).expect("Failed to parse int");
    Ok(date)
}

#[inline]
fn title(s: &str) -> String {
    format!("{} {}", JWT_ICON, s)
}

fn print_header(header: &Header) {
    let header_json = serde_json::to_string_pretty(header).expect("Failed to serialize header");
    println!("\n{}", title("Header").bold().cyan());
    println!("{}", header_json.cyan());
}

fn print_payload(payload: &serde_json::Value) {
    let payload_json = serde_json::to_string_pretty(payload).expect("Failed to serialize payload");
    println!("\n{}", title("Payload").bold().yellow());
    println!("{}", payload_json.yellow());
}

fn print_signature(signature: &str, valid: Option<bool>) {
    match valid {
        Some(true) => println!("\n{}", title("Signature ✓").bold().magenta()),
        Some(false) => println!("\n{}", title("Signature ✗").bold().magenta()),
        None => println!("\n{}", title("Signature").bold().magenta()),
    }
    println!("{}", signature.magenta());
}

fn print_claim_dates(jwt: &Jwt, utc: bool) -> Result<(), Error> {
    for &claim_name in &["exp", "iat", "nbf"] {
        if let Some(claim_value) = jwt.try_get_claim(claim_name) {
            let date = secs_str_to_date(&claim_value.to_string())?;
            let claim_value = claim_value.to_string();

            if utc {
                println!(
                    "   {}: {} {}",
                    claim_name.yellow(),
                    claim_value.yellow(),
                    date
                );
            } else {
                println!(
                    "   {}: {} {}",
                    claim_name.yellow(),
                    claim_value.yellow(),
                    date.with_timezone(&chrono::Local)
                );
            }
        }
    }

    // log if token is expired
    if let Some(claim_value) = jwt.try_get_claim("exp") {
        let date = secs_str_to_date(&claim_value.to_string())?;
        let now = chrono::Utc::now();
        let duration = date - now;
        if duration.num_seconds() < 0 {
            println!(
                "   {} {}",
                "⚠️ Token expired".yellow(),
                HumanTime::from(duration).to_string().yellow()
            );
        } else {
            println!(
                "   {} {}",
                "Token expires".yellow(),
                HumanTime::from(duration).to_string().yellow()
            );
        }
    }

    Ok(())
}

fn read_from_stdin() -> String {
    let stdin = std::io::stdin();
    let handle = stdin.lock();
    let mut buffer = String::new();
    for line in handle.lines() {
        buffer.push_str(&line.expect("Failed to read line"));
    }
    buffer
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = JWTOXArgs::parse();

    let cache = HttpCache::new("jwtox", 3600)?;

    // Clear cache first if requested
    if args.clear_cache {
        cache.clear_all()?;
        println!("All cached responses cleared.");
        // If only clearing cache (no JWT provided, we're done
        if args.jwt_string.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Ok(());
        }
    }

    let jwt_string = if let Some(jwt_string) = args.jwt_string {
        // Directly use the provided JWT string
        jwt_string
    } else if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // Read from stdin if no JWT string is provided and not in a TTY
        read_from_stdin()
    } else {
        // If in a TTY and no JWT string is provided, print help and return an error
        let mut cmd = JWTOXArgs::command();
        cmd.print_help()?;
        return Ok(());
    };

    // Then, parse the JWT string into a Jwt struct
    let jwt: Jwt = jwt_string.parse()?;

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
        print_claim_dates(&jwt, args.utc)?;
    }

    if let Some(key_file) = args.key_file {
        // Check if the algorithm is HS256 and verify the signature
        if jwt.header.alg != jwt::Algorithm::HS256 {
            Err(Error::AlgorithmNotSupported)?;
        }

        let key = std::fs::read_to_string(key_file)?;

        let valid = jwt.verify_signature(&key);
        print_signature(&jwt.signature.encoded, Some(valid));
    } else if args.jwks {
        // check if the "iss" claim is present and is a string
        let iss = jwt
            .try_get_claim("iss")
            .and_then(|claim| claim.as_str())
            .and_then(|iss| Url::parse(iss).ok())
            .ok_or(Error::IssClaimMissingOrNotUrl)?;

        let kid = jwt.header.kid.as_ref().ok_or(Error::KidHeaderMissing)?;
        let alg = &jwt.header.alg;

        // Reach out to the authority specified in the "iss" claim using the JWKs endpoint
        let jwks_url = iss
            .join(".well-known/jwks.json")
            .expect("Failed to join URL");
        let client = Client::new();

        let jwks_response = if args.no_cache {
            client
                .get(jwks_url)
                .send()
                .await?
                .error_for_status()?
                .json::<Jwks>()
                .await?
        } else {
            cache.get_or_fetch(&client, &jwks_url).await?
        };

        // Find the key in the JWKs that matches the "kid" header
        let jwk = jwks_response
            .keys
            .into_iter()
            .find(|jwk| jwk.kid.as_ref() == Some(kid))
            .ok_or(Error::KidNotFound)?;

        if jwk.alg.as_ref() != Some(alg) {
            Err(Error::AlgorithmNotSupported)?;
        }

        let verified = jwt.verify_signature_with_jwk(jwk);

        print_signature(&jwt.signature.encoded, Some(verified));
    } else {
        print_signature(&jwt.signature.encoded, None);
    }

    Ok(())
}
