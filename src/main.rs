mod cli;
mod jwt;

use chrono::DateTime;
use clap::{CommandFactory, Parser};
use colored::Colorize;
use jwt::{Error, Header, Jwt};
use std::io::BufRead;

use cli::JWTOXArgs;

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

fn main() -> anyhow::Result<()> {
    let args = JWTOXArgs::parse();

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

    if let Some(key) = args.key {
        // Check if the algorithm is HS256 and verify the signature
        if jwt.header.alg != jwt::Algorithm::HS256 {
            Err(Error::AlgorithmNotSupported)?;
        }
        let valid = jwt.verify_signature(&key);
        print_signature(&jwt.signature.encoded, Some(valid));
    } else {
        print_signature(&jwt.signature.encoded, None);
    }

    Ok(())
}
