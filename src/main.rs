mod jwt;

use chrono::DateTime;
use clap::Parser;
use colored::Colorize;
use jwt::{Error, Header, Jwt};

const JWT_ICON: char = '✻';

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
        print_signature(&jwt.signature.encoded, Some(valid));
    } else {
        print_signature(&jwt.signature.encoded, None);
    }

    Ok(())
}
