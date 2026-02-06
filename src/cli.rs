use clap::Parser;
/// A simple JWT decoder
/// Supports decoding the header, payload, and signature of a JWT token.
/// Also supports verifying the signature for the HS256 algorithm.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct JWTOXArgs {
    /// The JWT token to decode.
    /// If not provided, it will be read from stdin.
    #[clap(name = "JWT")]
    pub jwt_string: Option<String>,

    /// Do not calculate the dates for iat, exp, and nbf
    #[clap(long = "no-calc", short = 'c')]
    pub no_calc: bool,

    /// No color output
    #[clap(long = "no-color", short = 'n')]
    pub no_color: bool,

    /// Only print the header as JSON
    #[clap(long = "header-only", short = 'H', conflicts_with = "payload_only")]
    pub header_only: bool,

    /// Only print the payload as JSON
    #[clap(long = "payload-only", short = 'p', conflicts_with = "header_only")]
    pub payload_only: bool,

    /// Print dates in UTC instead of local time
    #[clap(long = "utc", short = 'u')]
    pub utc: bool,

    /// The key to use for signature verification
    #[clap(long = "key", short = 'k')]
    pub key: Option<String>,

    /// Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint
    #[clap(long = "verify-jwks", short = 'v', conflicts_with = "key")]
    pub jwks: bool,
}
