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
    #[clap(long = "header-only", short = 'H', conflicts_with_all = ["payload_only", "signature_only"])]
    pub header_only: bool,

    /// Only print the payload as JSON
    #[clap(long = "payload-only", short = 'P', conflicts_with_all = ["header_only", "signature_only"])]
    pub payload_only: bool,

    /// pretty print the output instead of compact JSON (only applies when printing header and/or payload)
    #[clap(long = "pretty", short = 'p', requires_all = ["header_only", "payload_only"])]
    pub pretty: bool,

    /// Only print the signature as a base64 string
    #[clap(long = "signature-only", short = 'S', conflicts_with_all = ["header_only", "payload_only"])]
    pub signature_only: bool,

    /// Print dates in UTC instead of local time
    #[clap(long = "utc", short = 'u')]
    pub utc: bool,

    /// Extract a single, top-level claim from the payload
    #[clap(long = "field", short = 'f')]
    pub field: Option<String>,

    /// The key to use for signature verification
    #[clap(long = "key-file", short = 'k')]
    pub key_file: Option<String>,

    /// Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint
    #[clap(long = "verify-jwks", short = 'v', conflicts_with = "key_file")]
    pub jwks: bool,

    #[clap(long = "no-cache", short = 'C', conflicts_with = "clear_cache")]
    pub no_cache: bool,

    #[clap(long = "clear-cache", short = 'X', conflicts_with = "no_cache")]
    pub clear_cache: bool,
}
