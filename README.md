# JWTOX

A fast and simple command-line tool for decoding and verifying JSON Web Tokens (JWTs).

## Features

- Decode JWT headers and payloads
- Verify JWT signatures (HS256, RS256, ES256, and more)
- Automatic JWKS endpoint verification
- Human-readable timestamp conversion (iat, exp, nbf)
- Colorized output for better readability
- Built with Rust for speed and reliability

## Installation

### Quick Install (Recommended)

The easiest way to install jwtox is using the install script:

```bash
curl -sSL https://raw.githubusercontent.com/and-rose/jwtox/main/install.sh | bash
```

This will:

- Download the latest release for your platform
- Install the binary to `~/.local/bin/jwtox`
- Set up shell completions (if applicable)

Make sure `~/.local/bin` is in your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc  # or ~/.zshrc
```

### Build from Source

If you prefer to build from source, you'll need [Rust](https://rustup.rs/) installed.

1. Clone the repository:

```bash
git clone https://github.com/and-rose/jwtox.git
cd jwtox
```

2. Build the project:

```bash
cargo build --release
```

3. The binary will be available at `./target/release/jwtox`. You can copy it to
   a directory in your PATH:

```bash
cp ./target/release/jwtox ~/.local/bin/
```

## Usage

### Basic Usage

Decode a JWT token:

```bash
jwtox eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Or read from stdin:

```bash
echo "your.jwt.token" | jwtox
```

### Command-Line Options

| Option              | Short | Description                                                 |
| ------------------- | ----- | ----------------------------------------------------------- |
| `--no-calc`         | `-c`  | Skip calculating human-readable dates for iat, exp, and nbf |
| `--no-color`        | `-n`  | Disable colorized output                                    |
| `--header-only`     | `-H`  | Only print the JWT header                                   |
| `--payload-only`    | `-p`  | Only print the JWT payload                                  |
| `--utc`             | `-u`  | Display dates in UTC instead of local time                  |
| `--key-file <FILE>` | `-k`  | Verify signature using a key file                           |
| `--verify-jwks`     | `-v`  | Verify signature using the issuer's JWKS endpoint           |
| `--no-cache`        | `-C`  | Disable caching of JWKS responses                           |
| `--clear-cache`     | `-X`  | Clear the JWKS cache                                        |
| `--help`            | `-h`  | Display help information                                    |
| `--version`         | `-V`  | Display version information                                 |

### Examples

**Decode only the header:**

```bash
jwtox -H your.jwt.token
```

**Decode only the payload:**

```bash
jwtox -p your.jwt.token
```

**Verify signature with JWKS:**

```bash
jwtox -v your.jwt.token
```

**Verify signature with a key file:**

```bash
jwtox -k secret.key your.jwt.token
```

**Display dates in UTC:**

```bash
jwtox -u your.jwt.token
```

**Plain output without colors:**

```bash
jwtox -n your.jwt.token
```

## Shell Completions

The install script automatically sets up shell completions if your shell's
completion directory exists. Completion files are also available in the
`contrib/completions/` directory for manual installation:

- **Bash**: `contrib/completions/jwtox.bash`
- **Zsh**: `contrib/completions/_jwtox`
- **Fish**: `contrib/completions/jwtox.fish`
- **PowerShell**: `contrib/completions/_jwtox.ps1`
- **Elvish**: `contrib/completions/jwtox.elv`
