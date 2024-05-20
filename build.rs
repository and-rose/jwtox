#[path = "src/cli.rs"]
mod cli;

use clap::CommandFactory;
use clap_complete::generate_to;
use clap_complete::shells::{Bash, Elvish, Fish, PowerShell, Zsh};
use cli::JWTOXArgs;
use std::{env, io};

fn main() -> io::Result<()> {
    // Since we are generating completions in the package directory, we need to
    // set this so that Cargo doesn't rebuild every time.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=tests/");
    generate_completions()
}

fn generate_completions() -> io::Result<()> {
    const BIN_NAME: &str = env!("CARGO_PKG_NAME");
    const OUT_DIR: &str = "contrib/completions";
    let cmd = &mut JWTOXArgs::command();

    generate_to(Bash, cmd, BIN_NAME, OUT_DIR)?;
    generate_to(Elvish, cmd, BIN_NAME, OUT_DIR)?;
    generate_to(Fish, cmd, BIN_NAME, OUT_DIR)?;
    generate_to(PowerShell, cmd, BIN_NAME, OUT_DIR)?;
    generate_to(Zsh, cmd, BIN_NAME, OUT_DIR)?;

    Ok(())
}
