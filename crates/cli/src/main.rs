use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

mod generate;

#[derive(Parser)]
#[command(name = "better-auth-rs", about = "CLI tools for better-auth-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the auth schema file with SeaORM entity definitions
    Generate {
        /// Write output to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate { output } => {
            let schema = generate::auth_schema();

            match output {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        if !parent.exists() {
                            if let Err(e) = fs::create_dir_all(parent) {
                                eprintln!("failed to create directory {}: {e}", parent.display());
                                process::exit(1);
                            }
                        }
                    }
                    if let Err(e) = fs::write(&path, schema) {
                        eprintln!("failed to write {}: {e}", path.display());
                        process::exit(1);
                    }
                    eprintln!("wrote auth schema to {}", path.display());
                }
                None => print!("{schema}"),
            }
        }
    }
}
