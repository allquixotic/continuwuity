use std::process::ExitCode;

use clap::Parser;
use continuwuity_synapse_migration::cli::Cli;

fn main() -> ExitCode {
	match Cli::parse().run() {
		| Ok(()) => ExitCode::SUCCESS,
		| Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		},
	}
}
