use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
	Result,
	config::ConfigOverrides,
	execute::execute_plan,
	plan::{DataKind, MigrationPlan, PlanRequest},
	store::ImportReport,
};

#[derive(Debug, Parser)]
#[command(name = "continuwuity-synapse-migrate", version, about)]
pub struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
	/// Discover Synapse inputs and print the resolved migration plan.
	Plan(MigrationArgs),

	/// Run an all-in Synapse migration. Use --dry-run to print the plan only.
	Migrate(MigrationArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
	Text,
	Json,
}

#[derive(Debug, Args)]
struct MigrationArgs {
	/// Synapse homeserver.yaml path. Can be passed more than once.
	#[arg(long = "synapse-config", value_name = "PATH")]
	synapse_configs: Vec<PathBuf>,

	/// Root directory to scan for homeserver.yaml candidates.
	#[arg(long = "synapse-root", value_name = "PATH")]
	synapse_roots: Vec<PathBuf>,

	/// Override Synapse SQLite database path.
	#[arg(long = "synapse-sqlite-db", value_name = "PATH")]
	synapse_sqlite_db: Option<PathBuf>,

	/// Override Synapse PostgreSQL database name.
	#[arg(long = "synapse-postgres-db", value_name = "NAME")]
	synapse_postgres_db: Option<String>,

	/// Override Synapse PostgreSQL host.
	#[arg(long = "synapse-postgres-host", value_name = "HOST")]
	synapse_postgres_host: Option<String>,

	/// Override Synapse PostgreSQL port.
	#[arg(long = "synapse-postgres-port", value_name = "PORT")]
	synapse_postgres_port: Option<u16>,

	/// Override Synapse PostgreSQL user.
	#[arg(long = "synapse-postgres-user", value_name = "USER")]
	synapse_postgres_user: Option<String>,

	/// Override Synapse PostgreSQL password.
	#[arg(long = "synapse-postgres-password", value_name = "PASSWORD")]
	synapse_postgres_password: Option<String>,

	/// Override Synapse PostgreSQL sslmode.
	#[arg(long = "synapse-postgres-sslmode", value_name = "SSLMODE")]
	synapse_postgres_sslmode: Option<String>,

	/// Override Synapse media_store_path.
	#[arg(long = "synapse-media-store", value_name = "PATH")]
	synapse_media_store: Option<PathBuf>,

	/// Override Synapse backup_media_store_path.
	#[arg(long = "synapse-backup-media-store", value_name = "PATH")]
	synapse_backup_media_store: Option<PathBuf>,

	/// Override Synapse signing_key_path.
	#[arg(long = "synapse-signing-key", value_name = "PATH")]
	synapse_signing_key: Option<PathBuf>,

	/// Override Synapse password_config.pepper for legacy bcrypt verification.
	#[arg(long = "synapse-password-pepper", value_name = "PEPPER")]
	synapse_password_pepper: Option<String>,

	/// Continuwuity config path. Can be passed more than once.
	#[arg(long = "continuwuity-config", short = 'c', value_name = "PATH")]
	continuwuity_configs: Vec<PathBuf>,

	/// Override destination continuwuity database_path.
	#[arg(long = "continuwuity-database", value_name = "PATH")]
	continuwuity_database: Option<PathBuf>,

	/// Migrate only these data kinds. Repeat for multiple kinds.
	#[arg(long, value_enum)]
	only: Vec<DataKind>,

	/// Skip these data kinds. Repeat for multiple kinds.
	#[arg(long, value_enum)]
	skip: Vec<DataKind>,

	/// Output format for plan and dry-run output.
	#[arg(long, value_enum, default_value = "text")]
	output: OutputFormat,

	/// Print the migration plan without writing anything.
	#[arg(long)]
	dry_run: bool,
}

impl Cli {
	pub fn run(self) -> Result<()> {
		match self.command {
			| Command::Plan(args) => args.print_plan(),
			| Command::Migrate(args) =>
				if args.dry_run {
					args.print_plan()
				} else {
					let plan = args.plan()?;
					let report = execute_plan(&plan)?;
					print_report(&report, args.output)
				},
		}
	}
}

impl MigrationArgs {
	fn plan(&self) -> Result<MigrationPlan> {
		MigrationPlan::build(PlanRequest {
			explicit_synapse_configs: self.synapse_configs.clone(),
			synapse_roots: self.synapse_roots.clone(),
			config_overrides: ConfigOverrides {
				sqlite_database: self.synapse_sqlite_db.clone(),
				postgres_database: self.synapse_postgres_db.clone(),
				postgres_host: self.synapse_postgres_host.clone(),
				postgres_port: self.synapse_postgres_port,
				postgres_user: self.synapse_postgres_user.clone(),
				postgres_password: self.synapse_postgres_password.clone(),
				postgres_sslmode: self.synapse_postgres_sslmode.clone(),
				media_store_path: self.synapse_media_store.clone(),
				backup_media_store_path: self.synapse_backup_media_store.clone(),
				signing_key_path: self.synapse_signing_key.clone(),
				password_pepper: self.synapse_password_pepper.clone(),
			},
			continuwuity_config_paths: self.continuwuity_configs.clone(),
			continuwuity_database_path: self.continuwuity_database.clone(),
			only: self.only.clone(),
			skip: self.skip.clone(),
		})
	}

	fn print_plan(&self) -> Result<()> {
		let plan = self.plan()?;
		print_plan(&plan, self.output)
	}
}

fn print_plan(plan: &MigrationPlan, output: OutputFormat) -> Result<()> {
	match output {
		| OutputFormat::Text => {
			print!("{}", plan.to_text());
			Ok(())
		},
		| OutputFormat::Json => {
			println!("{}", serde_json::to_string_pretty(plan)?);
			Ok(())
		},
	}
}

fn print_report(report: &ImportReport, output: OutputFormat) -> Result<()> {
	match output {
		| OutputFormat::Text => {
			println!("{}", report.to_text());
			for warning in &report.warnings {
				eprintln!("warning: {warning}");
			}
			Ok(())
		},
		| OutputFormat::Json => {
			println!("{}", serde_json::to_string_pretty(report)?);
			Ok(())
		},
	}
}
