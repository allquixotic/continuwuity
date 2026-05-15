use std::{
	collections::BTreeSet,
	fmt::Write,
	path::{Path, PathBuf},
};

use clap::ValueEnum;
use serde::Serialize;

use crate::{
	Error, Result,
	config::{ConfigOverrides, SynapseDatabase, SynapseInstall},
	discover::{ConfigCandidate, DiscoveryInput, discover_configs},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum DataKind {
	Users,
	Profiles,
	Devices,
	AccessTokens,
	AccountData,
	Media,
	RoomEvents,
	RoomState,
	Receipts,
	Pushers,
	Appservices,
	SigningKey,
	ServerKeys,
}

#[derive(Clone, Debug, Serialize)]
pub struct MigrationPlan {
	pub synapse: SynapseInstall,
	pub continuwuity_config_paths: Vec<PathBuf>,
	pub continuwuity_database_path: Option<PathBuf>,
	pub selected_data: Vec<DataKind>,
	pub candidates: Vec<ConfigCandidate>,
	pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PlanRequest {
	pub explicit_synapse_configs: Vec<PathBuf>,
	pub synapse_roots: Vec<PathBuf>,
	pub config_overrides: ConfigOverrides,
	pub continuwuity_config_paths: Vec<PathBuf>,
	pub continuwuity_database_path: Option<PathBuf>,
	pub only: Vec<DataKind>,
	pub skip: Vec<DataKind>,
}

impl MigrationPlan {
	pub fn build(request: PlanRequest) -> Result<Self> {
		let input = DiscoveryInput::from_process(
			request.explicit_synapse_configs.clone(),
			request.synapse_roots.clone(),
		);
		Self::build_with_discovery(request, &input)
	}

	pub fn build_with_discovery(request: PlanRequest, input: &DiscoveryInput) -> Result<Self> {
		let candidates = discover_configs(input);
		let config_path = candidates
			.iter()
			.find(|candidate| candidate.exists)
			.map(|candidate| candidate.path.clone())
			.ok_or(Error::MissingSynapseConfig)?;

		let synapse = SynapseInstall::load(&config_path, &request.config_overrides)?;
		let selected_data = selected_data(&request.only, &request.skip);
		let warnings = warnings(&synapse, &selected_data);

		Ok(Self {
			synapse,
			continuwuity_config_paths: request.continuwuity_config_paths,
			continuwuity_database_path: request.continuwuity_database_path,
			selected_data,
			candidates,
			warnings,
		})
	}

	pub fn to_text(&self) -> String {
		let mut out = String::new();
		let _ = writeln!(out, "Synapse migration plan");
		let _ = writeln!(out, "  Synapse config: {}", display(&self.synapse.config_path));
		if let Some(server_name) = &self.synapse.server_name {
			let _ = writeln!(out, "  Server name: {server_name}");
		}
		let _ = writeln!(out, "  Database: {}", database_summary(&self.synapse.database));
		if let Some(path) = &self.synapse.media_store_path {
			let _ = writeln!(out, "  Media store: {}", display(path));
		}
		if let Some(path) = &self.synapse.signing_key_path {
			let _ = writeln!(out, "  Signing key: {}", display(path));
		} else if self.synapse.signing_key.is_some() {
			let _ = writeln!(out, "  Signing key: inline");
		}
		if let Some(path) = &self.continuwuity_database_path {
			let _ = writeln!(out, "  Continuwuity database: {}", display(path));
		}
		let selected = self
			.selected_data
			.iter()
			.map(DataKind::as_str)
			.collect::<Vec<_>>()
			.join(", ");
		let _ = writeln!(out, "  Selected data: {selected}");
		if !self.warnings.is_empty() {
			let _ = writeln!(out, "Warnings:");
			for warning in &self.warnings {
				let _ = writeln!(out, "  - {warning}");
			}
		}
		out
	}
}

impl DataKind {
	fn as_str(&self) -> &'static str {
		match self {
			| Self::Users => "users",
			| Self::Profiles => "profiles",
			| Self::Devices => "devices",
			| Self::AccessTokens => "access-tokens",
			| Self::AccountData => "account-data",
			| Self::Media => "media",
			| Self::RoomEvents => "room-events",
			| Self::RoomState => "room-state",
			| Self::Receipts => "receipts",
			| Self::Pushers => "pushers",
			| Self::Appservices => "appservices",
			| Self::SigningKey => "signing-key",
			| Self::ServerKeys => "server-keys",
		}
	}
}

pub fn all_data_kinds() -> Vec<DataKind> {
	vec![
		DataKind::Users,
		DataKind::Profiles,
		DataKind::Devices,
		DataKind::AccessTokens,
		DataKind::AccountData,
		DataKind::Media,
		DataKind::RoomEvents,
		DataKind::RoomState,
		DataKind::Receipts,
		DataKind::Pushers,
		DataKind::Appservices,
		DataKind::SigningKey,
		DataKind::ServerKeys,
	]
}

fn selected_data(only: &[DataKind], skip: &[DataKind]) -> Vec<DataKind> {
	let mut selected = if only.is_empty() {
		all_data_kinds().into_iter().collect::<BTreeSet<_>>()
	} else {
		only.iter().copied().collect::<BTreeSet<_>>()
	};

	for skipped in skip {
		selected.remove(skipped);
	}

	selected.into_iter().collect()
}

fn warnings(synapse: &SynapseInstall, selected_data: &[DataKind]) -> Vec<String> {
	let mut warnings = Vec::new();

	if matches!(synapse.database, SynapseDatabase::Postgres { .. }) {
		warnings.push(
			"PostgreSQL source detected; provide explicit credentials or a service file when running import"
				.to_owned(),
		);
	}

	if selected_data.contains(&DataKind::Media) && synapse.media_store_path.is_none() {
		warnings.push("media selected but Synapse media_store_path was not found".to_owned());
	}

	if selected_data.contains(&DataKind::SigningKey)
		&& synapse.signing_key_path.is_none()
		&& synapse.signing_key.is_none()
	{
		warnings.push("signing-key selected but no Synapse signing key was found".to_owned());
	}

	if synapse.password_pepper.is_some() {
		warnings.push(
			"Synapse password pepper will be embedded in migrated legacy password hash markers"
				.to_owned(),
		);
	}

	warnings
}

fn database_summary(database: &SynapseDatabase) -> String {
	match database {
		| SynapseDatabase::Sqlite { path } => format!("sqlite {}", display(path)),
		| SynapseDatabase::Postgres { database, host, port, user, .. } => {
			let database = database.as_deref().unwrap_or("<unspecified>");
			let host = host.as_deref().unwrap_or("<default>");
			let user = user.as_deref().unwrap_or("<default>");
			let port = port.map_or_else(|| "<default>".to_owned(), |port| port.to_string());
			format!("postgres database={database} host={host} port={port} user={user}")
		},
		| SynapseDatabase::Other { name, .. } => format!("{name}"),
	}
}

fn display(path: &Path) -> String {
	path.display().to_string()
}

#[cfg(test)]
mod tests {
	use std::{collections::HashMap, io::Write};

	use tempfile::NamedTempFile;

	use super::*;

	#[test]
	fn plan_selects_existing_candidate_and_applies_scope() {
		let mut file = NamedTempFile::new().expect("temp file");
		write!(
			file,
			r#"
server_name: example.com
database:
  name: sqlite3
  args:
    database: homeserver.db
"#
		)
		.expect("write config");

		let request = PlanRequest {
			explicit_synapse_configs: vec![file.path().to_owned()],
			only: vec![DataKind::Users, DataKind::Media],
			skip: vec![DataKind::Media],
			..PlanRequest::default()
		};
		let input = DiscoveryInput {
			explicit_configs: request.explicit_synapse_configs.clone(),
			roots: Vec::new(),
			cwd: "/unused".into(),
			env: HashMap::new(),
		};

		let plan = MigrationPlan::build_with_discovery(request, &input).expect("plan");

		assert_eq!(plan.synapse.server_name.as_deref(), Some("example.com"));
		assert_eq!(plan.selected_data, vec![DataKind::Users]);
		assert!(plan.to_text().contains("Synapse migration plan"));
	}
}
