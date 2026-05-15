use std::{
	collections::{BTreeSet, HashMap},
	env,
	path::{Path, PathBuf},
};

use serde::Serialize;

#[derive(Clone, Debug)]
pub struct DiscoveryInput {
	pub explicit_configs: Vec<PathBuf>,
	pub roots: Vec<PathBuf>,
	pub cwd: PathBuf,
	pub env: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigCandidate {
	pub path: PathBuf,
	pub source: CandidateSource,
	pub exists: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
	Explicit,
	Environment,
	Root,
	CurrentDirectory,
	System,
}

impl DiscoveryInput {
	pub fn from_process(explicit_configs: Vec<PathBuf>, roots: Vec<PathBuf>) -> Self {
		Self {
			explicit_configs,
			roots,
			cwd: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
			env: env::vars().collect(),
		}
	}
}

pub fn discover_configs(input: &DiscoveryInput) -> Vec<ConfigCandidate> {
	let mut seen = BTreeSet::new();
	let mut candidates = Vec::new();

	for path in &input.explicit_configs {
		push(&mut candidates, &mut seen, path.clone(), CandidateSource::Explicit);
	}

	if let Some(path) = input.env.get("SYNAPSE_CONFIG_PATH") {
		for path in env::split_paths(path) {
			push(&mut candidates, &mut seen, path, CandidateSource::Environment);
		}
	}

	if let Some(path) = input.env.get("SYNAPSE_CONFIG_DIR") {
		push(
			&mut candidates,
			&mut seen,
			Path::new(path).join("homeserver.yaml"),
			CandidateSource::Environment,
		);
	}

	for root in &input.roots {
		for relative in ["homeserver.yaml", "data/homeserver.yaml", "config/homeserver.yaml"] {
			push(
				&mut candidates,
				&mut seen,
				root.join(relative),
				CandidateSource::Root,
			);
		}
	}

	push(
		&mut candidates,
		&mut seen,
		input.cwd.join("homeserver.yaml"),
		CandidateSource::CurrentDirectory,
	);

	for path in [
		"/etc/matrix-synapse/homeserver.yaml",
		"/etc/synapse/homeserver.yaml",
		"/data/homeserver.yaml",
	] {
		push(&mut candidates, &mut seen, path.into(), CandidateSource::System);
	}

	candidates
}

fn push(
	candidates: &mut Vec<ConfigCandidate>,
	seen: &mut BTreeSet<PathBuf>,
	path: PathBuf,
	source: CandidateSource,
) {
	if seen.insert(path.clone()) {
		candidates.push(ConfigCandidate {
			exists: path.exists(),
			path,
			source,
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn explicit_paths_are_first_and_deduplicated() {
		let input = DiscoveryInput {
			explicit_configs: vec!["/a/homeserver.yaml".into(), "/a/homeserver.yaml".into()],
			roots: vec!["/root".into()],
			cwd: "/cwd".into(),
			env: HashMap::new(),
		};

		let candidates = discover_configs(&input);

		assert_eq!(candidates[0].path, PathBuf::from("/a/homeserver.yaml"));
		assert_eq!(candidates[0].source, CandidateSource::Explicit);
		assert_eq!(
			candidates
				.iter()
				.filter(|candidate| candidate.path == PathBuf::from("/a/homeserver.yaml"))
				.count(),
			1
		);
	}

	#[test]
	fn environment_config_dir_adds_homeserver_yaml() {
		let input = DiscoveryInput {
			explicit_configs: Vec::new(),
			roots: Vec::new(),
			cwd: "/cwd".into(),
			env: HashMap::from([("SYNAPSE_CONFIG_DIR".to_owned(), "/synapse".to_owned())]),
		};

		let candidates = discover_configs(&input);

		assert!(candidates.iter().any(|candidate| {
			candidate.path == PathBuf::from("/synapse/homeserver.yaml")
				&& candidate.source == CandidateSource::Environment
		}));
	}
}
