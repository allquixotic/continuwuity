use std::{io, path::PathBuf};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("I/O error for {path:?}: {source}")]
	Io { path: PathBuf, source: io::Error },

	#[error("failed to parse YAML in {path:?}: {source}")]
	Yaml {
		path: PathBuf,
		source: serde_saphyr::Error,
	},

	#[error("failed to render JSON output: {0}")]
	Json(#[from] serde_json::Error),

	#[error("could not locate a Synapse homeserver.yaml; pass --synapse-config")]
	MissingSynapseConfig,

	#[error("Synapse config {0:?} does not contain database.name")]
	MissingDatabaseName(PathBuf),

	#[error("Synapse config {0:?} does not contain a usable SQLite database path")]
	MissingSqliteDatabase(PathBuf),

	#[error("{0}")]
	Message(String),
}

impl Error {
	pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
		Self::Io { path: path.into(), source }
	}
}
