use std::{
	collections::BTreeMap,
	fs,
	path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
	Error, Result,
	error::Error::{MissingDatabaseName, MissingSqliteDatabase},
};

#[derive(Clone, Debug, Serialize)]
pub struct SynapseInstall {
	pub config_path: PathBuf,
	pub config_dir: PathBuf,
	pub server_name: Option<String>,
	pub database: SynapseDatabase,
	pub media_store_path: Option<PathBuf>,
	pub backup_media_store_path: Option<PathBuf>,
	pub signing_key_path: Option<PathBuf>,
	#[serde(skip_serializing)]
	pub signing_key: Option<String>,
	pub app_service_config_files: Vec<PathBuf>,
	pub registration_shared_secret_path: Option<PathBuf>,
	pub has_registration_shared_secret: bool,
	pub password_pepper: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SynapseDatabase {
	Sqlite {
		path: PathBuf,
	},
	Postgres {
		database: Option<String>,
		host: Option<String>,
		port: Option<u16>,
		user: Option<String>,
		password: Option<String>,
		sslmode: Option<String>,
		raw_args: BTreeMap<String, Value>,
	},
	Other {
		name: String,
		raw_args: BTreeMap<String, Value>,
	},
}

#[derive(Debug, Deserialize)]
struct RawSynapseConfig {
	server_name: Option<String>,
	database: Option<RawDatabase>,
	media_store_path: Option<PathBuf>,
	backup_media_store_path: Option<PathBuf>,
	signing_key_path: Option<PathBuf>,
	signing_key: Option<String>,
	app_service_config_files: Option<Vec<PathBuf>>,
	registration_shared_secret: Option<String>,
	registration_shared_secret_path: Option<PathBuf>,
	password_config: Option<RawPasswordConfig>,
}

#[derive(Debug, Deserialize)]
struct RawDatabase {
	name: Option<String>,
	#[serde(default)]
	args: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawPasswordConfig {
	pepper: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {
	pub sqlite_database: Option<PathBuf>,
	pub postgres_database: Option<String>,
	pub postgres_host: Option<String>,
	pub postgres_port: Option<u16>,
	pub postgres_user: Option<String>,
	pub postgres_password: Option<String>,
	pub postgres_sslmode: Option<String>,
	pub media_store_path: Option<PathBuf>,
	pub backup_media_store_path: Option<PathBuf>,
	pub signing_key_path: Option<PathBuf>,
	pub password_pepper: Option<String>,
}

impl SynapseInstall {
	pub fn load(path: impl AsRef<Path>, overrides: &ConfigOverrides) -> Result<Self> {
		let path = path.as_ref();
		let body = fs::read(path).map_err(|e| Error::io(path, e))?;
		let raw = serde_saphyr::from_slice::<RawSynapseConfig>(&body).map_err(|e| {
			Error::Yaml {
				path: path.to_owned(),
				source: e,
			}
		})?;

		Self::from_raw(path, raw, overrides)
	}

	fn from_raw(
		config_path: &Path,
		raw: RawSynapseConfig,
		overrides: &ConfigOverrides,
	) -> Result<Self> {
		let config_path = absolute(config_path)?;
		let config_dir = config_path
			.parent()
			.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
		let server_name = raw.server_name.clone();
		let signing_key = if overrides.signing_key_path.is_some() {
			None
		} else {
			raw.signing_key
		};
		let signing_key_path = if signing_key.is_some() {
			None
		} else {
			overrides
				.signing_key_path
				.clone()
				.or(raw.signing_key_path)
				.or_else(|| {
					server_name
						.as_ref()
						.map(|server_name| PathBuf::from(format!("{server_name}.signing.key")))
				})
				.map(|path| resolve_path(&config_dir, path))
		};

		let database = raw
			.database
			.as_ref()
			.map_or_else(
				|| Err(MissingDatabaseName(config_path.clone())),
				|database| database.resolve(&config_path, &config_dir, overrides),
			)?;

		Ok(Self {
			config_path,
			config_dir: config_dir.clone(),
			server_name: raw.server_name,
			database,
			media_store_path: overrides
				.media_store_path
				.clone()
				.or(raw.media_store_path)
				.map(|path| resolve_path(&config_dir, path)),
			backup_media_store_path: overrides
				.backup_media_store_path
				.clone()
				.or(raw.backup_media_store_path)
				.map(|path| resolve_path(&config_dir, path)),
			signing_key_path,
			signing_key,
			app_service_config_files: raw
				.app_service_config_files
				.unwrap_or_default()
				.into_iter()
				.map(|path| resolve_path(&config_dir, path))
				.collect(),
			registration_shared_secret_path: raw
				.registration_shared_secret_path
				.map(|path| resolve_path(&config_dir, path)),
			has_registration_shared_secret: raw.registration_shared_secret.is_some(),
			password_pepper: overrides
				.password_pepper
				.clone()
				.or_else(|| raw.password_config.and_then(|password| password.pepper)),
		})
	}
}

impl RawDatabase {
	fn resolve(
		&self,
		config_path: &Path,
		config_dir: &Path,
		overrides: &ConfigOverrides,
	) -> Result<SynapseDatabase> {
		let name = self
			.name
			.clone()
			.ok_or_else(|| MissingDatabaseName(config_path.to_owned()))?;

		match name.as_str() {
			| "sqlite3" => {
				let path = overrides
					.sqlite_database
					.clone()
					.or_else(|| path_arg(&self.args, "database"))
					.ok_or_else(|| MissingSqliteDatabase(config_path.to_owned()))?;

				Ok(SynapseDatabase::Sqlite {
					path: resolve_path(config_dir, path),
				})
			},
			| "psycopg2" => Ok(SynapseDatabase::Postgres {
				database: overrides
					.postgres_database
					.clone()
					.or_else(|| string_arg(&self.args, "database"))
					.or_else(|| string_arg(&self.args, "dbname")),
				host: overrides.postgres_host.clone().or_else(|| string_arg(&self.args, "host")),
				port: overrides.postgres_port.or_else(|| u16_arg(&self.args, "port")),
				user: overrides.postgres_user.clone().or_else(|| string_arg(&self.args, "user")),
				password: overrides
					.postgres_password
					.clone()
					.or_else(|| string_arg(&self.args, "password")),
				sslmode: overrides
					.postgres_sslmode
					.clone()
					.or_else(|| string_arg(&self.args, "sslmode")),
				raw_args: self.args.clone(),
			}),
			| _ => Ok(SynapseDatabase::Other {
				name,
				raw_args: self.args.clone(),
			}),
		}
	}
}

fn string_arg(args: &BTreeMap<String, Value>, key: &str) -> Option<String> {
	args.get(key).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn path_arg(args: &BTreeMap<String, Value>, key: &str) -> Option<PathBuf> {
	string_arg(args, key).map(PathBuf::from)
}

fn u16_arg(args: &BTreeMap<String, Value>, key: &str) -> Option<u16> {
	args.get(key)
		.and_then(Value::as_u64)
		.and_then(|value| u16::try_from(value).ok())
}

pub fn resolve_path(base: &Path, path: PathBuf) -> PathBuf {
	if path.is_absolute() {
		path
	} else {
		base.join(path)
	}
}

fn absolute(path: &Path) -> Result<PathBuf> {
	if path.is_absolute() {
		Ok(path.to_owned())
	} else {
		std::env::current_dir()
			.map(|cwd| cwd.join(path))
			.map_err(|e| Error::io(path, e))
	}
}

#[cfg(test)]
mod tests {
	use std::io::Write;

	use tempfile::NamedTempFile;

	use super::*;

	#[test]
	fn parses_sqlite_synapse_config_with_relative_paths() {
		let mut file = NamedTempFile::new().expect("temp file");
		write!(
			file,
			r#"
server_name: example.com
database:
  name: sqlite3
  args:
    database: homeserver.db
media_store_path: media_store
signing_key_path: example.com.signing.key
app_service_config_files:
  - bridges/appservice.yaml
password_config:
  pepper: "pepper"
"#
		)
		.expect("write config");

		let install = SynapseInstall::load(file.path(), &ConfigOverrides::default())
			.expect("synapse install");
		let config_dir = file.path().parent().expect("config dir");

		assert_eq!(install.server_name.as_deref(), Some("example.com"));
		assert_eq!(
			install.database,
			SynapseDatabase::Sqlite {
				path: config_dir.join("homeserver.db"),
			}
		);
		assert_eq!(install.media_store_path, Some(config_dir.join("media_store")));
		assert_eq!(
			install.signing_key_path,
			Some(config_dir.join("example.com.signing.key"))
		);
		assert_eq!(
			install.app_service_config_files,
			vec![config_dir.join("bridges/appservice.yaml")]
		);
		assert_eq!(install.password_pepper.as_deref(), Some("pepper"));
	}

	#[test]
	fn override_sqlite_database_wins() {
		let mut file = NamedTempFile::new().expect("temp file");
		write!(
			file,
			r#"
database:
  name: sqlite3
  args:
    database: homeserver.db
"#
		)
		.expect("write config");

		let install = SynapseInstall::load(
			file.path(),
			&ConfigOverrides {
				sqlite_database: Some(PathBuf::from("/tmp/synapse.db")),
				..ConfigOverrides::default()
			},
		)
		.expect("synapse install");

		assert_eq!(
			install.database,
			SynapseDatabase::Sqlite {
				path: PathBuf::from("/tmp/synapse.db"),
			}
		);
	}

	#[test]
	fn override_postgres_connection_wins() {
		let mut file = NamedTempFile::new().expect("temp file");
		write!(
			file,
			r#"
database:
  name: psycopg2
  args:
    database: synapse
    host: /var/run/postgresql
    port: 5432
    user: synapse
    password: yaml-secret
    sslmode: disable
"#
		)
		.expect("write config");

		let install = SynapseInstall::load(
			file.path(),
			&ConfigOverrides {
				postgres_database: Some("override_db".to_owned()),
				postgres_host: Some("db.example.com".to_owned()),
				postgres_port: Some(6543),
				postgres_user: Some("override_user".to_owned()),
				postgres_password: Some("override-secret".to_owned()),
				postgres_sslmode: Some("require".to_owned()),
				..ConfigOverrides::default()
			},
		)
		.expect("synapse install");

		assert_eq!(
			install.database,
			SynapseDatabase::Postgres {
				database: Some("override_db".to_owned()),
				host: Some("db.example.com".to_owned()),
				port: Some(6543),
				user: Some("override_user".to_owned()),
				password: Some("override-secret".to_owned()),
				sslmode: Some("require".to_owned()),
				raw_args: BTreeMap::from([
					("database".to_owned(), Value::String("synapse".to_owned())),
					("host".to_owned(), Value::String("/var/run/postgresql".to_owned())),
					("port".to_owned(), Value::from(5432)),
					("user".to_owned(), Value::String("synapse".to_owned())),
					("password".to_owned(), Value::String("yaml-secret".to_owned())),
					("sslmode".to_owned(), Value::String("disable".to_owned())),
				]),
			}
		);
	}
}
