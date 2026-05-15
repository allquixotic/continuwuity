use std::{
	collections::BTreeSet,
	path::{Path, PathBuf},
};

use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::Value;

use crate::{Error, Result};

pub struct SqliteSource {
	path: PathBuf,
	conn: Connection,
}

#[derive(Clone, Debug)]
pub struct SynapseUser {
	pub name: String,
	pub password_hash: Option<String>,
	pub deactivated: bool,
	pub admin: bool,
	pub appservice_id: Option<String>,
	pub user_type: Option<String>,
	pub shadow_banned: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseProfile {
	pub user_id: String,
	pub displayname: Option<String>,
	pub avatar_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDevice {
	pub user_id: String,
	pub device_id: String,
	pub display_name: Option<String>,
	pub last_seen: Option<i64>,
	pub ip: Option<String>,
	pub hidden: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseAccessToken {
	pub user_id: String,
	pub device_id: Option<String>,
	pub token: String,
	pub valid_until_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseAccountData {
	pub user_id: String,
	pub room_id: Option<String>,
	pub event_type: String,
	pub content: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseMedia {
	pub mxc_server: String,
	pub media_id: String,
	pub filesystem_id: String,
	pub content_type: Option<String>,
	pub upload_name: Option<String>,
	pub user_id: Option<String>,
	pub source_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomEvent {
	pub event_id: String,
	pub room_id: String,
	pub stream_ordering: i64,
	pub json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomState {
	pub event_id: String,
	pub room_id: String,
	pub event_type: String,
	pub state_key: String,
	pub membership: Option<String>,
	pub stream_ordering: Option<i64>,
	pub json: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct SynapseReceipt {
	pub stream_id: i64,
	pub room_id: String,
	pub receipt_type: String,
	pub user_id: String,
	pub event_id: String,
	pub thread_id: Option<String>,
	pub event_stream_ordering: Option<i64>,
	pub data: Value,
}

impl SqliteSource {
	pub fn open(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref().to_owned();
		let conn = Connection::open_with_flags(
			&path,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
				| rusqlite::OpenFlags::SQLITE_OPEN_URI
				| rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
		)
		.map_err(|e| Error::sqlite(&path, e))?;

		Ok(Self { path, conn })
	}

	pub fn users(&self) -> Result<Vec<SynapseUser>> {
		if !self.table_exists("users")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT name, password_hash, deactivated, admin, appservice_id, user_type,
				       COALESCE(shadow_banned, 0)
				FROM users
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;

		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUser {
					name: row.get(0)?,
					password_hash: row.get(1)?,
					deactivated: int_bool(row, 2)?,
					admin: int_bool(row, 3)?,
					appservice_id: row.get(4)?,
					user_type: row.get(5)?,
					shadow_banned: int_bool(row, 6)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn profiles(&self, server_name: Option<&str>) -> Result<Vec<SynapseProfile>> {
		if !self.table_exists("profiles")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("profiles")?;
		let has_full_user_id = columns.contains("full_user_id");
		let query = if has_full_user_id {
			"SELECT user_id, full_user_id, displayname, avatar_url FROM profiles"
		} else {
			"SELECT user_id, NULL, displayname, avatar_url FROM profiles"
		};

		let mut stmt = self
			.conn
			.prepare(query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let user_id: String = row.get::<_, Option<String>>(1)?.unwrap_or_else(|| {
					let localpart = row.get::<_, String>(0).unwrap_or_default();
					full_user_id(&localpart, server_name).unwrap_or(localpart)
				});

				Ok(SynapseProfile {
					user_id,
					displayname: row.get(2)?,
					avatar_url: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn devices(&self) -> Result<Vec<SynapseDevice>> {
		if !self.table_exists("devices")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"SELECT user_id, device_id, display_name, last_seen, ip, COALESCE(hidden, 0) FROM devices",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDevice {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					display_name: row.get(2)?,
					last_seen: row.get(3)?,
					ip: row.get(4)?,
					hidden: int_bool(row, 5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn access_tokens(&self) -> Result<Vec<SynapseAccessToken>> {
		if !self.table_exists("access_tokens")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare("SELECT user_id, device_id, token, valid_until_ms FROM access_tokens")
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseAccessToken {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					token: row.get(2)?,
					valid_until_ms: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn account_data(&self) -> Result<Vec<SynapseAccountData>> {
		let mut rows = Vec::new();
		if self.table_exists("account_data")? {
			rows.extend(self.account_data_from_table("account_data", false)?);
		}
		if self.table_exists("room_account_data")? {
			rows.extend(self.account_data_from_table("room_account_data", true)?);
		}

		Ok(rows)
	}

	pub fn media(&self, media_store: &Path, server_name: &str) -> Result<Vec<SynapseMedia>> {
		let mut media = Vec::new();

		if self.table_exists("local_media_repository")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT media_id, media_type, upload_name, user_id
					FROM local_media_repository
					WHERE COALESCE(url_cache, '') = ''
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					let media_id: String = row.get(0)?;
					Ok(SynapseMedia {
						mxc_server: server_name.to_owned(),
						filesystem_id: media_id.clone(),
						source_path: local_media_path(media_store, &media_id),
						media_id,
						content_type: row.get(1)?,
						upload_name: row.get(2)?,
						user_id: row.get(3)?,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			media.extend(collect_rows(&self.path, rows)?);
		}

		if self.table_exists("remote_media_cache")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT media_origin, media_id, media_type, upload_name,
					       COALESCE(filesystem_id, media_id)
					FROM remote_media_cache
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					let media_origin: String = row.get(0)?;
					let media_id: String = row.get(1)?;
					let filesystem_id: String = row.get(4)?;
					Ok(SynapseMedia {
						source_path: remote_media_path(
							media_store,
							&media_origin,
							&filesystem_id,
						),
						mxc_server: media_origin,
						media_id,
						filesystem_id,
						content_type: row.get(2)?,
						upload_name: row.get(3)?,
						user_id: None,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			media.extend(collect_rows(&self.path, rows)?);
		}

		Ok(media)
	}

	pub fn room_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT e.event_id, e.room_id, e.stream_ordering, ej.json
				FROM events e
				JOIN event_json ej ON e.event_id = ej.event_id
				WHERE COALESCE(e.outlier, 0) = 0
				  AND e.rejection_reason IS NULL
				ORDER BY e.stream_ordering ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let json: String = row.get(3)?;
				Ok(SynapseRoomEvent {
					event_id: row.get(0)?,
					room_id: row.get(1)?,
					stream_ordering: row.get(2)?,
					json: serde_json::from_str(&json).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_state(&self) -> Result<Vec<SynapseRoomState>> {
		if !self.table_exists("current_state_events")? {
			return Ok(Vec::new());
		}

		let has_events = self.table_exists("events")?;
		let has_event_json = self.table_exists("event_json")?;
		let stream_ordering = if has_events { "e.stream_ordering" } else { "NULL" };
		let event_json = if has_event_json { "ej.json" } else { "NULL" };
		let event_join = if has_events {
			"LEFT JOIN events e ON e.event_id = cse.event_id"
		} else {
			""
		};
		let json_join = if has_event_json {
			"LEFT JOIN event_json ej ON ej.event_id = cse.event_id"
		} else {
			""
		};
		let query = format!(
			"
			SELECT cse.event_id, cse.room_id, cse.type, cse.state_key, cse.membership,
			       {stream_ordering}, {event_json}
			FROM current_state_events cse
			{event_join}
			{json_join}
			ORDER BY cse.room_id, cse.type, cse.state_key
			"
		);

		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let json: Option<String> = row.get(6)?;
				Ok(SynapseRoomState {
					event_id: row.get(0)?,
					room_id: row.get(1)?,
					event_type: row.get(2)?,
					state_key: row.get(3)?,
					membership: row.get(4)?,
					stream_ordering: row.get(5)?,
					json: json.and_then(|json| serde_json::from_str(&json).ok()),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn receipts(&self) -> Result<Vec<SynapseReceipt>> {
		if !self.table_exists("receipts_linearized")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, room_id, receipt_type, user_id, event_id, thread_id,
				       event_stream_ordering, data
				FROM receipts_linearized
				WHERE receipt_type IN ('m.read', 'm.read.private')
				ORDER BY stream_id ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let data: String = row.get(7)?;
				Ok(SynapseReceipt {
					stream_id: row.get(0)?,
					room_id: row.get(1)?,
					receipt_type: row.get(2)?,
					user_id: row.get(3)?,
					event_id: row.get(4)?,
					thread_id: row.get(5)?,
					event_stream_ordering: row.get(6)?,
					data: serde_json::from_str(&data).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	fn account_data_from_table(
		&self,
		table: &str,
		room_scoped: bool,
	) -> Result<Vec<SynapseAccountData>> {
		let query = if room_scoped {
			format!("SELECT user_id, room_id, account_data_type, content FROM {table}")
		} else {
			format!("SELECT user_id, NULL, account_data_type, content FROM {table}")
		};

		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let content: String = row.get(3)?;
				Ok(SynapseAccountData {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
					event_type: row.get(2)?,
					content: serde_json::from_str(&content).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	fn table_exists(&self, table: &str) -> Result<bool> {
		self.conn
			.query_row(
				"SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
				[table],
				|row| row.get::<_, i64>(0),
			)
			.optional()
			.map(|value| value.is_some())
			.map_err(|e| Error::sqlite(&self.path, e))
	}

	fn columns(&self, table: &str) -> Result<BTreeSet<String>> {
		let mut stmt = self
			.conn
			.prepare(&format!("PRAGMA table_info({table})"))
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| row.get::<_, String>(1))
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows).map(|rows| rows.into_iter().collect())
	}
}

fn collect_rows<T>(
	path: &Path,
	rows: impl Iterator<Item = rusqlite::Result<T>>,
) -> Result<Vec<T>> {
	rows.collect::<rusqlite::Result<Vec<_>>>()
		.map_err(|e| Error::sqlite(path, e))
}

fn int_bool(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
	row.get::<_, Option<i64>>(index)
		.map(|value| value.unwrap_or_default() != 0)
}

fn full_user_id(user_id: &str, server_name: Option<&str>) -> Option<String> {
	if user_id.starts_with('@') {
		Some(user_id.to_owned())
	} else {
		server_name.map(|server_name| format!("@{user_id}:{server_name}"))
	}
}

fn local_media_path(media_store: &Path, media_id: &str) -> PathBuf {
	media_store
		.join("local_content")
		.join(slice(media_id, 0, 2))
		.join(slice(media_id, 2, 4))
		.join(slice(media_id, 4, media_id.len()))
}

fn remote_media_path(media_store: &Path, server_name: &str, filesystem_id: &str) -> PathBuf {
	media_store
		.join("remote_content")
		.join(server_name)
		.join(slice(filesystem_id, 0, 2))
		.join(slice(filesystem_id, 2, 4))
		.join(slice(filesystem_id, 4, filesystem_id.len()))
}

fn slice(value: &str, start: usize, end: usize) -> &str {
	value.get(start..end).unwrap_or_default()
}
