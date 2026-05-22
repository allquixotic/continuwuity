use std::{
	collections::{BTreeMap, BTreeSet},
	path::{Path, PathBuf},
};

use rusqlite::{Connection, OptionalExtension, Row, types::ValueRef};
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
	pub locked: bool,
	pub suspended: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseErasedUser {
	pub user_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseAccountValidity {
	pub user_id: String,
	pub expiration_ts_ms: i64,
	pub email_sent: bool,
	pub renewal_token: Option<String>,
	pub token_used_ts_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseRatelimitOverride {
	pub user_id: String,
	pub messages_per_second: Option<i64>,
	pub burst_count: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseMonthlyActiveUser {
	pub user_id: String,
	pub timestamp: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseRegistrationToken {
	pub token: String,
	pub uses_allowed: Option<i64>,
	pub pending: i64,
	pub completed: i64,
	pub expiry_time: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseProfile {
	pub user_id: String,
	pub displayname: Option<String>,
	pub avatar_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseThreepid {
	pub user_id: String,
	pub medium: String,
	pub address: String,
	pub added_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseUserExternalId {
	pub auth_provider: String,
	pub external_id: String,
	pub user_id: String,
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
pub struct SynapseDeviceAuthProvider {
	pub user_id: String,
	pub device_id: String,
	pub auth_provider_id: String,
	pub auth_provider_session_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseDehydratedDevice {
	pub user_id: String,
	pub device_id: String,
	pub device_data: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceKey {
	pub user_id: String,
	pub device_id: String,
	pub key_json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseOneTimeKey {
	pub user_id: String,
	pub device_id: String,
	pub algorithm: String,
	pub key_id: String,
	pub key_json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseFallbackKey {
	pub user_id: String,
	pub device_id: String,
	pub algorithm: String,
	pub key_id: String,
	pub key_json: Value,
	pub used: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseCrossSigningKey {
	pub user_id: String,
	pub key_type: String,
	pub key_data: Value,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseKeySignature {
	pub user_id: String,
	pub key_id: String,
	pub target_user_id: String,
	pub target_device_id: String,
	pub signature: String,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomKeyBackupVersion {
	pub user_id: String,
	pub version: i64,
	pub algorithm: String,
	pub auth_data: Value,
	pub etag: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomKeyBackup {
	pub user_id: String,
	pub version: i64,
	pub room_id: String,
	pub session_id: String,
	pub first_message_index: Option<i64>,
	pub forwarded_count: Option<i64>,
	pub is_verified: bool,
	pub session_data: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseToDeviceMessage {
	pub user_id: String,
	pub device_id: String,
	pub stream_id: i64,
	pub message_json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceFederationInbox {
	pub origin: String,
	pub message_id: String,
	pub received_ts: i64,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceFederationOutbox {
	pub destination: String,
	pub stream_id: i64,
	pub queued_ts: i64,
	pub messages_json: Value,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListRemoteExtremity {
	pub user_id: String,
	pub stream_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListRemoteResync {
	pub user_id: String,
	pub added_ts: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseUserSignatureStream {
	pub stream_id: i64,
	pub from_user_id: String,
	pub user_ids: Value,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseAccessToken {
	pub user_id: String,
	pub device_id: Option<String>,
	pub token: String,
	pub valid_until_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseOpenIdToken {
	pub token: String,
	pub ts_valid_until_ms: i64,
	pub user_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseLoginToken {
	pub token: String,
	pub user_id: String,
	pub expiry_ts: i64,
	pub used_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseUiAuthSession {
	pub session_id: String,
	pub creation_time: i64,
	pub serverdict: Value,
	pub clientdict: Value,
	pub uri: String,
	pub method: String,
	pub description: String,
}

#[derive(Clone, Debug)]
pub struct SynapseUiAuthSessionCredential {
	pub session_id: String,
	pub stage_type: String,
	pub result: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseUiAuthSessionIp {
	pub session_id: String,
	pub ip: String,
	pub user_agent: String,
}

#[derive(Clone, Debug)]
pub struct SynapseAccountData {
	pub user_id: String,
	pub room_id: Option<String>,
	pub event_type: String,
	pub content: Value,
}

#[derive(Clone, Debug)]
pub struct SynapsePushRule {
	pub user_id: String,
	pub rule_id: String,
	pub priority_class: i64,
	pub priority: i64,
	pub conditions: Value,
	pub actions: Value,
	pub enabled: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct SynapseIgnoredUser {
	pub ignorer_user_id: String,
	pub ignored_user_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomTag {
	pub user_id: String,
	pub room_id: String,
	pub tag: String,
	pub content: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseFilter {
	pub user_id: String,
	pub filter_id: i64,
	pub filter_json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapsePresence {
	pub stream_id: i64,
	pub user_id: String,
	pub state: String,
	pub last_active_ts: Option<i64>,
	pub status_msg: Option<String>,
	pub currently_active: Option<bool>,
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
	pub backup_source_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct SynapseMediaThumbnail {
	pub mxc_server: String,
	pub media_id: String,
	pub content_type: Option<String>,
	pub width: i64,
	pub height: i64,
	pub method: String,
	pub source_path: Option<PathBuf>,
	pub backup_source_path: Option<PathBuf>,
	pub legacy_source_path: Option<PathBuf>,
	pub backup_legacy_source_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct SynapseUrlPreview {
	pub url: String,
	pub download_ts: Option<i64>,
	pub og: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomEvent {
	pub event_id: String,
	pub room_id: String,
	pub stream_ordering: i64,
	pub json: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseEventEdge {
	pub event_id: String,
	pub prev_event_id: String,
	pub room_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseSoftFailedEvent {
	pub event_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseForwardExtremity {
	pub event_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseEventRelation {
	pub event_id: String,
	pub relates_to_id: String,
	pub relation_type: String,
	pub aggregation_key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventTransaction {
	pub event_id: String,
	pub room_id: String,
	pub user_id: String,
	pub device_id: Option<String>,
	pub txn_id: String,
	pub inserted_ts: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseRedaction {
	pub event_id: String,
	pub redacts: String,
}

#[derive(Clone, Debug)]
pub struct SynapseEventReport {
	pub id: i64,
	pub received_ts: i64,
	pub room_id: String,
	pub event_id: String,
	pub user_id: String,
	pub reason: Option<String>,
	pub content: Value,
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
pub struct SynapseRoomRetention {
	pub room_id: String,
	pub event_id: String,
	pub min_lifetime: Option<i64>,
	pub max_lifetime: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventExpiry {
	pub event_id: String,
	pub expiry_ts: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseForgottenRoom {
	pub user_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseBlockedRoom {
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomAlias {
	pub room_alias: String,
	pub room_id: String,
	pub creator: Option<String>,
	pub servers: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SynapsePublicRoom {
	pub room_id: String,
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

#[derive(Clone, Debug)]
pub struct SynapseNotificationCount {
	pub user_id: String,
	pub room_id: String,
	pub notification_count: i64,
	pub highlight_count: i64,
}

#[derive(Clone, Debug)]
pub struct SynapsePusher {
	pub user_id: String,
	pub profile_tag: String,
	pub kind: String,
	pub app_id: String,
	pub app_display_name: String,
	pub device_display_name: String,
	pub pushkey: String,
	pub lang: Option<String>,
	pub data: Value,
	pub device_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeletedPusher {
	pub stream_id: i64,
	pub app_id: String,
	pub pushkey: String,
	pub user_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseApplicationServiceTxn {
	pub as_id: String,
	pub txn_id: i64,
	pub event_ids: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseApplicationServiceState {
	pub as_id: String,
	pub state: Option<String>,
	pub read_receipt_stream_id: Option<i64>,
	pub presence_stream_id: Option<i64>,
	pub to_device_stream_id: Option<i64>,
	pub device_list_stream_id: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseApplicationServiceStreamPosition {
	pub lock: String,
	pub stream_ordering: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseApplicationServiceRoom {
	pub appservice_id: String,
	pub network_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseServerKey {
	pub server_name: String,
	pub key_id: String,
	pub ts_added_ms: i64,
	pub ts_valid_until_ms: i64,
	pub key_json: Value,
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

		let columns = self.columns("users")?;
		let shadow_banned = if columns.contains("shadow_banned") {
			"COALESCE(shadow_banned, 0)"
		} else {
			"0"
		};
		let locked = if columns.contains("locked") {
			"COALESCE(locked, 0)"
		} else {
			"0"
		};
		let suspended = if columns.contains("suspended") {
			"COALESCE(suspended, 0)"
		} else {
			"0"
		};
		let query = format!(
			"
			SELECT name, password_hash, deactivated, admin, appservice_id, user_type,
			       {shadow_banned}, {locked}, {suspended}
			FROM users
			"
		);

		let mut stmt = self
			.conn
			.prepare(&query)
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
					locked: int_bool(row, 7)?,
					suspended: int_bool(row, 8)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn erased_users(&self) -> Result<Vec<SynapseErasedUser>> {
		if !self.table_exists("erased_users")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id
				FROM erased_users
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| Ok(SynapseErasedUser { user_id: row.get(0)? }))
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn account_validity(&self) -> Result<Vec<SynapseAccountValidity>> {
		if !self.table_exists("account_validity")? {
			return Ok(Vec::new());
		}

		let token_used = if self.columns("account_validity")?.contains("token_used_ts_ms") {
			"token_used_ts_ms"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, expiration_ts_ms, email_sent, renewal_token, {token_used}
			FROM account_validity
			ORDER BY user_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseAccountValidity {
					user_id: row.get(0)?,
					expiration_ts_ms: row.get(1)?,
					email_sent: row.get(2)?,
					renewal_token: row.get(3)?,
					token_used_ts_ms: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ratelimit_overrides(&self) -> Result<Vec<SynapseRatelimitOverride>> {
		if !self.table_exists("ratelimit_override")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, messages_per_second, burst_count
				FROM ratelimit_override
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRatelimitOverride {
					user_id: row.get(0)?,
					messages_per_second: row.get(1)?,
					burst_count: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn monthly_active_users(&self) -> Result<Vec<SynapseMonthlyActiveUser>> {
		if !self.table_exists("monthly_active_users")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, timestamp
				FROM monthly_active_users
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseMonthlyActiveUser {
					user_id: row.get(0)?,
					timestamp: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn registration_tokens(&self) -> Result<Vec<SynapseRegistrationToken>> {
		if !self.table_exists("registration_tokens")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT token, uses_allowed, pending, completed, expiry_time
				FROM registration_tokens
				ORDER BY token
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRegistrationToken {
					token: row.get(0)?,
					uses_allowed: row.get(1)?,
					pending: row.get(2)?,
					completed: row.get(3)?,
					expiry_time: row.get(4)?,
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

	pub fn threepids(&self) -> Result<Vec<SynapseThreepid>> {
		if !self.table_exists("user_threepids")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, medium, address, added_at
				FROM user_threepids
				ORDER BY user_id, added_at DESC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseThreepid {
					user_id: row.get(0)?,
					medium: row.get(1)?,
					address: row.get(2)?,
					added_at: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_external_ids(&self) -> Result<Vec<SynapseUserExternalId>> {
		if !self.table_exists("user_external_ids")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT auth_provider, external_id, user_id
				FROM user_external_ids
				ORDER BY auth_provider, external_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserExternalId {
					auth_provider: row.get(0)?,
					external_id: row.get(1)?,
					user_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn devices(&self) -> Result<Vec<SynapseDevice>> {
		if !self.table_exists("devices")? {
			return Ok(Vec::new());
		}

		let device_columns = self.columns("devices")?;
		let hidden = if device_columns.contains("hidden") {
			"COALESCE(d.hidden, 0)"
		} else {
			"0"
		};
		let use_user_ips = if self.table_exists("user_ips")? {
			let user_ip_columns = self.columns("user_ips")?;
			["user_id", "device_id", "ip", "last_seen"]
				.into_iter()
				.all(|column| user_ip_columns.contains(column))
		} else {
			false
		};
		let query = if use_user_ips {
			format!(
				"
				SELECT d.user_id, d.device_id, d.display_name,
				       COALESCE(d.last_seen, ips.last_seen),
				       COALESCE(d.ip, ips.ip),
				       {hidden}
				FROM devices d
				LEFT JOIN (
					SELECT rows.user_id, rows.device_id, rows.ip, rows.last_seen
					FROM user_ips rows
					INNER JOIN (
						SELECT user_id, device_id, MAX(last_seen) AS last_seen
						FROM user_ips
						WHERE device_id IS NOT NULL
						GROUP BY user_id, device_id
					) latest
						ON latest.user_id = rows.user_id
						AND latest.device_id = rows.device_id
						AND latest.last_seen = rows.last_seen
					GROUP BY rows.user_id, rows.device_id
				)
				ips ON ips.user_id = d.user_id AND ips.device_id = d.device_id
				"
			)
		} else {
			format!(
				"
				SELECT d.user_id, d.device_id, d.display_name, d.last_seen, d.ip, {hidden}
				FROM devices d
				"
			)
		};
		let mut stmt = self
			.conn
			.prepare(&query)
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

	pub fn device_auth_providers(&self) -> Result<Vec<SynapseDeviceAuthProvider>> {
		if !self.table_exists("device_auth_providers")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, auth_provider_id, auth_provider_session_id
				FROM device_auth_providers
				ORDER BY user_id, device_id, auth_provider_id, auth_provider_session_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceAuthProvider {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					auth_provider_id: row.get(2)?,
					auth_provider_session_id: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn dehydrated_devices(&self) -> Result<Vec<SynapseDehydratedDevice>> {
		if !self.table_exists("dehydrated_devices")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, device_data
				FROM dehydrated_devices
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let device_data: String = row.get(2)?;
				Ok(SynapseDehydratedDevice {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					device_data: serde_json::from_str(&device_data).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		if !self.table_exists("e2e_device_keys_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, key_json
				FROM e2e_device_keys_json
				ORDER BY user_id, device_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let key_json: String = row.get(2)?;
				Ok(SynapseDeviceKey {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					key_json: serde_json::from_str(&key_json).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn remote_device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		if !self.table_exists("device_lists_remote_cache")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, content
				FROM device_lists_remote_cache
				ORDER BY user_id, device_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let content: String = row.get(2)?;
				Ok(SynapseDeviceKey {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					key_json: serde_json::from_str(&content).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn one_time_keys(&self) -> Result<Vec<SynapseOneTimeKey>> {
		if !self.table_exists("e2e_one_time_keys_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, algorithm, key_id, key_json
				FROM e2e_one_time_keys_json
				ORDER BY user_id, device_id, algorithm, key_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let key_json: String = row.get(4)?;
				Ok(SynapseOneTimeKey {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					algorithm: row.get(2)?,
					key_id: row.get(3)?,
					key_json: serde_json::from_str(&key_json).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn fallback_keys(&self) -> Result<Vec<SynapseFallbackKey>> {
		if !self.table_exists("e2e_fallback_keys_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, algorithm, key_id, key_json, used
				FROM e2e_fallback_keys_json
				ORDER BY user_id, device_id, algorithm
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let key_json: String = row.get(4)?;
				Ok(SynapseFallbackKey {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					algorithm: row.get(2)?,
					key_id: row.get(3)?,
					key_json: serde_json::from_str(&key_json).unwrap_or(Value::Null),
					used: int_bool(row, 5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn cross_signing_keys(&self) -> Result<Vec<SynapseCrossSigningKey>> {
		if !self.table_exists("e2e_cross_signing_keys")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, keytype, keydata, stream_id
				FROM e2e_cross_signing_keys
				ORDER BY user_id, keytype, stream_id ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let key_data: String = row.get(2)?;
				Ok(SynapseCrossSigningKey {
					user_id: row.get(0)?,
					key_type: row.get(1)?,
					key_data: serde_json::from_str(&key_data).unwrap_or(Value::Null),
					stream_id: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn cross_signing_signatures(&self) -> Result<Vec<SynapseKeySignature>> {
		if !self.table_exists("e2e_cross_signing_signatures")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, key_id, target_user_id, target_device_id, signature
				FROM e2e_cross_signing_signatures
				ORDER BY target_user_id, target_device_id, user_id, key_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseKeySignature {
					user_id: row.get(0)?,
					key_id: row.get(1)?,
					target_user_id: row.get(2)?,
					target_device_id: row.get(3)?,
					signature: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_key_backup_versions(&self) -> Result<Vec<SynapseRoomKeyBackupVersion>> {
		if !self.table_exists("e2e_room_keys_versions")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("e2e_room_keys_versions")?;
		let etag = if columns.contains("etag") { "etag" } else { "NULL" };
		let deleted = if columns.contains("deleted") {
			"COALESCE(deleted, 0)"
		} else {
			"0"
		};
		let query = format!(
			"
			SELECT user_id, version, algorithm, auth_data, {etag}
			FROM e2e_room_keys_versions
			WHERE {deleted} = 0
			ORDER BY user_id, version
			"
		);

		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let auth_data: String = row.get(3)?;
				Ok(SynapseRoomKeyBackupVersion {
					user_id: row.get(0)?,
					version: row.get(1)?,
					algorithm: row.get(2)?,
					auth_data: serde_json::from_str(&auth_data).unwrap_or(Value::Null),
					etag: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_key_backups(&self) -> Result<Vec<SynapseRoomKeyBackup>> {
		if !self.table_exists("e2e_room_keys")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, version, room_id, session_id, first_message_index,
				       forwarded_count, is_verified, session_data
				FROM e2e_room_keys
				ORDER BY user_id, version, room_id, session_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let session_data: String = row.get(7)?;
				Ok(SynapseRoomKeyBackup {
					user_id: row.get(0)?,
					version: row.get(1)?,
					room_id: row.get(2)?,
					session_id: row.get(3)?,
					first_message_index: row.get(4)?,
					forwarded_count: row.get(5)?,
					is_verified: int_bool(row, 6)?,
					session_data: serde_json::from_str(&session_data).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn to_device_messages(&self) -> Result<Vec<SynapseToDeviceMessage>> {
		if !self.table_exists("device_inbox")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, device_id, stream_id, message_json
				FROM device_inbox
				ORDER BY stream_id ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let message_json: String = row.get(3)?;
				Ok(SynapseToDeviceMessage {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					stream_id: row.get(2)?,
					message_json: serde_json::from_str(&message_json).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_federation_inbox(&self) -> Result<Vec<SynapseDeviceFederationInbox>> {
		if !self.table_exists("device_federation_inbox")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_federation_inbox")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT origin, message_id, received_ts, {instance_name}
			FROM device_federation_inbox
			ORDER BY received_ts, origin, message_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceFederationInbox {
					origin: row.get(0)?,
					message_id: row.get(1)?,
					received_ts: row.get(2)?,
					instance_name: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_federation_outbox(&self) -> Result<Vec<SynapseDeviceFederationOutbox>> {
		if !self.table_exists("device_federation_outbox")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_federation_outbox")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT destination, stream_id, queued_ts, messages_json, {instance_name}
			FROM device_federation_outbox
			ORDER BY stream_id, destination
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let messages_json: String = row.get(3)?;
				Ok(SynapseDeviceFederationOutbox {
					destination: row.get(0)?,
					stream_id: row.get(1)?,
					queued_ts: row.get(2)?,
					messages_json: serde_json::from_str(&messages_json).unwrap_or(Value::Null),
					instance_name: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_remote_extremities(&self) -> Result<Vec<SynapseDeviceListRemoteExtremity>> {
		if !self.table_exists("device_lists_remote_extremeties")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, stream_id
				FROM device_lists_remote_extremeties
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListRemoteExtremity {
					user_id: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_remote_resync(&self) -> Result<Vec<SynapseDeviceListRemoteResync>> {
		if !self.table_exists("device_lists_remote_resync")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, added_ts
				FROM device_lists_remote_resync
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListRemoteResync {
					user_id: row.get(0)?,
					added_ts: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_signature_stream(&self) -> Result<Vec<SynapseUserSignatureStream>> {
		if !self.table_exists("user_signature_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("user_signature_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, from_user_id, user_ids, {instance_name}
			FROM user_signature_stream
			ORDER BY stream_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let user_ids: String = row.get(2)?;
				Ok(SynapseUserSignatureStream {
					stream_id: row.get(0)?,
					from_user_id: row.get(1)?,
					user_ids: serde_json::from_str(&user_ids).unwrap_or(Value::Null),
					instance_name: row.get(3)?,
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

	pub fn open_id_tokens(&self) -> Result<Vec<SynapseOpenIdToken>> {
		if !self.table_exists("open_id_tokens")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT token, ts_valid_until_ms, user_id
				FROM open_id_tokens
				ORDER BY token
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseOpenIdToken {
					token: row.get(0)?,
					ts_valid_until_ms: row.get(1)?,
					user_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn login_tokens(&self) -> Result<Vec<SynapseLoginToken>> {
		if !self.table_exists("login_tokens")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT token, user_id, expiry_ts, used_ts
				FROM login_tokens
				ORDER BY token
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseLoginToken {
					token: row.get(0)?,
					user_id: row.get(1)?,
					expiry_ts: row.get(2)?,
					used_ts: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ui_auth_sessions(&self) -> Result<Vec<SynapseUiAuthSession>> {
		if !self.table_exists("ui_auth_sessions")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT session_id, creation_time, serverdict, clientdict, uri, method, description
				FROM ui_auth_sessions
				ORDER BY session_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let serverdict: String = row.get(2)?;
				let clientdict: String = row.get(3)?;
				Ok(SynapseUiAuthSession {
					session_id: row.get(0)?,
					creation_time: row.get(1)?,
					serverdict: serde_json::from_str(&serverdict).unwrap_or(Value::Null),
					clientdict: serde_json::from_str(&clientdict).unwrap_or(Value::Null),
					uri: row.get(4)?,
					method: row.get(5)?,
					description: row.get(6)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ui_auth_session_credentials(&self) -> Result<Vec<SynapseUiAuthSessionCredential>> {
		if !self.table_exists("ui_auth_sessions_credentials")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT session_id, stage_type, result
				FROM ui_auth_sessions_credentials
				ORDER BY session_id, stage_type
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let result: String = row.get(2)?;
				Ok(SynapseUiAuthSessionCredential {
					session_id: row.get(0)?,
					stage_type: row.get(1)?,
					result: serde_json::from_str(&result).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ui_auth_session_ips(&self) -> Result<Vec<SynapseUiAuthSessionIp>> {
		if !self.table_exists("ui_auth_sessions_ips")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT session_id, ip, user_agent
				FROM ui_auth_sessions_ips
				ORDER BY session_id, ip, user_agent
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUiAuthSessionIp {
					session_id: row.get(0)?,
					ip: row.get(1)?,
					user_agent: row.get(2)?,
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

	pub fn push_rules(&self) -> Result<Vec<SynapsePushRule>> {
		if !self.table_exists("push_rules")? {
			return Ok(Vec::new());
		}

		let has_enabled = self.table_exists("push_rules_enable")?;
		let enabled_join = if has_enabled {
			"LEFT JOIN push_rules_enable AS enable
				ON enable.user_name = rules.user_name
				AND enable.rule_id = rules.rule_id"
		} else {
			""
		};
		let enabled_select = if has_enabled { "enable.enabled" } else { "NULL" };
		let query = format!(
			"
			SELECT rules.user_name, rules.rule_id, rules.priority_class, rules.priority,
			       rules.conditions, rules.actions, {enabled_select}
			FROM push_rules AS rules
			{enabled_join}
			ORDER BY rules.user_name, rules.priority_class DESC, rules.priority DESC, rules.rule_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let conditions: String = row.get(4)?;
				let actions: String = row.get(5)?;
				let enabled = row.get::<_, Option<i64>>(6)?.map(|value| value != 0);

				Ok(SynapsePushRule {
					user_id: row.get(0)?,
					rule_id: row.get(1)?,
					priority_class: row.get(2)?,
					priority: row.get(3)?,
					conditions: serde_json::from_str(&conditions).unwrap_or(Value::Null),
					actions: serde_json::from_str(&actions).unwrap_or(Value::Null),
					enabled,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ignored_users(&self) -> Result<Vec<SynapseIgnoredUser>> {
		if !self.table_exists("ignored_users")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT ignorer_user_id, ignored_user_id
				FROM ignored_users
				ORDER BY ignorer_user_id, ignored_user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseIgnoredUser {
					ignorer_user_id: row.get(0)?,
					ignored_user_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_tags(&self) -> Result<Vec<SynapseRoomTag>> {
		if !self.table_exists("room_tags")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, room_id, tag, content
				FROM room_tags
				ORDER BY user_id, room_id, tag
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let content: String = row.get(3)?;
				Ok(SynapseRoomTag {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
					tag: row.get(2)?,
					content: serde_json::from_str(&content).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn filters(&self, server_name: Option<&str>) -> Result<Vec<SynapseFilter>> {
		if !self.table_exists("user_filters")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("user_filters")?;
		let full_user_id_column = if columns.contains("full_user_id") {
			"full_user_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, {full_user_id_column}, filter_id, filter_json
			FROM user_filters
			ORDER BY user_id, filter_id
			"
		);

		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let user_id: String = row.get::<_, Option<String>>(1)?.unwrap_or_else(|| {
					let localpart = row.get::<_, String>(0).unwrap_or_default();
					full_user_id(&localpart, server_name).unwrap_or(localpart)
				});
				let filter_json = match row.get_ref(3)? {
					| ValueRef::Blob(bytes) | ValueRef::Text(bytes) =>
						serde_json::from_slice(bytes).unwrap_or(Value::Null),
					| _ => Value::Null,
				};

				Ok(SynapseFilter {
					user_id,
					filter_id: row.get(2)?,
					filter_json,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn presence(&self) -> Result<Vec<SynapsePresence>> {
		if !self.table_exists("presence_stream")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, user_id, state, last_active_ts, status_msg, currently_active
				FROM presence_stream
				ORDER BY user_id, stream_id ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapsePresence {
					stream_id: row.get(0)?,
					user_id: row.get(1)?,
					state: row.get(2)?,
					last_active_ts: row.get(3)?,
					status_msg: row.get(4)?,
					currently_active: row.get::<_, Option<i64>>(5)?.map(|value| value != 0),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn media(
		&self,
		media_store: &Path,
		backup_media_store: Option<&Path>,
		server_name: &str,
	) -> Result<Vec<SynapseMedia>> {
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
						backup_source_path: backup_media_store
							.map(|media_store| local_media_path(media_store, &media_id)),
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
						backup_source_path: backup_media_store.map(|media_store| {
							remote_media_path(media_store, &media_origin, &filesystem_id)
						}),
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

	pub fn media_thumbnails(
		&self,
		media_store: &Path,
		backup_media_store: Option<&Path>,
		server_name: &str,
	) -> Result<Vec<SynapseMediaThumbnail>> {
		let mut thumbnails = Vec::new();

		if self.table_exists("local_media_repository_thumbnails")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT media_id, thumbnail_width, thumbnail_height,
					       thumbnail_type, COALESCE(thumbnail_method, 'scale')
					FROM local_media_repository_thumbnails
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					let media_id: String = row.get(0)?;
					let content_type: Option<String> = row.get(3)?;
					let method: String = row.get(4)?;
					let width: i64 = row.get(1)?;
					let height: i64 = row.get(2)?;
					Ok(SynapseMediaThumbnail {
						mxc_server: server_name.to_owned(),
						source_path: content_type.as_deref().and_then(|content_type| {
							local_thumbnail_path(
								media_store,
								&media_id,
								width,
								height,
								content_type,
								&method,
							)
						}),
						backup_source_path: backup_media_store.and_then(|media_store| {
							content_type.as_deref().and_then(|content_type| {
								local_thumbnail_path(
									media_store,
									&media_id,
									width,
									height,
									content_type,
									&method,
								)
							})
						}),
						legacy_source_path: None,
						backup_legacy_source_path: None,
						media_id,
						content_type,
						width,
						height,
						method,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			thumbnails.extend(collect_rows(&self.path, rows)?);
		}

		if self.table_exists("remote_media_cache_thumbnails")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT media_origin, media_id, thumbnail_width, thumbnail_height,
					       thumbnail_type, COALESCE(thumbnail_method, 'scale'), COALESCE(filesystem_id, media_id)
					FROM remote_media_cache_thumbnails
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					let media_origin: String = row.get(0)?;
					let media_id: String = row.get(1)?;
					let content_type: Option<String> = row.get(4)?;
					let method: String = row.get(5)?;
					let filesystem_id: String = row.get(6)?;
					let width: i64 = row.get(2)?;
					let height: i64 = row.get(3)?;
					Ok(SynapseMediaThumbnail {
						source_path: content_type.as_deref().and_then(|content_type| {
							remote_thumbnail_path(
								media_store,
								&media_origin,
								&filesystem_id,
								width,
								height,
								content_type,
								&method,
							)
						}),
						legacy_source_path: content_type.as_deref().and_then(|content_type| {
							remote_thumbnail_legacy_path(
								media_store,
								&media_origin,
								&filesystem_id,
								width,
								height,
								content_type,
							)
						}),
						backup_source_path: backup_media_store.and_then(|media_store| {
							content_type.as_deref().and_then(|content_type| {
								remote_thumbnail_path(
									media_store,
									&media_origin,
									&filesystem_id,
									width,
									height,
									content_type,
									&method,
								)
							})
						}),
						backup_legacy_source_path: backup_media_store.and_then(|media_store| {
							content_type.as_deref().and_then(|content_type| {
								remote_thumbnail_legacy_path(
									media_store,
									&media_origin,
									&filesystem_id,
									width,
									height,
									content_type,
								)
							})
						}),
						mxc_server: media_origin,
						media_id,
						content_type,
						width,
						height,
						method,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			thumbnails.extend(collect_rows(&self.path, rows)?);
		}

		Ok(thumbnails)
	}

	pub fn url_previews(&self) -> Result<Vec<SynapseUrlPreview>> {
		if !self.table_exists("local_media_repository_url_cache")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT url, download_ts, og
				FROM local_media_repository_url_cache
				WHERE og IS NOT NULL
				ORDER BY url, download_ts
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let og: String = row.get(2)?;
				Ok(SynapseUrlPreview {
					url: row.get(0)?,
					download_ts: row.get(1)?,
					og: serde_json::from_str(&og).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
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
				  AND e.stream_ordering > 0
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

	pub fn outlier_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT e.event_id, e.room_id, COALESCE(e.stream_ordering, 0), ej.json
				FROM events e
				JOIN event_json ej ON e.event_id = ej.event_id
				WHERE COALESCE(e.outlier, 0) != 0
				  AND e.rejection_reason IS NULL
				ORDER BY e.event_id
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

	pub fn backfilled_events(&self) -> Result<Vec<SynapseRoomEvent>> {
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
				  AND e.stream_ordering < 0
				ORDER BY e.stream_ordering DESC
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

	pub fn event_edges(&self) -> Result<Vec<SynapseEventEdge>> {
		if !self.table_exists("event_edges")? {
			return Ok(Vec::new());
		}

		let events_join = if self.table_exists("events")? {
			"LEFT JOIN events ON events.event_id = edges.event_id"
		} else {
			""
		};
		let room_id = if self.table_exists("events")? {
			"COALESCE(edges.room_id, events.room_id)"
		} else {
			"edges.room_id"
		};
		let query = format!(
			"
			SELECT edges.event_id, edges.prev_event_id, {room_id}
			FROM event_edges AS edges
			{events_join}
			WHERE edges.is_state = 0
			ORDER BY edges.event_id, edges.prev_event_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventEdge {
					event_id: row.get(0)?,
					prev_event_id: row.get(1)?,
					room_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn soft_failed_events(&self) -> Result<Vec<SynapseSoftFailedEvent>> {
		if !self.table_exists("event_json")? || !self.columns("event_json")?.contains("internal_metadata") {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, internal_metadata
				FROM event_json
				WHERE internal_metadata IS NOT NULL
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let event_id: String = row.get(0)?;
				let metadata: String = row.get(1)?;
				let metadata = serde_json::from_str::<Value>(&metadata).unwrap_or(Value::Null);
				let soft_failed = metadata
					.get("soft_failed")
					.and_then(Value::as_bool)
					.unwrap_or(false);
				Ok(soft_failed.then_some(SynapseSoftFailedEvent { event_id }))
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows).map(|rows| rows.into_iter().flatten().collect())
	}

	pub fn forward_extremities(&self) -> Result<Vec<SynapseForwardExtremity>> {
		if !self.table_exists("event_forward_extremities")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, room_id
				FROM event_forward_extremities
				ORDER BY room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseForwardExtremity {
					event_id: row.get(0)?,
					room_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_relations(&self) -> Result<Vec<SynapseEventRelation>> {
		if !self.table_exists("event_relations")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, relates_to_id, relation_type, aggregation_key
				FROM event_relations
				ORDER BY event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventRelation {
					event_id: row.get(0)?,
					relates_to_id: row.get(1)?,
					relation_type: row.get(2)?,
					aggregation_key: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_transactions(&self) -> Result<Vec<SynapseEventTransaction>> {
		let mut transactions = Vec::new();

		if self.table_exists("event_txn_id_device_id")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT event_id, room_id, user_id, device_id, txn_id, inserted_ts
					FROM event_txn_id_device_id
					ORDER BY inserted_ts, event_id
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					Ok(SynapseEventTransaction {
						event_id: row.get(0)?,
						room_id: row.get(1)?,
						user_id: row.get(2)?,
						device_id: row.get(3)?,
						txn_id: row.get(4)?,
						inserted_ts: row.get(5)?,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			transactions.extend(collect_rows(&self.path, rows)?);
		}

		if self.table_exists("event_txn_id")? {
			let has_access_token_ids =
				self.table_exists("access_tokens")? && self.columns("access_tokens")?.contains("id");
			let device_id = if has_access_token_ids {
				"tokens.device_id"
			} else {
				"NULL"
			};
			let access_tokens_join = if has_access_token_ids {
				"LEFT JOIN access_tokens AS tokens ON tokens.id = txns.token_id"
			} else {
				""
			};
			let query = format!(
				"
				SELECT txns.event_id, txns.room_id, txns.user_id, {device_id}, txns.txn_id, txns.inserted_ts
				FROM event_txn_id AS txns
				{access_tokens_join}
				ORDER BY txns.inserted_ts, txns.event_id
				"
			);
			let mut stmt = self
				.conn
				.prepare(&query)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					Ok(SynapseEventTransaction {
						event_id: row.get(0)?,
						room_id: row.get(1)?,
						user_id: row.get(2)?,
						device_id: row.get(3)?,
						txn_id: row.get(4)?,
						inserted_ts: row.get(5)?,
					})
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			transactions.extend(collect_rows(&self.path, rows)?);
		}

		Ok(transactions)
	}

	pub fn redactions(&self) -> Result<Vec<SynapseRedaction>> {
		if !self.table_exists("redactions")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, redacts
				FROM redactions
				ORDER BY event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRedaction {
					event_id: row.get(0)?,
					redacts: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_reports(&self) -> Result<Vec<SynapseEventReport>> {
		if !self.table_exists("event_reports")? {
			return Ok(Vec::new());
		}

		let content = if self.columns("event_reports")?.contains("content") {
			"content"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT id, received_ts, room_id, event_id, user_id, reason, {content}
			FROM event_reports
			ORDER BY id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let content: Option<String> = row.get(6)?;
				Ok(SynapseEventReport {
					id: row.get(0)?,
					received_ts: row.get(1)?,
					room_id: row.get(2)?,
					event_id: row.get(3)?,
					user_id: row.get(4)?,
					reason: row.get(5)?,
					content: content
						.as_deref()
						.and_then(|content| serde_json::from_str(content).ok())
						.unwrap_or(Value::Null),
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

		let mut stmt = self.conn.prepare(&query).map_err(|e| Error::sqlite(&self.path, e))?;
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

	pub fn room_retention(&self) -> Result<Vec<SynapseRoomRetention>> {
		if !self.table_exists("room_retention")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, event_id, min_lifetime, max_lifetime
				FROM room_retention
				ORDER BY room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomRetention {
					room_id: row.get(0)?,
					event_id: row.get(1)?,
					min_lifetime: row.get(2)?,
					max_lifetime: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_expiry(&self) -> Result<Vec<SynapseEventExpiry>> {
		if !self.table_exists("event_expiry")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, expiry_ts
				FROM event_expiry
				ORDER BY expiry_ts, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventExpiry {
					event_id: row.get(0)?,
					expiry_ts: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn forgotten_rooms(&self) -> Result<Vec<SynapseForgottenRoom>> {
		if !self.table_exists("room_memberships")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT m.user_id, m.room_id
				FROM room_memberships AS m
				WHERE COALESCE(m.forgotten, 0) = 1
				  AND NOT EXISTS (
				      SELECT 1
				      FROM room_memberships AS rm2
				      WHERE rm2.user_id = m.user_id
				        AND rm2.room_id = m.room_id
				        AND COALESCE(rm2.forgotten, 0) = 0
				  )
				GROUP BY m.user_id, m.room_id
				ORDER BY m.user_id, m.room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseForgottenRoom {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn blocked_rooms(&self) -> Result<Vec<SynapseBlockedRoom>> {
		if !self.table_exists("blocked_rooms")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT DISTINCT room_id
				FROM blocked_rooms
				ORDER BY room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| Ok(SynapseBlockedRoom { room_id: row.get(0)? }))
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_aliases(&self) -> Result<Vec<SynapseRoomAlias>> {
		if !self.table_exists("room_aliases")? {
			return Ok(Vec::new());
		}

		let mut servers = BTreeMap::<String, Vec<String>>::new();
		if self.table_exists("room_alias_servers")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT room_alias, server
					FROM room_alias_servers
					ORDER BY room_alias, server
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
				.map_err(|e| Error::sqlite(&self.path, e))?;
			for (room_alias, server) in collect_rows(&self.path, rows)? {
				servers.entry(room_alias).or_default().push(server);
			}
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_alias, room_id, creator
				FROM room_aliases
				ORDER BY room_alias
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let room_alias: String = row.get(0)?;
				Ok(SynapseRoomAlias {
					room_id: row.get(1)?,
					creator: row.get(2)?,
					servers: servers.remove(&room_alias).unwrap_or_default(),
					room_alias,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn public_rooms(&self) -> Result<Vec<SynapsePublicRoom>> {
		let mut room_ids = BTreeSet::<String>::new();

		if self.table_exists("rooms")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT room_id
					FROM rooms
					WHERE COALESCE(is_public, 0) != 0
					ORDER BY room_id
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| row.get::<_, String>(0))
				.map_err(|e| Error::sqlite(&self.path, e))?;
			room_ids.extend(collect_rows(&self.path, rows)?);
		}

		if self.table_exists("appservice_room_list")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT room_id
					FROM appservice_room_list
					ORDER BY room_id
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| row.get::<_, String>(0))
				.map_err(|e| Error::sqlite(&self.path, e))?;
			room_ids.extend(collect_rows(&self.path, rows)?);
		}

		Ok(room_ids
			.into_iter()
			.map(|room_id| SynapsePublicRoom { room_id })
			.collect())
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

	pub fn notification_counts(&self) -> Result<Vec<SynapseNotificationCount>> {
		let mut counts = BTreeMap::<(String, String), (i64, i64)>::new();

		if self.table_exists("event_push_summary")? {
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT user_id, room_id, SUM(notif_count)
					FROM event_push_summary
					GROUP BY user_id, room_id
					ORDER BY user_id, room_id
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					Ok((
						row.get::<_, String>(0)?,
						row.get::<_, String>(1)?,
						row.get::<_, Option<i64>>(2)?.unwrap_or_default(),
					))
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			for (user_id, room_id, notification_count) in collect_rows(&self.path, rows)? {
				counts.entry((user_id, room_id)).or_default().0 = notification_count;
			}
		}

		if self.table_exists("event_push_actions")?
			&& self.columns("event_push_actions")?.contains("highlight")
		{
			let mut stmt = self
				.conn
				.prepare(
					"
					SELECT user_id, room_id, COUNT(*)
					FROM event_push_actions
					WHERE COALESCE(highlight, 0) = 1
					GROUP BY user_id, room_id
					ORDER BY user_id, room_id
					",
				)
				.map_err(|e| Error::sqlite(&self.path, e))?;
			let rows = stmt
				.query_map([], |row| {
					Ok((
						row.get::<_, String>(0)?,
						row.get::<_, String>(1)?,
						row.get::<_, i64>(2)?,
					))
				})
				.map_err(|e| Error::sqlite(&self.path, e))?;
			for (user_id, room_id, highlight_count) in collect_rows(&self.path, rows)? {
				counts.entry((user_id, room_id)).or_default().1 = highlight_count;
			}
		}

		Ok(counts
			.into_iter()
			.filter(|(_, (notification_count, highlight_count))| {
				*notification_count != 0 || *highlight_count != 0
			})
			.map(|((user_id, room_id), (notification_count, highlight_count))| {
				SynapseNotificationCount {
					user_id,
					room_id,
					notification_count,
					highlight_count,
				}
			})
			.collect())
	}

	pub fn pushers(&self) -> Result<Vec<SynapsePusher>> {
		if !self.table_exists("pushers")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("pushers")?;
		let enabled = if columns.contains("enabled") {
			"COALESCE(enabled, 1)"
		} else {
			"1"
		};
		let device_id = if columns.contains("device_id") {
			"device_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_name, profile_tag, kind, app_id, app_display_name,
			       device_display_name, pushkey, lang, data, {device_id}
			FROM pushers
			WHERE {enabled} != 0
			ORDER BY user_name, app_id, pushkey
			"
		);

		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let data: Option<String> = row.get(8)?;
				Ok(SynapsePusher {
					user_id: row.get(0)?,
					profile_tag: row.get(1)?,
					kind: row.get(2)?,
					app_id: row.get(3)?,
					app_display_name: row.get(4)?,
					device_display_name: row.get(5)?,
					pushkey: row.get(6)?,
					lang: row.get(7)?,
					data: data
						.and_then(|data| serde_json::from_str(&data).ok())
						.unwrap_or(Value::Null),
					device_id: row.get(9)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn deleted_pushers(&self) -> Result<Vec<SynapseDeletedPusher>> {
		if !self.table_exists("deleted_pushers")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, app_id, pushkey, user_id
				FROM deleted_pushers
				ORDER BY stream_id, user_id, app_id, pushkey
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeletedPusher {
					stream_id: row.get(0)?,
					app_id: row.get(1)?,
					pushkey: row.get(2)?,
					user_id: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn application_service_txns(&self) -> Result<Vec<SynapseApplicationServiceTxn>> {
		if !self.table_exists("application_services_txns")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT as_id, txn_id, event_ids
				FROM application_services_txns
				ORDER BY as_id, txn_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let event_ids: String = row.get(2)?;
				Ok(SynapseApplicationServiceTxn {
					as_id: row.get(0)?,
					txn_id: row.get(1)?,
					event_ids: serde_json::from_str(&event_ids).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn application_service_state(&self) -> Result<Vec<SynapseApplicationServiceState>> {
		if !self.table_exists("application_services_state")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT as_id, state, read_receipt_stream_id, presence_stream_id,
				       to_device_stream_id, device_list_stream_id
				FROM application_services_state
				ORDER BY as_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseApplicationServiceState {
					as_id: row.get(0)?,
					state: row.get(1)?,
					read_receipt_stream_id: row.get(2)?,
					presence_stream_id: row.get(3)?,
					to_device_stream_id: row.get(4)?,
					device_list_stream_id: row.get(5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn appservice_stream_position(
		&self,
	) -> Result<Vec<SynapseApplicationServiceStreamPosition>> {
		if !self.table_exists("appservice_stream_position")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT Lock, stream_ordering
				FROM appservice_stream_position
				ORDER BY Lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseApplicationServiceStreamPosition {
					lock: row.get(0)?,
					stream_ordering: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn appservice_room_list(&self) -> Result<Vec<SynapseApplicationServiceRoom>> {
		if !self.table_exists("appservice_room_list")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT appservice_id, network_id, room_id
				FROM appservice_room_list
				ORDER BY appservice_id, network_id, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseApplicationServiceRoom {
					appservice_id: row.get(0)?,
					network_id: row.get(1)?,
					room_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn server_keys(&self) -> Result<Vec<SynapseServerKey>> {
		if !self.table_exists("server_keys_json")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT server_name, key_id, ts_added_ms, ts_valid_until_ms, key_json
				FROM server_keys_json
				ORDER BY server_name, ts_added_ms ASC
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let key_json = match row.get_ref(4)? {
					| ValueRef::Blob(bytes) | ValueRef::Text(bytes) =>
						serde_json::from_slice(bytes).unwrap_or(Value::Null),
					| _ => Value::Null,
				};
				Ok(SynapseServerKey {
					server_name: row.get(0)?,
					key_id: row.get(1)?,
					ts_added_ms: row.get(2)?,
					ts_valid_until_ms: row.get(3)?,
					key_json,
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

fn local_thumbnail_path(
	media_store: &Path,
	media_id: &str,
	width: i64,
	height: i64,
	content_type: &str,
	method: &str,
) -> Option<PathBuf> {
	thumbnail_file_name(width, height, content_type, Some(method)).map(|file_name| {
		media_store
			.join("local_thumbnails")
			.join(slice(media_id, 0, 2))
			.join(slice(media_id, 2, 4))
			.join(slice(media_id, 4, media_id.len()))
			.join(file_name)
	})
}

fn remote_thumbnail_path(
	media_store: &Path,
	server_name: &str,
	filesystem_id: &str,
	width: i64,
	height: i64,
	content_type: &str,
	method: &str,
) -> Option<PathBuf> {
	remote_thumbnail_path_with_method(
		media_store,
		server_name,
		filesystem_id,
		width,
		height,
		content_type,
		Some(method),
	)
}

fn remote_thumbnail_legacy_path(
	media_store: &Path,
	server_name: &str,
	filesystem_id: &str,
	width: i64,
	height: i64,
	content_type: &str,
) -> Option<PathBuf> {
	remote_thumbnail_path_with_method(
		media_store,
		server_name,
		filesystem_id,
		width,
		height,
		content_type,
		None,
	)
}

fn remote_thumbnail_path_with_method(
	media_store: &Path,
	server_name: &str,
	filesystem_id: &str,
	width: i64,
	height: i64,
	content_type: &str,
	method: Option<&str>,
) -> Option<PathBuf> {
	thumbnail_file_name(width, height, content_type, method).map(|file_name| {
		media_store
			.join("remote_thumbnail")
			.join(server_name)
			.join(slice(filesystem_id, 0, 2))
			.join(slice(filesystem_id, 2, 4))
			.join(slice(filesystem_id, 4, filesystem_id.len()))
			.join(file_name)
	})
}

fn thumbnail_file_name(
	width: i64,
	height: i64,
	content_type: &str,
	method: Option<&str>,
) -> Option<String> {
	let (top_level_type, sub_type) = content_type.split_once('/')?;
	let base = format!("{width}-{height}-{top_level_type}-{sub_type}");
	Some(match method {
		| Some(method) => format!("{base}-{method}"),
		| None => base,
	})
}

fn slice(value: &str, start: usize, end: usize) -> &str {
	value.get(start..end).unwrap_or_default()
}
