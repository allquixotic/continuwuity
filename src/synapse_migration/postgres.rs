use std::{
	cell::RefCell,
	collections::{BTreeMap, BTreeSet},
	path::{Path, PathBuf},
};

use postgres::{Client, NoTls, Row, types::ToSql};
use serde_json::Value;

use crate::{
	Result,
	config::SynapseDatabase,
	sqlite::{
		SynapseAccessToken, SynapseAccountData, SynapseBlockedRoom, SynapseCrossSigningKey, SynapseDevice,
		SynapseDehydratedDevice, SynapseDeviceKey, SynapseErasedUser, SynapseEventEdge, SynapseEventExpiry,
		SynapseEventRelation, SynapseEventTransaction, SynapseFallbackKey, SynapseFilter,
		SynapseForgottenRoom, SynapseForwardExtremity, SynapseIgnoredUser, SynapseKeySignature,
		SynapseLoginToken, SynapseMedia, SynapseMediaThumbnail, SynapseNotificationCount,
		SynapseOneTimeKey, SynapseOpenIdToken, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapsePushRule, SynapseReceipt, SynapseRedaction, SynapseRegistrationToken,
		SynapseRoomAlias, SynapseRoomEvent, SynapseRoomKeyBackup, SynapseRoomKeyBackupVersion,
		SynapseRoomRetention, SynapseRoomState, SynapseRoomTag, SynapseServerKey, SynapseSoftFailedEvent,
		SynapseThreepid, SynapseToDeviceMessage, SynapseUrlPreview, SynapseUser,
	},
};

pub struct PostgresSource {
	client: RefCell<Client>,
}

const DEFAULT_BATCH_SIZE: i64 = 10_000;

impl PostgresSource {
	pub fn open(database: &SynapseDatabase) -> Result<Self> {
		let SynapseDatabase::Postgres {
			database,
			host,
			port,
			user,
			password,
			..
		} = database
		else {
			return Err(crate::Error::Message(
				"PostgresSource requires a Synapse PostgreSQL database".to_owned(),
			));
		};

		let mut config = postgres::Config::new();
		if let Some(database) = database {
			config.dbname(database);
		}
		if let Some(host) = host {
			config.host(host);
		}
		if let Some(port) = port {
			config.port(*port);
		}
		if let Some(user) = user {
			config.user(user);
		}
		if let Some(password) = password {
			config.password(password);
		}

		Ok(Self {
			client: RefCell::new(config.connect(NoTls)?),
		})
	}

	pub fn users(&self) -> Result<Vec<SynapseUser>> {
		if !self.table_exists("users")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("users")?;
		let shadow_banned = if columns.contains("shadow_banned") {
			"COALESCE(shadow_banned, false)"
		} else {
			"false"
		};
		let locked = if columns.contains("locked") {
			"COALESCE(locked, false)"
		} else {
			"false"
		};
		let suspended = if columns.contains("suspended") {
			"COALESCE(suspended, false)"
		} else {
			"false"
		};
		let query = format!(
			"
			SELECT name, password_hash, COALESCE(deactivated, 0), admin, appservice_id, user_type,
			       {shadow_banned}, {locked}, {suspended}
			FROM users
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUser {
					name: row.get(0),
					password_hash: row.get(1),
					deactivated: bool_value(&row, 2),
					admin: bool_value(&row, 3),
					appservice_id: row.get(4),
					user_type: row.get(5),
					shadow_banned: bool_value(&row, 6),
					locked: bool_value(&row, 7),
					suspended: bool_value(&row, 8),
				})
				.collect()
		})
	}

	pub fn erased_users(&self) -> Result<Vec<SynapseErasedUser>> {
		if !self.table_exists("erased_users")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id
			FROM erased_users
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseErasedUser { user_id: row.get(0) })
				.collect()
			})
	}

	pub fn registration_tokens(&self) -> Result<Vec<SynapseRegistrationToken>> {
		if !self.table_exists("registration_tokens")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT token, uses_allowed, pending, completed, expiry_time
			FROM registration_tokens
			ORDER BY token
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRegistrationToken {
					token: row.get(0),
					uses_allowed: optional_int_value(&row, 1),
					pending: int_value(&row, 2),
					completed: int_value(&row, 3),
					expiry_time: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn profiles(&self, server_name: Option<&str>) -> Result<Vec<SynapseProfile>> {
		if !self.table_exists("profiles")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("profiles")?;
		let query = if columns.contains("full_user_id") {
			"SELECT user_id, full_user_id, displayname, avatar_url FROM profiles"
		} else {
			"SELECT user_id, NULL::text, displayname, avatar_url FROM profiles"
		};

		self.query(query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| {
					let user_id: String = row.get::<_, Option<String>>(1).unwrap_or_else(|| {
						let localpart = row.get::<_, String>(0);
						full_user_id(&localpart, server_name).unwrap_or(localpart)
					});
					SynapseProfile {
						user_id,
						displayname: row.get(2),
						avatar_url: row.get(3),
					}
				})
				.collect()
		})
	}

	pub fn threepids(&self) -> Result<Vec<SynapseThreepid>> {
		if !self.table_exists("user_threepids")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, medium, address, added_at
			FROM user_threepids
			ORDER BY user_id, added_at DESC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseThreepid {
					user_id: row.get(0),
					medium: row.get(1),
					address: row.get(2),
					added_at: optional_int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn devices(&self) -> Result<Vec<SynapseDevice>> {
		if !self.table_exists("devices")? {
			return Ok(Vec::new());
		}

		let device_columns = self.columns("devices")?;
		let hidden = if device_columns.contains("hidden") {
			"COALESCE(d.hidden, false)"
		} else {
			"false"
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
				LEFT JOIN LATERAL (
					SELECT ip, last_seen
					FROM user_ips
					WHERE user_id = d.user_id AND device_id = d.device_id
					ORDER BY last_seen DESC NULLS LAST, ip DESC NULLS LAST
					LIMIT 1
				) ips ON true
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

		self.query(&query, &[])
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDevice {
					user_id: row.get(0),
					device_id: row.get(1),
					display_name: row.get(2),
					last_seen: optional_int_value(&row, 3),
					ip: row.get(4),
					hidden: bool_value(&row, 5),
				})
				.collect()
			})
	}

	pub fn dehydrated_devices(&self) -> Result<Vec<SynapseDehydratedDevice>> {
		if !self.table_exists("dehydrated_devices")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, device_data
			FROM dehydrated_devices
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDehydratedDevice {
					user_id: row.get(0),
					device_id: row.get(1),
					device_data: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		if !self.table_exists("e2e_device_keys_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, key_json
			FROM e2e_device_keys_json
			ORDER BY user_id, device_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceKey {
					user_id: row.get(0),
					device_id: row.get(1),
					key_json: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn remote_device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		if !self.table_exists("device_lists_remote_cache")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, content
			FROM device_lists_remote_cache
			ORDER BY user_id, device_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceKey {
					user_id: row.get(0),
					device_id: row.get(1),
					key_json: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn one_time_keys(&self) -> Result<Vec<SynapseOneTimeKey>> {
		if !self.table_exists("e2e_one_time_keys_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, algorithm, key_id, key_json
			FROM e2e_one_time_keys_json
			ORDER BY user_id, device_id, algorithm, key_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseOneTimeKey {
					user_id: row.get(0),
					device_id: row.get(1),
					algorithm: row.get(2),
					key_id: row.get(3),
					key_json: json_from_text(&row, 4),
				})
				.collect()
		})
	}

	pub fn fallback_keys(&self) -> Result<Vec<SynapseFallbackKey>> {
		if !self.table_exists("e2e_fallback_keys_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, algorithm, key_id, key_json, used
			FROM e2e_fallback_keys_json
			ORDER BY user_id, device_id, algorithm
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseFallbackKey {
					user_id: row.get(0),
					device_id: row.get(1),
					algorithm: row.get(2),
					key_id: row.get(3),
					key_json: json_from_text(&row, 4),
					used: bool_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn cross_signing_keys(&self) -> Result<Vec<SynapseCrossSigningKey>> {
		if !self.table_exists("e2e_cross_signing_keys")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, keytype, keydata, stream_id
			FROM e2e_cross_signing_keys
			ORDER BY user_id, keytype, stream_id ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseCrossSigningKey {
					user_id: row.get(0),
					key_type: row.get(1),
					key_data: json_from_text(&row, 2),
					stream_id: int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn cross_signing_signatures(&self) -> Result<Vec<SynapseKeySignature>> {
		if !self.table_exists("e2e_cross_signing_signatures")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, key_id, target_user_id, target_device_id, signature
			FROM e2e_cross_signing_signatures
			ORDER BY target_user_id, target_device_id, user_id, key_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseKeySignature {
					user_id: row.get(0),
					key_id: row.get(1),
					target_user_id: row.get(2),
					target_device_id: row.get(3),
					signature: row.get(4),
				})
				.collect()
		})
	}

	pub fn room_key_backup_versions(&self) -> Result<Vec<SynapseRoomKeyBackupVersion>> {
		if !self.table_exists("e2e_room_keys_versions")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("e2e_room_keys_versions")?;
		let etag = if columns.contains("etag") {
			"etag"
		} else {
			"NULL::bigint"
		};
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

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomKeyBackupVersion {
					user_id: row.get(0),
					version: int_value(&row, 1),
					algorithm: row.get(2),
					auth_data: json_from_text(&row, 3),
					etag: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn room_key_backups(&self) -> Result<Vec<SynapseRoomKeyBackup>> {
		if !self.table_exists("e2e_room_keys")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, version, room_id, session_id, first_message_index,
			       forwarded_count, is_verified, session_data
			FROM e2e_room_keys
			ORDER BY user_id, version, room_id, session_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomKeyBackup {
					user_id: row.get(0),
					version: int_value(&row, 1),
					room_id: row.get(2),
					session_id: row.get(3),
					first_message_index: optional_int_value(&row, 4),
					forwarded_count: optional_int_value(&row, 5),
					is_verified: bool_value(&row, 6),
					session_data: json_from_text(&row, 7),
				})
				.collect()
		})
	}

	pub fn to_device_messages(&self) -> Result<Vec<SynapseToDeviceMessage>> {
		if !self.table_exists("device_inbox")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, stream_id, message_json
			FROM device_inbox
			ORDER BY stream_id ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseToDeviceMessage {
					user_id: row.get(0),
					device_id: row.get(1),
					stream_id: int_value(&row, 2),
					message_json: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	pub fn access_tokens(&self) -> Result<Vec<SynapseAccessToken>> {
		if !self.table_exists("access_tokens")? {
			return Ok(Vec::new());
		}

		self.query(
			"SELECT user_id, device_id, token, valid_until_ms FROM access_tokens",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseAccessToken {
					user_id: row.get(0),
					device_id: row.get(1),
					token: row.get(2),
					valid_until_ms: optional_int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn open_id_tokens(&self) -> Result<Vec<SynapseOpenIdToken>> {
		if !self.table_exists("open_id_tokens")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT token, ts_valid_until_ms, user_id
			FROM open_id_tokens
			ORDER BY token
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseOpenIdToken {
					token: row.get(0),
					ts_valid_until_ms: int_value(&row, 1),
					user_id: row.get(2),
				})
				.collect()
		})
	}

	pub fn login_tokens(&self) -> Result<Vec<SynapseLoginToken>> {
		if !self.table_exists("login_tokens")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT token, user_id, expiry_ts, used_ts
			FROM login_tokens
			ORDER BY token
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseLoginToken {
					token: row.get(0),
					user_id: row.get(1),
					expiry_ts: int_value(&row, 2),
					used_ts: optional_int_value(&row, 3),
				})
				.collect()
		})
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
		let enabled_select = if has_enabled { "enable.enabled" } else { "NULL::smallint" };
		let query = format!(
			"
			SELECT rules.user_name, rules.rule_id, rules.priority_class, rules.priority,
			       rules.conditions, rules.actions, {enabled_select}
			FROM push_rules AS rules
			{enabled_join}
			ORDER BY rules.user_name, rules.priority_class DESC, rules.priority DESC, rules.rule_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePushRule {
					user_id: row.get(0),
					rule_id: row.get(1),
					priority_class: int_value(&row, 2),
					priority: int_value(&row, 3),
					conditions: json_from_text(&row, 4),
					actions: json_from_text(&row, 5),
					enabled: optional_bool_value(&row, 6),
				})
				.collect()
		})
	}

	pub fn ignored_users(&self) -> Result<Vec<SynapseIgnoredUser>> {
		if !self.table_exists("ignored_users")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT ignorer_user_id, ignored_user_id
			FROM ignored_users
			ORDER BY ignorer_user_id, ignored_user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseIgnoredUser {
					ignorer_user_id: row.get(0),
					ignored_user_id: row.get(1),
				})
				.collect()
		})
	}

	pub fn room_tags(&self) -> Result<Vec<SynapseRoomTag>> {
		if !self.table_exists("room_tags")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, room_id, tag, content
			FROM room_tags
			ORDER BY user_id, room_id, tag
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomTag {
					user_id: row.get(0),
					room_id: row.get(1),
					tag: row.get(2),
					content: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	pub fn filters(&self, server_name: Option<&str>) -> Result<Vec<SynapseFilter>> {
		if !self.table_exists("user_filters")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("user_filters")?;
		let full_user_id_column = if columns.contains("full_user_id") {
			"full_user_id"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT user_id, {full_user_id_column}, filter_id, filter_json
			FROM user_filters
			ORDER BY user_id, filter_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| {
					let user_id: String = row.get::<_, Option<String>>(1).unwrap_or_else(|| {
						let localpart = row.get::<_, String>(0);
						full_user_id(&localpart, server_name).unwrap_or(localpart)
					});

					SynapseFilter {
						user_id,
						filter_id: int_value(&row, 2),
						filter_json: json_from_bytes(&row, 3),
					}
				})
				.collect()
		})
	}

	pub fn presence(&self) -> Result<Vec<SynapsePresence>> {
		if !self.table_exists("presence_stream")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id, user_id, state, last_active_ts, status_msg, currently_active
			FROM presence_stream
			ORDER BY user_id, stream_id ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePresence {
					stream_id: int_value(&row, 0),
					user_id: row.get(1),
					state: row.get(2),
					last_active_ts: optional_int_value(&row, 3),
					status_msg: row.get(4),
					currently_active: optional_bool_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn media(
		&self,
		media_store: &Path,
		backup_media_store: Option<&Path>,
		server_name: &str,
	) -> Result<Vec<SynapseMedia>> {
		let mut media = Vec::new();

		if self.table_exists("local_media_repository")? {
			media.extend(self.query(
				"
				SELECT media_id, media_type, upload_name, user_id
				FROM local_media_repository
				WHERE COALESCE(url_cache, '') = ''
				",
				&[],
			)?
			.into_iter()
			.map(|row| {
				let media_id: String = row.get(0);
				SynapseMedia {
					mxc_server: server_name.to_owned(),
					filesystem_id: media_id.clone(),
					source_path: local_media_path(media_store, &media_id),
					backup_source_path: backup_media_store
						.map(|media_store| local_media_path(media_store, &media_id)),
					media_id,
					content_type: row.get(1),
					upload_name: row.get(2),
					user_id: row.get(3),
				}
			}));
		}

		if self.table_exists("remote_media_cache")? {
			media.extend(self.query(
				"
				SELECT media_origin, media_id, media_type, upload_name,
				       COALESCE(filesystem_id, media_id)
				FROM remote_media_cache
				",
				&[],
			)?
			.into_iter()
			.map(|row| {
				let media_origin: String = row.get(0);
				let media_id: String = row.get(1);
				let filesystem_id: String = row.get(4);
				SynapseMedia {
					source_path: remote_media_path(media_store, &media_origin, &filesystem_id),
					backup_source_path: backup_media_store.map(|media_store| {
						remote_media_path(media_store, &media_origin, &filesystem_id)
					}),
					mxc_server: media_origin,
					media_id,
					filesystem_id,
					content_type: row.get(2),
					upload_name: row.get(3),
					user_id: None,
				}
			}));
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
			thumbnails.extend(self.query(
				"
				SELECT media_id, thumbnail_width, thumbnail_height,
				       thumbnail_type, COALESCE(thumbnail_method, 'scale')
				FROM local_media_repository_thumbnails
				",
				&[],
			)?
			.into_iter()
			.map(|row| {
				let media_id: String = row.get(0);
				let content_type: Option<String> = row.get(3);
				let method: String = row.get(4);
				let width = i64::from(row.get::<_, i32>(1));
				let height = i64::from(row.get::<_, i32>(2));
				SynapseMediaThumbnail {
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
				}
			}));
		}

		if self.table_exists("remote_media_cache_thumbnails")? {
			thumbnails.extend(self.query(
				"
				SELECT media_origin, media_id, thumbnail_width, thumbnail_height,
				       thumbnail_type, COALESCE(thumbnail_method, 'scale'), COALESCE(filesystem_id, media_id)
				FROM remote_media_cache_thumbnails
				",
				&[],
			)?
			.into_iter()
			.map(|row| {
				let media_origin: String = row.get(0);
				let media_id: String = row.get(1);
				let content_type: Option<String> = row.get(4);
				let method: String = row.get(5);
				let filesystem_id: String = row.get(6);
				let width = i64::from(row.get::<_, i32>(2));
				let height = i64::from(row.get::<_, i32>(3));
				SynapseMediaThumbnail {
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
				}
			}));
		}

		Ok(thumbnails)
	}

	pub fn url_previews(&self) -> Result<Vec<SynapseUrlPreview>> {
		if !self.table_exists("local_media_repository_url_cache")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT url, download_ts, og
			FROM local_media_repository_url_cache
			WHERE og IS NOT NULL
			ORDER BY url, download_ts
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUrlPreview {
					url: row.get(0),
					download_ts: optional_int_value(&row, 1),
					og: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn room_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT e.event_id, e.room_id, e.stream_ordering, ej.json
			FROM events e
			JOIN event_json ej ON e.event_id = ej.event_id
			WHERE COALESCE(e.outlier, false) = false
			  AND e.rejection_reason IS NULL
			  AND e.stream_ordering > 0
			ORDER BY e.stream_ordering ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	pub fn for_each_room_events_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseRoomEvent>) -> Result<()>,
	{
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(());
		}

		let mut last_stream_ordering = 0_i64;
		loop {
			let rows = self.query(
				"
				SELECT e.event_id, e.room_id, e.stream_ordering, ej.json
				FROM events e
				JOIN event_json ej ON e.event_id = ej.event_id
				WHERE COALESCE(e.outlier, false) = false
				  AND e.rejection_reason IS NULL
				  AND e.stream_ordering > $1
				ORDER BY e.stream_ordering ASC
				LIMIT $2
				",
				&[&last_stream_ordering, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_stream_ordering) = rows.last().map(|row| int_value(row, 2)) else {
				break;
			};
			let events = rows
				.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect();
			f(events)?;
			last_stream_ordering = next_stream_ordering;
		}

		Ok(())
	}

	pub fn outlier_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT e.event_id, e.room_id, COALESCE(e.stream_ordering, 0), ej.json
			FROM events e
			JOIN event_json ej ON e.event_id = ej.event_id
			WHERE COALESCE(e.outlier, false) != false
			  AND e.rejection_reason IS NULL
			ORDER BY e.event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	pub fn for_each_outlier_events_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseRoomEvent>) -> Result<()>,
	{
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(());
		}

		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT e.event_id, e.room_id, COALESCE(e.stream_ordering, 0), ej.json
				FROM events e
				JOIN event_json ej ON e.event_id = ej.event_id
				WHERE COALESCE(e.outlier, false) != false
				  AND e.rejection_reason IS NULL
				  AND e.event_id > $1
				ORDER BY e.event_id
				LIMIT $2
				",
				&[&last_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_event_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let events = rows
				.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect();
			f(events)?;
			last_event_id = next_event_id;
		}

		Ok(())
	}

	pub fn backfilled_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT e.event_id, e.room_id, e.stream_ordering, ej.json
			FROM events e
			JOIN event_json ej ON e.event_id = ej.event_id
			WHERE COALESCE(e.outlier, false) = false
			  AND e.rejection_reason IS NULL
			  AND e.stream_ordering < 0
			ORDER BY e.stream_ordering DESC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	pub fn for_each_backfilled_events_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseRoomEvent>) -> Result<()>,
	{
		if !self.table_exists("events")? || !self.table_exists("event_json")? {
			return Ok(());
		}

		let mut last_stream_ordering = 0_i64;
		loop {
			let rows = self.query(
				"
				SELECT e.event_id, e.room_id, e.stream_ordering, ej.json
				FROM events e
				JOIN event_json ej ON e.event_id = ej.event_id
				WHERE COALESCE(e.outlier, false) = false
				  AND e.rejection_reason IS NULL
				  AND e.stream_ordering < $1
				ORDER BY e.stream_ordering DESC
				LIMIT $2
				",
				&[&last_stream_ordering, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_stream_ordering) = rows.last().map(|row| int_value(row, 2)) else {
				break;
			};
			let events = rows
				.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
					json: json_from_text(&row, 3),
				})
				.collect();
			f(events)?;
			last_stream_ordering = next_stream_ordering;
		}

		Ok(())
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
			WHERE edges.is_state = false
			ORDER BY edges.event_id, edges.prev_event_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventEdge {
					event_id: row.get(0),
					prev_event_id: row.get(1),
					room_id: row.get(2),
				})
				.collect()
		})
	}

	pub fn for_each_event_edges_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseEventEdge>) -> Result<()>,
	{
		if !self.table_exists("event_edges")? {
			return Ok(());
		}

		let events_exist = self.table_exists("events")?;
		let events_join = if events_exist {
			"LEFT JOIN events ON events.event_id = batch.event_id"
		} else {
			""
		};
		let room_id = if events_exist {
			"COALESCE(batch.room_id, events.room_id)"
		} else {
			"batch.room_id"
		};
		let query = format!(
			"
			WITH batch AS MATERIALIZED (
				SELECT edges.event_id, edges.prev_event_id, edges.room_id
				FROM event_edges AS edges
				WHERE edges.is_state = false
				  AND (edges.event_id, edges.prev_event_id) > ($1, $2)
				ORDER BY edges.event_id, edges.prev_event_id
				LIMIT $3
			)
			SELECT batch.event_id, batch.prev_event_id, {room_id}
			FROM batch
			{events_join}
			ORDER BY batch.event_id, batch.prev_event_id
			LIMIT $3
			"
		);

		let mut last_event_id = String::new();
		let mut last_prev_event_id = String::new();
		loop {
			let rows = self.query(
				&query,
				&[&last_event_id, &last_prev_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some((next_event_id, next_prev_event_id)) = rows
				.last()
				.map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
			else {
				break;
			};
			let edges = rows
				.into_iter()
				.map(|row| SynapseEventEdge {
					event_id: row.get(0),
					prev_event_id: row.get(1),
					room_id: row.get(2),
				})
				.collect();
			f(edges)?;
			last_event_id = next_event_id;
			last_prev_event_id = next_prev_event_id;
		}

		Ok(())
	}

	pub fn soft_failed_events(&self) -> Result<Vec<SynapseSoftFailedEvent>> {
		if !self.table_exists("event_json")? || !self.columns("event_json")?.contains("internal_metadata") {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, internal_metadata
			FROM event_json
			WHERE internal_metadata IS NOT NULL
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.filter_map(|row| {
					let metadata = json_from_text(&row, 1);
					metadata
						.get("soft_failed")
						.and_then(Value::as_bool)
						.unwrap_or(false)
						.then(|| SynapseSoftFailedEvent {
							event_id: row.get(0),
						})
				})
				.collect()
		})
	}

	pub fn for_each_soft_failed_events_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseSoftFailedEvent>) -> Result<()>,
	{
		if !self.table_exists("event_json")? || !self.columns("event_json")?.contains("internal_metadata") {
			return Ok(());
		}

		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT event_id, internal_metadata
				FROM event_json
				WHERE internal_metadata IS NOT NULL
				  AND event_id > $1
				ORDER BY event_id
				LIMIT $2
				",
				&[&last_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_event_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let events = rows
				.into_iter()
				.filter_map(|row| {
					let metadata = json_from_text(&row, 1);
					metadata
						.get("soft_failed")
						.and_then(Value::as_bool)
						.unwrap_or(false)
						.then(|| SynapseSoftFailedEvent {
							event_id: row.get(0),
						})
				})
				.collect();
			f(events)?;
			last_event_id = next_event_id;
		}

		Ok(())
	}

	pub fn forward_extremities(&self) -> Result<Vec<SynapseForwardExtremity>> {
		if !self.table_exists("event_forward_extremities")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, room_id
			FROM event_forward_extremities
			ORDER BY room_id, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseForwardExtremity {
					event_id: row.get(0),
					room_id: row.get(1),
				})
				.collect()
			})
	}

	pub fn event_relations(&self) -> Result<Vec<SynapseEventRelation>> {
		if !self.table_exists("event_relations")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, relates_to_id, relation_type, aggregation_key
			FROM event_relations
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventRelation {
					event_id: row.get(0),
					relates_to_id: row.get(1),
					relation_type: row.get(2),
					aggregation_key: row.get(3),
				})
				.collect()
		})
	}

	pub fn event_transactions(&self) -> Result<Vec<SynapseEventTransaction>> {
		let mut transactions = Vec::new();

		if self.table_exists("event_txn_id_device_id")? {
			transactions.extend(
				self.query(
					"
					SELECT event_id, room_id, user_id, device_id, txn_id, inserted_ts
					FROM event_txn_id_device_id
					ORDER BY inserted_ts, event_id
					",
					&[],
				)?
				.into_iter()
				.map(|row| SynapseEventTransaction {
					event_id: row.get(0),
					room_id: row.get(1),
					user_id: row.get(2),
					device_id: row.get(3),
					txn_id: row.get(4),
					inserted_ts: int_value(&row, 5),
				}),
			);
		}

		if self.table_exists("event_txn_id")? {
			let has_access_token_ids =
				self.table_exists("access_tokens")? && self.columns("access_tokens")?.contains("id");
			let device_id = if has_access_token_ids {
				"tokens.device_id"
			} else {
				"NULL::text"
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
			transactions.extend(self.query(&query, &[])?.into_iter().map(|row| {
				SynapseEventTransaction {
					event_id: row.get(0),
					room_id: row.get(1),
					user_id: row.get(2),
					device_id: row.get(3),
					txn_id: row.get(4),
					inserted_ts: int_value(&row, 5),
				}
			}));
		}

		Ok(transactions)
	}

	pub fn redactions(&self) -> Result<Vec<SynapseRedaction>> {
		if !self.table_exists("redactions")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, redacts
			FROM redactions
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRedaction {
					event_id: row.get(0),
					redacts: row.get(1),
				})
				.collect()
		})
	}

	pub fn room_state(&self) -> Result<Vec<SynapseRoomState>> {
		if !self.table_exists("current_state_events")? {
			return Ok(Vec::new());
		}

		let has_events = self.table_exists("events")?;
		let has_event_json = self.table_exists("event_json")?;
		let stream_ordering = if has_events {
			"e.stream_ordering"
		} else {
			"NULL::bigint"
		};
		let event_json = if has_event_json { "ej.json" } else { "NULL::text" };
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

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomState {
					event_id: row.get(0),
					room_id: row.get(1),
					event_type: row.get(2),
					state_key: row.get(3),
					membership: row.get(4),
					stream_ordering: optional_int_value(&row, 5),
					json: optional_json_from_text(&row, 6),
				})
				.collect()
		})
	}

	pub fn room_retention(&self) -> Result<Vec<SynapseRoomRetention>> {
		if !self.table_exists("room_retention")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, event_id, min_lifetime, max_lifetime
			FROM room_retention
			ORDER BY room_id, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomRetention {
					room_id: row.get(0),
					event_id: row.get(1),
					min_lifetime: optional_int_value(&row, 2),
					max_lifetime: optional_int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn event_expiry(&self) -> Result<Vec<SynapseEventExpiry>> {
		if !self.table_exists("event_expiry")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, expiry_ts
			FROM event_expiry
			ORDER BY expiry_ts, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventExpiry {
					event_id: row.get(0),
					expiry_ts: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn forgotten_rooms(&self) -> Result<Vec<SynapseForgottenRoom>> {
		if !self.table_exists("room_memberships")? {
			return Ok(Vec::new());
		}

		self.query(
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
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseForgottenRoom {
					user_id: row.get(0),
					room_id: row.get(1),
				})
				.collect()
		})
	}

	pub fn blocked_rooms(&self) -> Result<Vec<SynapseBlockedRoom>> {
		if !self.table_exists("blocked_rooms")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT DISTINCT room_id
			FROM blocked_rooms
			ORDER BY room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseBlockedRoom { room_id: row.get(0) })
				.collect()
		})
	}

	pub fn room_aliases(&self) -> Result<Vec<SynapseRoomAlias>> {
		if !self.table_exists("room_aliases")? {
			return Ok(Vec::new());
		}

		let mut servers = BTreeMap::<String, Vec<String>>::new();
		if self.table_exists("room_alias_servers")? {
			for row in self.query(
				"
				SELECT room_alias, server
				FROM room_alias_servers
				ORDER BY room_alias, server
				",
				&[],
			)? {
				servers
					.entry(row.get::<_, String>(0))
					.or_default()
					.push(row.get(1));
			}
		}

		self.query(
			"
			SELECT room_alias, room_id, creator
			FROM room_aliases
			ORDER BY room_alias
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| {
					let room_alias: String = row.get(0);
					SynapseRoomAlias {
						room_id: row.get(1),
						creator: row.get(2),
						servers: servers.remove(&room_alias).unwrap_or_default(),
						room_alias,
					}
				})
				.collect()
		})
	}

	pub fn public_rooms(&self) -> Result<Vec<SynapsePublicRoom>> {
		let mut room_ids = BTreeSet::<String>::new();

		if self.table_exists("rooms")? {
			room_ids.extend(
				self.query(
					"
					SELECT room_id
					FROM rooms
					WHERE COALESCE(is_public, false) != false
					ORDER BY room_id
					",
					&[],
				)?
				.into_iter()
				.map(|row| row.get::<_, String>(0)),
			);
		}

		if self.table_exists("appservice_room_list")? {
			room_ids.extend(
				self.query(
					"
					SELECT room_id
					FROM appservice_room_list
					ORDER BY room_id
					",
					&[],
				)?
				.into_iter()
				.map(|row| row.get::<_, String>(0)),
			);
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

		self.query(
			"
			SELECT stream_id, room_id, receipt_type, user_id, event_id, thread_id,
			       event_stream_ordering, data
			FROM receipts_linearized
			WHERE receipt_type IN ('m.read', 'm.read.private')
			ORDER BY stream_id ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseReceipt {
					stream_id: int_value(&row, 0),
					room_id: row.get(1),
					receipt_type: row.get(2),
					user_id: row.get(3),
					event_id: row.get(4),
					thread_id: row.get(5),
					event_stream_ordering: optional_int_value(&row, 6),
					data: json_from_text(&row, 7),
				})
				.collect()
			})
	}

	pub fn notification_counts(&self) -> Result<Vec<SynapseNotificationCount>> {
		let mut counts = BTreeMap::<(String, String), (i64, i64)>::new();

		if self.table_exists("event_push_summary")? {
			for row in self.query(
				"
				SELECT user_id, room_id, SUM(notif_count)
				FROM event_push_summary
				GROUP BY user_id, room_id
				ORDER BY user_id, room_id
				",
				&[],
			)? {
				counts
					.entry((row.get(0), row.get(1)))
					.or_default()
					.0 = optional_int_value(&row, 2).unwrap_or_default();
			}
		}

		if self.table_exists("event_push_actions")?
			&& self.columns("event_push_actions")?.contains("highlight")
		{
			for row in self.query(
				"
				SELECT user_id, room_id, COUNT(*)
				FROM event_push_actions
				WHERE COALESCE(highlight, 0) = 1
				GROUP BY user_id, room_id
				ORDER BY user_id, room_id
				",
				&[],
			)? {
				counts
					.entry((row.get(0), row.get(1)))
					.or_default()
					.1 = int_value(&row, 2);
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
			"COALESCE(enabled, true)"
		} else {
			"true"
		};
		let device_id = if columns.contains("device_id") {
			"device_id"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT user_name, profile_tag, kind, app_id, app_display_name,
			       device_display_name, pushkey, lang, data, {device_id}
			FROM pushers
			WHERE {enabled} != false
			ORDER BY user_name, app_id, pushkey
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePusher {
					user_id: row.get(0),
					profile_tag: row.get(1),
					kind: row.get(2),
					app_id: row.get(3),
					app_display_name: row.get(4),
					device_display_name: row.get(5),
					pushkey: row.get(6),
					lang: row.get(7),
					data: optional_json_from_text(&row, 8).unwrap_or(Value::Null),
					device_id: row.get(9),
				})
				.collect()
		})
	}

	pub fn server_keys(&self) -> Result<Vec<SynapseServerKey>> {
		if !self.table_exists("server_keys_json")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT server_name, key_id, ts_added_ms, ts_valid_until_ms, key_json
			FROM server_keys_json
			ORDER BY server_name, ts_added_ms ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseServerKey {
					server_name: row.get(0),
					key_id: row.get(1),
					ts_added_ms: int_value(&row, 2),
					ts_valid_until_ms: int_value(&row, 3),
					key_json: json_from_bytes(&row, 4),
				})
				.collect()
		})
	}

	fn account_data_from_table(
		&self,
		table: &str,
		room_scoped: bool,
	) -> Result<Vec<SynapseAccountData>> {
		let query = if room_scoped {
			format!("SELECT user_id, room_id, account_data_type, content FROM {table}")
		} else {
			format!("SELECT user_id, NULL::text, account_data_type, content FROM {table}")
		};

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseAccountData {
					user_id: row.get(0),
					room_id: row.get(1),
					event_type: row.get(2),
					content: json_from_text(&row, 3),
				})
				.collect()
		})
	}

	fn table_exists(&self, table: &str) -> Result<bool> {
		let rows = self.query("SELECT to_regclass($1) IS NOT NULL", &[&table])?;
		Ok(rows.first().is_some_and(|row| row.get::<_, bool>(0)))
	}

	fn columns(&self, table: &str) -> Result<BTreeSet<String>> {
		self.query(
			"
			SELECT column_name
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1
			",
			&[&table],
		)
		.map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
	}

	fn query(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
		self.client
			.borrow_mut()
			.query(query, params)
			.map_err(Into::into)
	}
}

fn bool_value(row: &Row, index: usize) -> bool {
	row.try_get::<_, bool>(index)
		.or_else(|_| row.try_get::<_, i16>(index).map(|value| value != 0))
		.or_else(|_| row.try_get::<_, i32>(index).map(|value| value != 0))
		.or_else(|_| row.try_get::<_, i64>(index).map(|value| value != 0))
		.unwrap_or_default()
}

fn int_value(row: &Row, index: usize) -> i64 {
	row.try_get::<_, i64>(index)
		.or_else(|_| row.try_get::<_, i32>(index).map(i64::from))
		.or_else(|_| row.try_get::<_, i16>(index).map(i64::from))
		.unwrap_or_default()
}

fn optional_int_value(row: &Row, index: usize) -> Option<i64> {
	row.try_get::<_, Option<i64>>(index)
		.or_else(|_| {
			row.try_get::<_, Option<i32>>(index)
				.map(|value| value.map(i64::from))
		})
		.or_else(|_| {
			row.try_get::<_, Option<i16>>(index)
				.map(|value| value.map(i64::from))
		})
		.unwrap_or_default()
}

fn optional_bool_value(row: &Row, index: usize) -> Option<bool> {
	row.try_get::<_, Option<bool>>(index)
		.or_else(|_| {
			row.try_get::<_, Option<i16>>(index)
				.map(|value| value.map(|value| value != 0))
		})
		.or_else(|_| {
			row.try_get::<_, Option<i32>>(index)
				.map(|value| value.map(|value| value != 0))
		})
		.or_else(|_| {
			row.try_get::<_, Option<i64>>(index)
				.map(|value| value.map(|value| value != 0))
		})
		.unwrap_or_default()
}

fn json_from_text(row: &Row, index: usize) -> Value {
	row.try_get::<_, String>(index)
		.ok()
		.and_then(|json| serde_json::from_str(&json).ok())
		.unwrap_or(Value::Null)
}

fn optional_json_from_text(row: &Row, index: usize) -> Option<Value> {
	row.try_get::<_, Option<String>>(index)
		.ok()
		.flatten()
		.and_then(|json| serde_json::from_str(&json).ok())
}

fn json_from_bytes(row: &Row, index: usize) -> Value {
	row.try_get::<_, Vec<u8>>(index)
		.ok()
		.and_then(|json| serde_json::from_slice(&json).ok())
		.unwrap_or(Value::Null)
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

#[cfg(test)]
mod tests {
	use std::{
		cell::RefCell,
		env,
		process,
	};

	use postgres::{Client, NoTls};

	use super::PostgresSource;

	#[test]
	fn imports_room_key_backups_from_synapse_int4_columns_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE e2e_room_keys_versions (
					user_id TEXT NOT NULL,
					version INTEGER NOT NULL,
					algorithm TEXT NOT NULL,
					auth_data TEXT NOT NULL,
					deleted SMALLINT DEFAULT 0 NOT NULL,
					etag INTEGER
				);
				INSERT INTO e2e_room_keys_versions VALUES (
					'@alice:example.com',
					1,
					'm.megolm_backup.v1.curve25519-aes-sha2',
					'{{"public_key":"backup-public-key"}}',
					0,
					99
				);

				CREATE TABLE e2e_room_keys (
					user_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					session_id TEXT NOT NULL,
					version INTEGER NOT NULL,
					first_message_index INTEGER,
					forwarded_count INTEGER,
					is_verified BOOLEAN,
					session_data TEXT NOT NULL
				);
				INSERT INTO e2e_room_keys VALUES (
					'@alice:example.com',
					'!room:example.com',
					'SESSION',
					1,
					7,
					2,
					true,
					'{{"ciphertext":"cipher","mac":"mac","ephemeral":"key"}}'
				);
				"#
			))
			.expect("seed postgres e2e room key tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let versions = source
			.room_key_backup_versions()
			.expect("read postgres room key backup versions");
		assert_eq!(versions.len(), 1);
		assert_eq!(versions[0].version, 1);
		assert_eq!(versions[0].etag, Some(99));

		let keys = source
			.room_key_backups()
			.expect("read postgres room key backups");
		assert_eq!(keys.len(), 1);
		assert_eq!(keys[0].version, 1);
		assert_eq!(keys[0].first_message_index, Some(7));
		assert_eq!(keys[0].forwarded_count, Some(2));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_retention_and_expiry_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_retention_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE room_retention (
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					min_lifetime BIGINT,
					max_lifetime BIGINT
				);
				INSERT INTO room_retention VALUES (
					'!room:example.com',
					'$retention:example.com',
					1000,
					2000
				);

				CREATE TABLE event_expiry (
					event_id TEXT NOT NULL,
					expiry_ts BIGINT NOT NULL
				);
				INSERT INTO event_expiry VALUES (
					'$event:example.com',
					4102444800000
				);
				"#
			))
			.expect("seed postgres retention tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let retention = source.room_retention().expect("read postgres room retention");
		assert_eq!(retention.len(), 1);
		assert_eq!(retention[0].room_id, "!room:example.com");
		assert_eq!(retention[0].event_id, "$retention:example.com");
		assert_eq!(retention[0].min_lifetime, Some(1000));
		assert_eq!(retention[0].max_lifetime, Some(2000));

		let expiry = source.event_expiry().expect("read postgres event expiry");
		assert_eq!(expiry.len(), 1);
		assert_eq!(expiry[0].event_id, "$event:example.com");
		assert_eq!(expiry[0].expiry_ts, 4102444800000);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_event_transaction_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_txn_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE access_tokens (
					id BIGINT PRIMARY KEY,
					user_id TEXT NOT NULL,
					device_id TEXT,
					token TEXT NOT NULL
				);
				INSERT INTO access_tokens VALUES (
					1,
					'@alice:example.com',
					'DEVICE',
					'token'
				);

				CREATE TABLE event_txn_id_device_id (
					event_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					txn_id TEXT NOT NULL,
					inserted_ts BIGINT NOT NULL
				);
				INSERT INTO event_txn_id_device_id VALUES (
					'$event:example.com',
					'!room:example.com',
					'@alice:example.com',
					'DEVICE',
					'txn-device',
					100
				);

				CREATE TABLE event_txn_id (
					event_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					token_id BIGINT NOT NULL,
					txn_id TEXT NOT NULL,
					inserted_ts BIGINT NOT NULL
				);
				INSERT INTO event_txn_id VALUES (
					'$thread:example.com',
					'!room:example.com',
					'@alice:example.com',
					1,
					'txn-token',
					101
				);
				"#
			))
			.expect("seed postgres transaction tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let transactions = source.event_transactions().expect("read postgres transactions");
		assert_eq!(transactions.len(), 2);
		assert_eq!(transactions[0].event_id, "$event:example.com");
		assert_eq!(transactions[0].device_id.as_deref(), Some("DEVICE"));
		assert_eq!(transactions[0].txn_id, "txn-device");
		assert_eq!(transactions[1].event_id, "$thread:example.com");
		assert_eq!(transactions[1].device_id.as_deref(), Some("DEVICE"));
		assert_eq!(transactions[1].txn_id, "txn-token");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}
}
