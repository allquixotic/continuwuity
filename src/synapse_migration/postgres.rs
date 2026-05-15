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
		SynapseAccessToken, SynapseAccountData, SynapseCrossSigningKey, SynapseDevice,
		SynapseDehydratedDevice, SynapseDeviceKey, SynapseErasedUser, SynapseEventRelation,
		SynapseFallbackKey, SynapseFilter, SynapseForgottenRoom, SynapseKeySignature,
		SynapseMedia, SynapseOneTimeKey, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapseReceipt, SynapseRedaction, SynapseRegistrationToken,
		SynapseNotificationCount, SynapseRoomAlias, SynapseRoomEvent, SynapseRoomKeyBackup,
		SynapseRoomKeyBackupVersion, SynapseRoomState, SynapseServerKey, SynapseThreepid,
		SynapseToDeviceMessage, SynapseUser,
	},
};

pub struct PostgresSource {
	client: RefCell<Client>,
}

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

		self.query(
			"
			SELECT name, password_hash, COALESCE(deactivated, 0), admin, appservice_id, user_type,
			       COALESCE(shadow_banned, false)
			FROM users
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUser {
					name: row.get(0),
					password_hash: row.get(1),
					deactivated: bool_value(&row, 2),
					admin: bool_value(&row, 3),
					appservice_id: row.get(4),
					user_type: row.get(5),
					shadow_banned: bool_value(&row, 6),
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
					uses_allowed: row.get(1),
					pending: row.get(2),
					completed: row.get(3),
					expiry_time: row.get(4),
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
					added_at: row.get(3),
				})
				.collect()
		})
	}

	pub fn devices(&self) -> Result<Vec<SynapseDevice>> {
		if !self.table_exists("devices")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, display_name, last_seen, ip, COALESCE(hidden, false)
			FROM devices
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDevice {
					user_id: row.get(0),
					device_id: row.get(1),
					display_name: row.get(2),
					last_seen: row.get(3),
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
					stream_id: row.get(3),
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
					version: row.get(1),
					algorithm: row.get(2),
					auth_data: json_from_text(&row, 3),
					etag: row.get(4),
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
					version: row.get(1),
					room_id: row.get(2),
					session_id: row.get(3),
					first_message_index: row.get(4),
					forwarded_count: row.get(5),
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
					stream_id: row.get(2),
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
					valid_until_ms: row.get(3),
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
						filter_id: row.get(2),
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
					stream_id: row.get(0),
					user_id: row.get(1),
					state: row.get(2),
					last_active_ts: row.get(3),
					status_msg: row.get(4),
					currently_active: optional_bool_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn media(&self, media_store: &Path, server_name: &str) -> Result<Vec<SynapseMedia>> {
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
			ORDER BY e.stream_ordering ASC
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomEvent {
					event_id: row.get(0),
					room_id: row.get(1),
					stream_ordering: row.get(2),
					json: json_from_text(&row, 3),
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
					stream_ordering: row.get(5),
					json: optional_json_from_text(&row, 6),
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
					stream_id: row.get(0),
					room_id: row.get(1),
					receipt_type: row.get(2),
					user_id: row.get(3),
					event_id: row.get(4),
					thread_id: row.get(5),
					event_stream_ordering: row.get(6),
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
					.0 = row.get::<_, Option<i64>>(2).unwrap_or_default();
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
					.1 = row.get(2);
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
					ts_added_ms: row.get(2),
					ts_valid_until_ms: row.get(3),
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

fn slice(value: &str, start: usize, end: usize) -> &str {
	value.get(start..end).unwrap_or_default()
}
