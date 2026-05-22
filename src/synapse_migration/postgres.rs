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
		SynapseAccessToken, SynapseAccountData, SynapseAccountValidity, SynapseBlockedRoom,
		SynapseApplicationServiceRoom, SynapseApplicationServiceState,
		SynapseApplicationServiceStreamPosition, SynapseApplicationServiceTxn,
		SynapseCrossSigningKey, SynapseCurrentStateDelta, SynapseDevice, SynapseDeviceAuthProvider, SynapseDehydratedDevice,
		SynapseDeletedPusher, SynapseDeviceFederationInbox, SynapseDeviceFederationOutbox,
		SynapseDeviceKey, SynapseDeviceListChangeInRoom, SynapseDeviceListChangesConvertedPosition,
		SynapseDeviceListChangesMaxPruned, SynapseDeviceListOutboundLastSuccess,
		SynapseDeviceListOutboundPoke, SynapseDeviceListRemoteExtremity,
		SynapseDeviceListRemotePending, SynapseDeviceListRemoteResync,
		SynapseDeviceListStreamUpdate,
		SynapseCacheInvalidation, SynapseDestination, SynapseDestinationRoom,
		SynapseBackwardExtremity, SynapseErasedUser, SynapseEventAuth, SynapseEventAuthChain,
		SynapseEventAuthChainLink, SynapseEventAuthChainToCalculate, SynapseEventEdge,
		SynapseEventExpiry, SynapseEventRelation, SynapseEventReport, SynapseEventToStateGroup,
		SynapseEventFailedPullAttempt, SynapseEventPushAction, SynapseEventPushActionStaging,
		SynapseEventPushSummary, SynapseEventPushSummaryStreamPosition, SynapseEventTransaction,
		SynapseExOutlierStream, SynapseFallbackKey, SynapseFederationInboundEvent, SynapseFederationStreamPosition,
		SynapseFilter, SynapseForgottenRoom, SynapseForwardExtremity, SynapseIgnoredUser, SynapseKeySignature,
		SynapseLocalCurrentMembership, SynapseLoginToken, SynapseMedia, SynapseMediaThumbnail,
		SynapseMonthlyActiveUser, SynapseNotificationCount,
		SynapseOneTimeKey, SynapseOpenIdToken, SynapsePartialStateEvent, SynapsePartialStateRoom,
		SynapsePartialStateRoomServer, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapsePushRule, SynapsePushRulesStream, SynapseRatelimitOverride, SynapseReceipt, SynapseReceiptGraph, SynapseRedaction,
		SynapseReceivedTransaction, SynapseRejectedEvent, SynapseRegistrationToken,
		SynapseRoomStatsCurrent, SynapseRoomStatsEarliestToken, SynapseRoomStatsState,
		SynapseRoomAlias, SynapseRoomEvent, SynapseRoomKeyBackup, SynapseRoomKeyBackupVersion,
		SynapseRoomDepth, SynapseRoomMetadata, SynapseRoomRetention, SynapseRoomState,
		SynapseRoomTag, SynapseRoomTagRevision, SynapseServerKey,
		SynapseServerSignatureKey, SynapseSoftFailedEvent,
		SynapseSlidingSyncConnection, SynapseSlidingSyncConnectionLazyMember,
		SynapseSlidingSyncConnectionPosition, SynapseSlidingSyncConnectionRequiredState,
		SynapseSlidingSyncConnectionRoomConfig, SynapseSlidingSyncConnectionStream,
		SynapseSlidingSyncJoinedRoom, SynapseSlidingSyncJoinedRoomToRecalculate,
		SynapseSlidingSyncMembershipSnapshot,
		SynapseDelayedEventsStreamPosition, SynapseEventPushSummaryLastReceiptStreamId,
		SynapseRoomForgetterStreamPosition, SynapseStatsIncrementalPosition,
		SynapseStreamPosition,
		SynapseAppliedSchemaDelta, SynapseBackgroundUpdate, SynapseScheduledTask,
		SynapseSchemaCompatVersion, SynapseSchemaVersion,
		SynapseStateEvent, SynapseStateGroup, SynapseStateGroupEdge, SynapseStateGroupState,
		SynapseStreamOrderingExtremity, SynapseThreepid, SynapseThreepidIdServer, SynapseThread, SynapseToDeviceMessage, SynapseUiAuthSession, SynapseUiAuthSessionCredential,
		SynapseTimelineGap, SynapseUiAuthSessionIp, SynapseUnPartialStatedEvent,
		SynapseUnPartialStatedRoom, SynapseUrlPreview, SynapseUser, SynapseUserDirectoryEntry,
		SynapseUserDirectorySearch, SynapseUserDirectoryStaleRemoteUser,
		SynapseUserDirectoryStreamPosition, SynapseUserExternalId, SynapseUserDailyVisit,
		SynapseThreepidValidationSession,
		SynapseUserIp, SynapseUserSignatureStream, SynapseUserStatsCurrent,
		SynapseUsersInPublicRoom, SynapseUsersWhoSharePrivateRoom,
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

	pub fn account_validity(&self) -> Result<Vec<SynapseAccountValidity>> {
		if !self.table_exists("account_validity")? {
			return Ok(Vec::new());
		}

		let token_used = if self.columns("account_validity")?.contains("token_used_ts_ms") {
			"token_used_ts_ms"
		} else {
			"NULL::bigint"
		};
		let query = format!(
			"
			SELECT user_id, expiration_ts_ms, email_sent, renewal_token, {token_used}
			FROM account_validity
			ORDER BY user_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseAccountValidity {
					user_id: row.get(0),
					expiration_ts_ms: int_value(&row, 1),
					email_sent: bool_value(&row, 2),
					renewal_token: row.get(3),
					token_used_ts_ms: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn ratelimit_overrides(&self) -> Result<Vec<SynapseRatelimitOverride>> {
		if !self.table_exists("ratelimit_override")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, messages_per_second, burst_count
			FROM ratelimit_override
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRatelimitOverride {
					user_id: row.get(0),
					messages_per_second: optional_int_value(&row, 1),
					burst_count: optional_int_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn monthly_active_users(&self) -> Result<Vec<SynapseMonthlyActiveUser>> {
		if !self.table_exists("monthly_active_users")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, timestamp
			FROM monthly_active_users
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseMonthlyActiveUser {
					user_id: row.get(0),
					timestamp: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn user_daily_visits(&self) -> Result<Vec<SynapseUserDailyVisit>> {
		if !self.table_exists("user_daily_visits")? {
			return Ok(Vec::new());
		}

		let user_agent = if self.columns("user_daily_visits")?.contains("user_agent") {
			"user_agent"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT user_id, device_id, timestamp, {user_agent}
			FROM user_daily_visits
			ORDER BY timestamp, user_id, device_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserDailyVisit {
					user_id: row.get(0),
					device_id: row.get(1),
					timestamp: int_value(&row, 2),
					user_agent: row.get(3),
				})
				.collect()
		})
	}

	pub fn user_ips(&self) -> Result<Vec<SynapseUserIp>> {
		if !self.table_exists("user_ips")? {
			return Ok(Vec::new());
		}

		let device_id = if self.columns("user_ips")?.contains("device_id") {
			"device_id"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT user_id, access_token, {device_id}, ip, user_agent, last_seen
			FROM user_ips
			ORDER BY user_id, access_token, ip, user_agent, last_seen
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserIp {
					user_id: row.get(0),
					access_token: row.get(1),
					device_id: row.get(2),
					ip: row.get(3),
					user_agent: row.get(4),
					last_seen: int_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn user_stats_current(&self) -> Result<Vec<SynapseUserStatsCurrent>> {
		if !self.table_exists("user_stats_current")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, joined_rooms, completed_delta_stream_id
			FROM user_stats_current
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserStatsCurrent {
					user_id: row.get(0),
					joined_rooms: int_value(&row, 1),
					completed_delta_stream_id: int_value(&row, 2),
				})
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

	pub fn threepid_validation_sessions(
		&self,
	) -> Result<Vec<SynapseThreepidValidationSession>> {
		if !self.table_exists("threepid_validation_session")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT session_id, medium, address, client_secret, last_send_attempt, validated_at
			FROM threepid_validation_session
			ORDER BY session_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseThreepidValidationSession {
					session_id: row.get(0),
					medium: row.get(1),
					address: row.get(2),
					client_secret: row.get(3),
					last_send_attempt: int_value(&row, 4),
					validated_at: optional_int_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn user_threepid_id_servers(&self) -> Result<Vec<SynapseThreepidIdServer>> {
		if !self.table_exists("user_threepid_id_server")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, medium, address, id_server
			FROM user_threepid_id_server
			ORDER BY user_id, medium, address, id_server
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseThreepidIdServer {
					user_id: row.get(0),
					medium: row.get(1),
					address: row.get(2),
					id_server: row.get(3),
				})
				.collect()
		})
	}

	pub fn user_external_ids(&self) -> Result<Vec<SynapseUserExternalId>> {
		if !self.table_exists("user_external_ids")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT auth_provider, external_id, user_id
			FROM user_external_ids
			ORDER BY auth_provider, external_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserExternalId {
					auth_provider: row.get(0),
					external_id: row.get(1),
					user_id: row.get(2),
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

	pub fn device_auth_providers(&self) -> Result<Vec<SynapseDeviceAuthProvider>> {
		if !self.table_exists("device_auth_providers")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, device_id, auth_provider_id, auth_provider_session_id
			FROM device_auth_providers
			ORDER BY user_id, device_id, auth_provider_id, auth_provider_session_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceAuthProvider {
					user_id: row.get(0),
					device_id: row.get(1),
					auth_provider_id: row.get(2),
					auth_provider_session_id: row.get(3),
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

	pub fn for_each_remote_device_keys_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseDeviceKey>) -> Result<()>,
	{
		if !self.table_exists("device_lists_remote_cache")? {
			return Ok(());
		}

		let mut last_user_id = String::new();
		let mut last_device_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT user_id, device_id, content
				FROM device_lists_remote_cache
				WHERE (user_id, device_id) > ($1, $2)
				ORDER BY user_id, device_id
				LIMIT $3
				",
				&[&last_user_id, &last_device_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next) = rows
				.last()
				.map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
			else {
				break;
			};
			let keys = rows
				.into_iter()
				.map(|row| SynapseDeviceKey {
					user_id: row.get(0),
					device_id: row.get(1),
					key_json: json_from_text(&row, 2),
				})
				.collect();
			f(keys)?;
			last_user_id = next.0;
			last_device_id = next.1;
		}

		Ok(())
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

	pub fn device_federation_inbox(&self) -> Result<Vec<SynapseDeviceFederationInbox>> {
		if !self.table_exists("device_federation_inbox")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_federation_inbox")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT origin, message_id, received_ts, {instance_name}
			FROM device_federation_inbox
			ORDER BY received_ts, origin, message_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceFederationInbox {
					origin: row.get(0),
					message_id: row.get(1),
					received_ts: int_value(&row, 2),
					instance_name: row.get(3),
				})
				.collect()
		})
	}

	pub fn device_federation_outbox(&self) -> Result<Vec<SynapseDeviceFederationOutbox>> {
		if !self.table_exists("device_federation_outbox")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_federation_outbox")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT destination, stream_id, queued_ts, messages_json, {instance_name}
			FROM device_federation_outbox
			ORDER BY stream_id, destination
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceFederationOutbox {
					destination: row.get(0),
					stream_id: int_value(&row, 1),
					queued_ts: int_value(&row, 2),
					messages_json: json_from_text(&row, 3),
					instance_name: row.get(4),
				})
				.collect()
		})
	}

	pub fn received_transactions(&self) -> Result<Vec<SynapseReceivedTransaction>> {
		if !self.table_exists("received_transactions")? {
			return Ok(Vec::new());
		}

		let has_been_referenced =
			if self.columns("received_transactions")?.contains("has_been_referenced") {
				"has_been_referenced"
			} else {
				"0"
			};
		let query = format!(
			"
			SELECT transaction_id, origin, ts, response_code, response_json, {has_been_referenced}
			FROM received_transactions
			ORDER BY ts, origin, transaction_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseReceivedTransaction {
					transaction_id: row.get(0),
					origin: row.get(1),
					ts: optional_int_value(&row, 2),
					response_code: optional_int_value(&row, 3),
					response_json: row.try_get::<_, Option<Vec<u8>>>(4).ok().flatten(),
					has_been_referenced: bool_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn destinations(&self) -> Result<Vec<SynapseDestination>> {
		if !self.table_exists("destinations")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT destination, retry_last_ts, retry_interval, failure_ts,
			       last_successful_stream_ordering
			FROM destinations
			ORDER BY destination
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDestination {
					destination: row.get(0),
					retry_last_ts: optional_int_value(&row, 1),
					retry_interval: optional_int_value(&row, 2),
					failure_ts: optional_int_value(&row, 3),
					last_successful_stream_ordering: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn destination_rooms(&self) -> Result<Vec<SynapseDestinationRoom>> {
		if !self.table_exists("destination_rooms")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT destination, room_id, stream_ordering
			FROM destination_rooms
			ORDER BY destination, room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDestinationRoom {
					destination: row.get(0),
					room_id: row.get(1),
					stream_ordering: int_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn event_failed_pull_attempts(&self) -> Result<Vec<SynapseEventFailedPullAttempt>> {
		if !self.table_exists("event_failed_pull_attempts")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, event_id, num_attempts, last_attempt_ts, last_cause
			FROM event_failed_pull_attempts
			ORDER BY room_id, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventFailedPullAttempt {
					room_id: row.get(0),
					event_id: row.get(1),
					num_attempts: int_value(&row, 2),
					last_attempt_ts: int_value(&row, 3),
					last_cause: row.get(4),
				})
				.collect()
		})
	}

	pub fn cache_invalidations(&self) -> Result<Vec<SynapseCacheInvalidation>> {
		if !self.table_exists("cache_invalidation_stream_by_instance")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id, instance_name, cache_func, keys, invalidation_ts
			FROM cache_invalidation_stream_by_instance
			ORDER BY stream_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseCacheInvalidation {
					stream_id: int_value(&row, 0),
					instance_name: row.get(1),
					cache_func: row.get(2),
					keys: row.get(3),
					invalidation_ts: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn federation_stream_positions(&self) -> Result<Vec<SynapseFederationStreamPosition>> {
		if !self.table_exists("federation_stream_position")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("federation_stream_position")?.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT type, stream_id, {instance_name}
			FROM federation_stream_position
			ORDER BY type, {instance_name}
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseFederationStreamPosition {
					stream_type: row.get(0),
					stream_id: int_value(&row, 1),
					instance_name: row.get(2),
				})
				.collect()
		})
	}

	pub fn federation_inbound_events(&self) -> Result<Vec<SynapseFederationInboundEvent>> {
		if !self.table_exists("federation_inbound_events_staging")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT origin, room_id, event_id, received_ts, event_json, internal_metadata
			FROM federation_inbound_events_staging
			ORDER BY received_ts, origin, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseFederationInboundEvent {
					origin: row.get(0),
					room_id: row.get(1),
					event_id: row.get(2),
					received_ts: int_value(&row, 3),
					event_json: json_from_text(&row, 4),
					internal_metadata: json_from_text(&row, 5),
				})
				.collect()
		})
	}

	pub fn device_list_remote_extremities(&self) -> Result<Vec<SynapseDeviceListRemoteExtremity>> {
		if !self.table_exists("device_lists_remote_extremeties")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, stream_id
			FROM device_lists_remote_extremeties
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListRemoteExtremity {
					user_id: row.get(0),
					stream_id: row.get(1),
				})
				.collect()
		})
	}

	pub fn device_list_remote_resync(&self) -> Result<Vec<SynapseDeviceListRemoteResync>> {
		if !self.table_exists("device_lists_remote_resync")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, added_ts
			FROM device_lists_remote_resync
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListRemoteResync {
					user_id: row.get(0),
					added_ts: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn user_signature_stream(&self) -> Result<Vec<SynapseUserSignatureStream>> {
		if !self.table_exists("user_signature_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("user_signature_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT stream_id, from_user_id, user_ids, {instance_name}
			FROM user_signature_stream
			ORDER BY stream_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserSignatureStream {
					stream_id: int_value(&row, 0),
					from_user_id: row.get(1),
					user_ids: json_from_text(&row, 2),
					instance_name: row.get(3),
				})
				.collect()
		})
	}

	pub fn device_list_stream_updates(&self) -> Result<Vec<SynapseDeviceListStreamUpdate>> {
		if !self.table_exists("device_lists_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_lists_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT stream_id, user_id, device_id, {instance_name}
			FROM device_lists_stream
			ORDER BY stream_id, user_id, device_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListStreamUpdate {
					stream_id: int_value(&row, 0),
					user_id: row.get(1),
					device_id: row.get(2),
					instance_name: row.get(3),
				})
				.collect()
		})
	}

	pub fn device_list_outbound_pokes(&self) -> Result<Vec<SynapseDeviceListOutboundPoke>> {
		if !self.table_exists("device_lists_outbound_pokes")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("device_lists_outbound_pokes")?;
		let opentracing_context = if columns.contains("opentracing_context") {
			"opentracing_context"
		} else {
			"NULL::text"
		};
		let instance_name = if columns.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT destination, stream_id, user_id, device_id, sent, ts,
			       {opentracing_context}, {instance_name}
			FROM device_lists_outbound_pokes
			ORDER BY stream_id, destination, user_id, device_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListOutboundPoke {
					destination: row.get(0),
					stream_id: int_value(&row, 1),
					user_id: row.get(2),
					device_id: row.get(3),
					sent: bool_value(&row, 4),
					ts: int_value(&row, 5),
					opentracing_context: row.get(6),
					instance_name: row.get(7),
				})
				.collect()
		})
	}

	pub fn device_list_outbound_last_success(
		&self,
	) -> Result<Vec<SynapseDeviceListOutboundLastSuccess>> {
		if !self.table_exists("device_lists_outbound_last_success")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT destination, user_id, stream_id
			FROM device_lists_outbound_last_success
			ORDER BY stream_id, destination, user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListOutboundLastSuccess {
					destination: row.get(0),
					user_id: row.get(1),
					stream_id: int_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn device_list_remote_pending(&self) -> Result<Vec<SynapseDeviceListRemotePending>> {
		if !self.table_exists("device_lists_remote_pending")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_lists_remote_pending")?.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT stream_id, user_id, device_id, {instance_name}
			FROM device_lists_remote_pending
			ORDER BY stream_id, user_id, device_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListRemotePending {
					stream_id: int_value(&row, 0),
					user_id: row.get(1),
					device_id: row.get(2),
					instance_name: row.get(3),
				})
				.collect()
		})
	}

	pub fn device_list_changes_in_room(&self) -> Result<Vec<SynapseDeviceListChangeInRoom>> {
		if !self.table_exists("device_lists_changes_in_room")? {
			return Ok(Vec::new());
		}

		let query = self.device_list_changes_in_room_query(None)?;
		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(device_list_change_in_room_from_row)
				.collect()
		})
	}

	pub fn for_each_device_list_changes_in_room_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseDeviceListChangeInRoom>) -> Result<()>,
	{
		if !self.table_exists("device_lists_changes_in_room")? {
			return Ok(());
		}

		let query = self.device_list_changes_in_room_query(Some(
			"WHERE (stream_id, room_id) > ($1, $2)",
		))?;
		let mut last_stream_id = i64::MIN;
		let mut last_room_id = String::new();
		loop {
			let rows = self.query(&query, &[&last_stream_id, &last_room_id, &DEFAULT_BATCH_SIZE])?;
			let Some((next_stream_id, next_room_id)) = rows
				.last()
				.map(|row| (int_value(row, 3), row.get::<_, String>(2)))
			else {
				break;
			};
			let changes = rows
				.into_iter()
				.map(device_list_change_in_room_from_row)
				.collect();
			f(changes)?;
			last_stream_id = next_stream_id;
			last_room_id = next_room_id;
		}

		Ok(())
	}

	fn device_list_changes_in_room_query(&self, where_clause: Option<&str>) -> Result<String> {
		let columns = self.columns("device_lists_changes_in_room")?;
		let converted_to_destinations = if columns.contains("converted_to_destinations") {
			"converted_to_destinations"
		} else {
			"FALSE"
		};
		let opentracing_context = if columns.contains("opentracing_context") {
			"opentracing_context"
		} else {
			"NULL::text"
		};
		let instance_name = if columns.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let inserted_ts = if columns.contains("inserted_ts") {
			"inserted_ts"
		} else {
			"NULL::bigint"
		};
		let where_clause = where_clause.unwrap_or_default();
		let limit = if where_clause.is_empty() {
			""
		} else {
			"LIMIT $3"
		};

		Ok(format!(
			"
			SELECT user_id, device_id, room_id, stream_id, {converted_to_destinations},
			       {opentracing_context}, {instance_name}, {inserted_ts}
			FROM device_lists_changes_in_room
			{where_clause}
			ORDER BY stream_id, room_id
			{limit}
			"
		))
	}

	pub fn device_list_changes_converted_positions(
		&self,
	) -> Result<Vec<SynapseDeviceListChangesConvertedPosition>> {
		if !self.table_exists("device_lists_changes_converted_stream_position")? {
			return Ok(Vec::new());
		}

		let instance_name = if self
			.columns("device_lists_changes_converted_stream_position")?
			.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT stream_id, room_id, {instance_name}
			FROM device_lists_changes_converted_stream_position
			ORDER BY stream_id, room_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListChangesConvertedPosition {
					stream_id: int_value(&row, 0),
					room_id: row.get(1),
					instance_name: row.get(2),
				})
				.collect()
		})
	}

	pub fn device_list_changes_max_pruned(
		&self,
	) -> Result<Vec<SynapseDeviceListChangesMaxPruned>> {
		if !self.table_exists("device_lists_changes_in_room_max_pruned_stream_id")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id
			FROM device_lists_changes_in_room_max_pruned_stream_id
			ORDER BY stream_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeviceListChangesMaxPruned {
					stream_id: int_value(&row, 0),
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

	pub fn ui_auth_sessions(&self) -> Result<Vec<SynapseUiAuthSession>> {
		if !self.table_exists("ui_auth_sessions")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT session_id, creation_time, serverdict, clientdict, uri, method, description
			FROM ui_auth_sessions
			ORDER BY session_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUiAuthSession {
					session_id: row.get(0),
					creation_time: int_value(&row, 1),
					serverdict: json_from_text(&row, 2),
					clientdict: json_from_text(&row, 3),
					uri: row.get(4),
					method: row.get(5),
					description: row.get(6),
				})
				.collect()
		})
	}

	pub fn ui_auth_session_credentials(&self) -> Result<Vec<SynapseUiAuthSessionCredential>> {
		if !self.table_exists("ui_auth_sessions_credentials")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT session_id, stage_type, result
			FROM ui_auth_sessions_credentials
			ORDER BY session_id, stage_type
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUiAuthSessionCredential {
					session_id: row.get(0),
					stage_type: row.get(1),
					result: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn ui_auth_session_ips(&self) -> Result<Vec<SynapseUiAuthSessionIp>> {
		if !self.table_exists("ui_auth_sessions_ips")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT session_id, ip, user_agent
			FROM ui_auth_sessions_ips
			ORDER BY session_id, ip, user_agent
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUiAuthSessionIp {
					session_id: row.get(0),
					ip: row.get(1),
					user_agent: row.get(2),
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

	pub fn push_rules_stream(&self) -> Result<Vec<SynapsePushRulesStream>> {
		if !self.table_exists("push_rules_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("push_rules_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT stream_id, event_stream_ordering, user_id, rule_id, op,
			       priority_class, priority, conditions, actions, {instance_name}
			FROM push_rules_stream
			ORDER BY stream_id, user_id, rule_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePushRulesStream {
					stream_id: int_value(&row, 0),
					event_stream_ordering: int_value(&row, 1),
					user_id: row.get(2),
					rule_id: row.get(3),
					op: row.get(4),
					priority_class: optional_int_value(&row, 5),
					priority: optional_int_value(&row, 6),
					conditions: optional_json_from_text(&row, 7),
					actions: optional_json_from_text(&row, 8),
					instance_name: row.get(9),
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

	pub fn room_tag_revisions(&self) -> Result<Vec<SynapseRoomTagRevision>> {
		if !self.table_exists("room_tags_revisions")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, room_id, stream_id, instance_name
			FROM room_tags_revisions
			ORDER BY user_id, room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomTagRevision {
					user_id: row.get(0),
					room_id: row.get(1),
					stream_id: int_value(&row, 2),
					instance_name: row.get(3),
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

	pub fn event_auth(&self) -> Result<Vec<SynapseEventAuth>> {
		if !self.table_exists("event_auth")? {
			return Ok(Vec::new());
		}

		let query = self.event_auth_query(None)?;
		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(event_auth_from_row)
				.collect()
		})
	}

	pub fn for_each_event_auth_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseEventAuth>) -> Result<()>,
	{
		if !self.table_exists("event_auth")? {
			return Ok(());
		}

		let query = self.event_auth_query(Some("WHERE (event_id, auth_id) > ($1, $2)"))?;
		let mut last_event_id = String::new();
		let mut last_auth_id = String::new();
		loop {
			let rows = self.query(&query, &[&last_event_id, &last_auth_id, &DEFAULT_BATCH_SIZE])?;
			let Some((next_event_id, next_auth_id)) = rows
				.last()
				.map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
			else {
				break;
			};
			let auth = rows.into_iter().map(event_auth_from_row).collect();
			f(auth)?;
			last_event_id = next_event_id;
			last_auth_id = next_auth_id;
		}

		Ok(())
	}

	fn event_auth_query(&self, where_clause: Option<&str>) -> Result<String> {
		let room_id = if self.columns("event_auth")?.contains("room_id") {
			"room_id"
		} else {
			"NULL::text"
		};
		let where_clause = where_clause.unwrap_or_default();
		let limit = if where_clause.is_empty() {
			""
		} else {
			"LIMIT $3"
		};
		Ok(format!(
			"
			SELECT event_id, auth_id, {room_id}
			FROM event_auth
			{where_clause}
			ORDER BY event_id, auth_id
			{limit}
			"
		))
	}

	pub fn event_auth_chains(&self) -> Result<Vec<SynapseEventAuthChain>> {
		if !self.table_exists("event_auth_chains")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, chain_id, sequence_number
			FROM event_auth_chains
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(event_auth_chain_from_row).collect())
	}

	pub fn for_each_event_auth_chains_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseEventAuthChain>) -> Result<()>,
	{
		if !self.table_exists("event_auth_chains")? {
			return Ok(());
		}

		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT event_id, chain_id, sequence_number
				FROM event_auth_chains
				WHERE event_id > $1
				ORDER BY event_id
				LIMIT $2
				",
				&[&last_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_event_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let chains = rows.into_iter().map(event_auth_chain_from_row).collect();
			f(chains)?;
			last_event_id = next_event_id;
		}

		Ok(())
	}

	pub fn event_auth_chain_links(&self) -> Result<Vec<SynapseEventAuthChainLink>> {
		if !self.table_exists("event_auth_chain_links")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT origin_chain_id, origin_sequence_number, target_chain_id,
			       target_sequence_number
			FROM event_auth_chain_links
			ORDER BY origin_chain_id, origin_sequence_number, target_chain_id,
			         target_sequence_number
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(event_auth_chain_link_from_row).collect())
	}

	pub fn for_each_event_auth_chain_links_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseEventAuthChainLink>) -> Result<()>,
	{
		if !self.table_exists("event_auth_chain_links")? {
			return Ok(());
		}

		let mut last_origin_chain_id = i64::MIN;
		let mut last_origin_sequence_number = i64::MIN;
		let mut last_target_chain_id = i64::MIN;
		let mut last_target_sequence_number = i64::MIN;
		loop {
			let rows = self.query(
				"
				SELECT origin_chain_id, origin_sequence_number, target_chain_id,
				       target_sequence_number
				FROM event_auth_chain_links
				WHERE (
					origin_chain_id, origin_sequence_number, target_chain_id,
					target_sequence_number
				) > ($1, $2, $3, $4)
				ORDER BY origin_chain_id, origin_sequence_number, target_chain_id,
				         target_sequence_number
				LIMIT $5
				",
				&[
					&last_origin_chain_id,
					&last_origin_sequence_number,
					&last_target_chain_id,
					&last_target_sequence_number,
					&DEFAULT_BATCH_SIZE,
				],
			)?;
			let Some(next) = rows.last().map(|row| {
				(
					int_value(row, 0),
					int_value(row, 1),
					int_value(row, 2),
					int_value(row, 3),
				)
			}) else {
				break;
			};
			let links = rows.into_iter().map(event_auth_chain_link_from_row).collect();
			f(links)?;
			last_origin_chain_id = next.0;
			last_origin_sequence_number = next.1;
			last_target_chain_id = next.2;
			last_target_sequence_number = next.3;
		}

		Ok(())
	}

	pub fn event_auth_chain_to_calculate(
		&self,
	) -> Result<Vec<SynapseEventAuthChainToCalculate>> {
		if !self.table_exists("event_auth_chain_to_calculate")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, room_id, type, state_key
			FROM event_auth_chain_to_calculate
			ORDER BY room_id, type, state_key, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventAuthChainToCalculate {
					event_id: row.get(0),
					room_id: row.get(1),
					event_type: row.get(2),
					state_key: row.get(3),
				})
				.collect()
		})
	}

	pub fn rejected_events(&self) -> Result<Vec<SynapseRejectedEvent>> {
		if !self.table_exists("rejections")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, reason, last_check
			FROM rejections
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRejectedEvent {
					event_id: row.get(0),
					reason: row.get(1),
					last_check: row.get(2),
				})
				.collect()
		})
	}

	pub fn backward_extremities(&self) -> Result<Vec<SynapseBackwardExtremity>> {
		if !self.table_exists("event_backward_extremities")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, room_id
			FROM event_backward_extremities
			ORDER BY room_id, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseBackwardExtremity {
					event_id: row.get(0),
					room_id: row.get(1),
				})
				.collect()
		})
	}

	pub fn timeline_gaps(&self) -> Result<Vec<SynapseTimelineGap>> {
		if !self.table_exists("timeline_gaps")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, instance_name, stream_ordering
			FROM timeline_gaps
			ORDER BY room_id, stream_ordering, instance_name
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseTimelineGap {
					room_id: row.get(0),
					instance_name: row.get(1),
					stream_ordering: int_value(&row, 2),
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

	pub fn threads(&self) -> Result<Vec<SynapseThread>> {
		if !self.table_exists("threads")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, thread_id, latest_event_id, topological_ordering,
			       stream_ordering
			FROM threads
			ORDER BY room_id, thread_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseThread {
					room_id: row.get(0),
					thread_id: row.get(1),
					latest_event_id: row.get(2),
					topological_ordering: int_value(&row, 3),
					stream_ordering: int_value(&row, 4),
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

	pub fn event_reports(&self) -> Result<Vec<SynapseEventReport>> {
		if !self.table_exists("event_reports")? {
			return Ok(Vec::new());
		}

		let content = if self.columns("event_reports")?.contains("content") {
			"content"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT id, received_ts, room_id, event_id, user_id, reason, {content}
			FROM event_reports
			ORDER BY id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| {
					let content: Option<String> = row.get(6);
					SynapseEventReport {
						id: int_value(&row, 0),
						received_ts: int_value(&row, 1),
						room_id: row.get(2),
						event_id: row.get(3),
						user_id: row.get(4),
						reason: row.get(5),
						content: content
							.as_deref()
							.and_then(|content| serde_json::from_str(content).ok())
							.unwrap_or(Value::Null),
					}
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

	pub fn state_events(&self) -> Result<Vec<SynapseStateEvent>> {
		if !self.table_exists("state_events")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, room_id, type, state_key, prev_state
			FROM state_events
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(state_event_from_row).collect())
	}

	pub fn for_each_state_events_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseStateEvent>) -> Result<()>,
	{
		if !self.table_exists("state_events")? {
			return Ok(());
		}

		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT event_id, room_id, type, state_key, prev_state
				FROM state_events
				WHERE event_id > $1
				ORDER BY event_id
				LIMIT $2
				",
				&[&last_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_event_id) = rows.last().map(|row| row.get::<_, String>(0)) else {
				break;
			};
			let rows = rows.into_iter().map(state_event_from_row).collect();
			f(rows)?;
			last_event_id = next_event_id;
		}

		Ok(())
	}

	pub fn current_state_delta_stream(&self) -> Result<Vec<SynapseCurrentStateDelta>> {
		if !self.table_exists("current_state_delta_stream")? {
			return Ok(Vec::new());
		}

		let query = self.current_state_delta_stream_query(None)?;
		self.query(&query, &[])
			.map(|rows| rows.into_iter().map(current_state_delta_from_row).collect())
	}

	pub fn for_each_current_state_delta_stream_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseCurrentStateDelta>) -> Result<()>,
	{
		if !self.table_exists("current_state_delta_stream")? {
			return Ok(());
		}

		let query = self.current_state_delta_stream_query(Some(
			"WHERE (stream_id, room_id, type, state_key) > ($1, $2, $3, $4)",
		))?;
		let mut last_stream_id = i64::MIN;
		let mut last_room_id = String::new();
		let mut last_event_type = String::new();
		let mut last_state_key = String::new();
		loop {
			let rows = self.query(
				&query,
				&[
					&last_stream_id,
					&last_room_id,
					&last_event_type,
					&last_state_key,
					&DEFAULT_BATCH_SIZE,
				],
			)?;
			let Some(next) = rows.last().map(|row| {
				(
					int_value(row, 0),
					row.get::<_, String>(1),
					row.get::<_, String>(2),
					row.get::<_, String>(3),
				)
			}) else {
				break;
			};
			let deltas = rows.into_iter().map(current_state_delta_from_row).collect();
			f(deltas)?;
			last_stream_id = next.0;
			last_room_id = next.1;
			last_event_type = next.2;
			last_state_key = next.3;
		}

		Ok(())
	}

	fn current_state_delta_stream_query(&self, where_clause: Option<&str>) -> Result<String> {
		let instance_name = if self
			.columns("current_state_delta_stream")?
			.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL::text"
		};
		let where_clause = where_clause.unwrap_or_default();
		let limit = if where_clause.is_empty() {
			""
		} else {
			"LIMIT $5"
		};
		Ok(format!(
			"
			SELECT stream_id, room_id, type, state_key, event_id, prev_event_id,
			       {instance_name}
			FROM current_state_delta_stream
			{where_clause}
			ORDER BY stream_id, room_id, type, state_key
			{limit}
			"
		))
	}

	pub fn stream_ordering_to_extremity(&self) -> Result<Vec<SynapseStreamOrderingExtremity>> {
		if !self.table_exists("stream_ordering_to_exterm")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_ordering, room_id, event_id
			FROM stream_ordering_to_exterm
			ORDER BY stream_ordering, room_id, event_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(stream_ordering_extremity_from_row).collect())
	}

	pub fn for_each_stream_ordering_to_extremity_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseStreamOrderingExtremity>) -> Result<()>,
	{
		if !self.table_exists("stream_ordering_to_exterm")? {
			return Ok(());
		}

		let mut last_stream_ordering = i64::MIN;
		let mut last_room_id = String::new();
		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT stream_ordering, room_id, event_id
				FROM stream_ordering_to_exterm
				WHERE (stream_ordering, room_id, event_id) > ($1, $2, $3)
				ORDER BY stream_ordering, room_id, event_id
				LIMIT $4
				",
				&[
					&last_stream_ordering,
					&last_room_id,
					&last_event_id,
					&DEFAULT_BATCH_SIZE,
				],
			)?;
			let Some(next) = rows.last().map(|row| {
				(
					int_value(row, 0),
					row.get::<_, String>(1),
					row.get::<_, String>(2),
				)
			}) else {
				break;
			};
			let rows = rows
				.into_iter()
				.map(stream_ordering_extremity_from_row)
				.collect();
			f(rows)?;
			last_stream_ordering = next.0;
			last_room_id = next.1;
			last_event_id = next.2;
		}

		Ok(())
	}

	pub fn ex_outlier_stream(&self) -> Result<Vec<SynapseExOutlierStream>> {
		if !self.table_exists("ex_outlier_stream")? {
			return Ok(Vec::new());
		}

		let query = self.ex_outlier_stream_query(None)?;
		self.query(&query, &[])
			.map(|rows| rows.into_iter().map(ex_outlier_stream_from_row).collect())
	}

	pub fn for_each_ex_outlier_stream_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseExOutlierStream>) -> Result<()>,
	{
		if !self.table_exists("ex_outlier_stream")? {
			return Ok(());
		}

		let query = self.ex_outlier_stream_query(Some("WHERE event_stream_ordering > $1"))?;
		let mut last_event_stream_ordering = i64::MIN;
		loop {
			let rows = self.query(&query, &[&last_event_stream_ordering, &DEFAULT_BATCH_SIZE])?;
			let Some(next_event_stream_ordering) = rows.last().map(|row| int_value(row, 0)) else {
				break;
			};
			let rows = rows.into_iter().map(ex_outlier_stream_from_row).collect();
			f(rows)?;
			last_event_stream_ordering = next_event_stream_ordering;
		}

		Ok(())
	}

	fn ex_outlier_stream_query(&self, where_clause: Option<&str>) -> Result<String> {
		let instance_name = if self.columns("ex_outlier_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL::text"
		};
		let where_clause = where_clause.unwrap_or_default();
		let limit = if where_clause.is_empty() {
			""
		} else {
			"LIMIT $2"
		};
		Ok(format!(
			"
			SELECT event_stream_ordering, event_id, state_group, {instance_name}
			FROM ex_outlier_stream
			{where_clause}
			ORDER BY event_stream_ordering
			{limit}
			"
		))
	}

	pub fn state_groups(&self) -> Result<Vec<SynapseStateGroup>> {
		if !self.table_exists("state_groups")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT id, room_id, event_id
			FROM state_groups
			ORDER BY id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(state_group_from_row).collect())
	}

	pub fn for_each_state_groups_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseStateGroup>) -> Result<()>,
	{
		if !self.table_exists("state_groups")? {
			return Ok(());
		}

		let mut last_id = i64::MIN;
		loop {
			let rows = self.query(
				"
				SELECT id, room_id, event_id
				FROM state_groups
				WHERE id > $1
				ORDER BY id
				LIMIT $2
				",
				&[&last_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_id) = rows.last().map(|row| int_value(row, 0)) else {
				break;
			};
			let rows = rows.into_iter().map(state_group_from_row).collect();
			f(rows)?;
			last_id = next_id;
		}

		Ok(())
	}

	pub fn state_group_edges(&self) -> Result<Vec<SynapseStateGroupEdge>> {
		if !self.table_exists("state_group_edges")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT state_group, prev_state_group
			FROM state_group_edges
			ORDER BY state_group, prev_state_group
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(state_group_edge_from_row).collect())
	}

	pub fn for_each_state_group_edges_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseStateGroupEdge>) -> Result<()>,
	{
		if !self.table_exists("state_group_edges")? {
			return Ok(());
		}

		let mut last_state_group = i64::MIN;
		let mut last_prev_state_group = i64::MIN;
		loop {
			let rows = self.query(
				"
				SELECT state_group, prev_state_group
				FROM state_group_edges
				WHERE (state_group, prev_state_group) > ($1, $2)
				ORDER BY state_group, prev_state_group
				LIMIT $3
				",
				&[&last_state_group, &last_prev_state_group, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next) = rows
				.last()
				.map(|row| (int_value(row, 0), int_value(row, 1)))
			else {
				break;
			};
			let rows = rows.into_iter().map(state_group_edge_from_row).collect();
			f(rows)?;
			last_state_group = next.0;
			last_prev_state_group = next.1;
		}

		Ok(())
	}

	pub fn event_to_state_groups(&self) -> Result<Vec<SynapseEventToStateGroup>> {
		if !self.table_exists("event_to_state_groups")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT event_id, state_group
			FROM event_to_state_groups
			ORDER BY event_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(event_to_state_group_from_row).collect())
	}

	pub fn for_each_event_to_state_groups_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseEventToStateGroup>) -> Result<()>,
	{
		if !self.table_exists("event_to_state_groups")? {
			return Ok(());
		}

		let mut last_event_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT event_id, state_group
				FROM event_to_state_groups
				WHERE event_id > $1
				ORDER BY event_id
				LIMIT $2
				",
				&[&last_event_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_event_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let rows = rows.into_iter().map(event_to_state_group_from_row).collect();
			f(rows)?;
			last_event_id = next_event_id;
		}

		Ok(())
	}

	pub fn state_groups_state(&self) -> Result<Vec<SynapseStateGroupState>> {
		if !self.table_exists("state_groups_state")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT state_group, room_id, type, state_key, event_id
			FROM state_groups_state
			ORDER BY state_group, type, state_key
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(state_group_state_from_row).collect())
	}

	pub fn for_each_state_groups_state_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseStateGroupState>) -> Result<()>,
	{
		if !self.table_exists("state_groups_state")? {
			return Ok(());
		}

		let mut last_state_group = i64::MIN;
		let mut last_event_type = String::new();
		let mut last_state_key = String::new();
		loop {
			let rows = self.query(
				"
				SELECT state_group, room_id, type, state_key, event_id
				FROM state_groups_state
				WHERE (state_group, type, state_key) > ($1, $2, $3)
				ORDER BY state_group, type, state_key
				LIMIT $4
				",
				&[
					&last_state_group,
					&last_event_type,
					&last_state_key,
					&DEFAULT_BATCH_SIZE,
				],
			)?;
			let Some(next) = rows.last().map(|row| {
				(
					int_value(row, 0),
					row.get::<_, String>(2),
					row.get::<_, String>(3),
				)
			}) else {
				break;
			};
			let rows = rows.into_iter().map(state_group_state_from_row).collect();
			f(rows)?;
			last_state_group = next.0;
			last_event_type = next.1;
			last_state_key = next.2;
		}

		Ok(())
	}

	pub fn local_current_membership(&self) -> Result<Vec<SynapseLocalCurrentMembership>> {
		if !self.table_exists("local_current_membership")? {
			return Ok(Vec::new());
		}

		let event_stream_ordering = if self
			.columns("local_current_membership")?
			.contains("event_stream_ordering")
		{
			"event_stream_ordering"
		} else {
			"NULL::bigint"
		};
		let query = format!(
			"
			SELECT room_id, user_id, event_id, membership, {event_stream_ordering}
			FROM local_current_membership
			ORDER BY room_id, user_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseLocalCurrentMembership {
					room_id: row.get(0),
					user_id: row.get(1),
					event_id: row.get(2),
					membership: row.get(3),
					event_stream_ordering: optional_int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn partial_state_rooms(&self) -> Result<Vec<SynapsePartialStateRoom>> {
		if !self.table_exists("partial_state_rooms")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("partial_state_rooms")?;
		let device_lists_stream_id = if columns.contains("device_lists_stream_id") {
			"device_lists_stream_id"
		} else {
			"NULL::bigint"
		};
		let join_event_id = if columns.contains("join_event_id") {
			"join_event_id"
		} else {
			"NULL::text"
		};
		let joined_via = if columns.contains("joined_via") {
			"joined_via"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT room_id, {device_lists_stream_id}, {join_event_id}, {joined_via}
			FROM partial_state_rooms
			ORDER BY room_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePartialStateRoom {
					room_id: row.get(0),
					device_lists_stream_id: optional_int_value(&row, 1),
					join_event_id: row.get(2),
					joined_via: row.get(3),
				})
				.collect()
		})
	}

	pub fn partial_state_room_servers(&self) -> Result<Vec<SynapsePartialStateRoomServer>> {
		if !self.table_exists("partial_state_rooms_servers")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, server_name
			FROM partial_state_rooms_servers
			ORDER BY room_id, server_name
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePartialStateRoomServer {
					room_id: row.get(0),
					server_name: row.get(1),
				})
				.collect()
		})
	}

	pub fn partial_state_events(&self) -> Result<Vec<SynapsePartialStateEvent>> {
		if !self.table_exists("partial_state_events")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, event_id
			FROM partial_state_events
			ORDER BY room_id, event_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapsePartialStateEvent {
					room_id: row.get(0),
					event_id: row.get(1),
				})
				.collect()
		})
	}

	pub fn un_partial_stated_rooms(&self) -> Result<Vec<SynapseUnPartialStatedRoom>> {
		if !self.table_exists("un_partial_stated_room_stream")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id, instance_name, room_id
			FROM un_partial_stated_room_stream
			ORDER BY stream_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUnPartialStatedRoom {
					stream_id: int_value(&row, 0),
					instance_name: row.get(1),
					room_id: row.get(2),
				})
				.collect()
		})
	}

	pub fn un_partial_stated_events(&self) -> Result<Vec<SynapseUnPartialStatedEvent>> {
		if !self.table_exists("un_partial_stated_event_stream")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id, instance_name, event_id, rejection_status_changed
			FROM un_partial_stated_event_stream
			ORDER BY stream_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUnPartialStatedEvent {
					stream_id: int_value(&row, 0),
					instance_name: row.get(1),
					event_id: row.get(2),
					rejection_status_changed: bool_value(&row, 3),
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

	pub fn room_metadata(&self) -> Result<Vec<SynapseRoomMetadata>> {
		if !self.table_exists("rooms")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("rooms")?;
		let is_public = if columns.contains("is_public") {
			"is_public"
		} else {
			"NULL::boolean"
		};
		let creator = if columns.contains("creator") {
			"creator"
		} else {
			"NULL::text"
		};
		let room_version = if columns.contains("room_version") {
			"room_version"
		} else {
			"NULL::text"
		};
		let has_auth_chain_index = if columns.contains("has_auth_chain_index") {
			"has_auth_chain_index"
		} else {
			"NULL::boolean"
		};
		let query = format!(
			"
			SELECT room_id, {is_public}, {creator}, {room_version}, {has_auth_chain_index}
			FROM rooms
			ORDER BY room_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomMetadata {
					room_id: row.get(0),
					is_public: optional_bool_value(&row, 1),
					creator: row.get(2),
					room_version: row.get(3),
					has_auth_chain_index: optional_bool_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn room_depths(&self) -> Result<Vec<SynapseRoomDepth>> {
		if !self.table_exists("room_depth")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, min_depth
			FROM room_depth
			ORDER BY room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomDepth {
					room_id: row.get(0),
					min_depth: optional_int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn users_in_public_rooms(&self) -> Result<Vec<SynapseUsersInPublicRoom>> {
		if !self.table_exists("users_in_public_rooms")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, room_id
			FROM users_in_public_rooms
			ORDER BY user_id, room_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(users_in_public_room_from_row).collect())
	}

	pub fn for_each_users_in_public_rooms_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseUsersInPublicRoom>) -> Result<()>,
	{
		if !self.table_exists("users_in_public_rooms")? {
			return Ok(());
		}

		let mut last_user_id = String::new();
		let mut last_room_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT user_id, room_id
				FROM users_in_public_rooms
				WHERE (user_id, room_id) > ($1, $2)
				ORDER BY user_id, room_id
				LIMIT $3
				",
				&[&last_user_id, &last_room_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next) = rows
				.last()
				.map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
			else {
				break;
			};
			let rows = rows.into_iter().map(users_in_public_room_from_row).collect();
			f(rows)?;
			last_user_id = next.0;
			last_room_id = next.1;
		}

		Ok(())
	}

	pub fn users_who_share_private_rooms(
		&self,
	) -> Result<Vec<SynapseUsersWhoSharePrivateRoom>> {
		if !self.table_exists("users_who_share_private_rooms")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, other_user_id, room_id
			FROM users_who_share_private_rooms
			ORDER BY user_id, other_user_id, room_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(users_who_share_private_room_from_row).collect())
	}

	pub fn for_each_users_who_share_private_rooms_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseUsersWhoSharePrivateRoom>) -> Result<()>,
	{
		if !self.table_exists("users_who_share_private_rooms")? {
			return Ok(());
		}

		let mut last_user_id = String::new();
		let mut last_other_user_id = String::new();
		let mut last_room_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT user_id, other_user_id, room_id
				FROM users_who_share_private_rooms
				WHERE (user_id, other_user_id, room_id) > ($1, $2, $3)
				ORDER BY user_id, other_user_id, room_id
				LIMIT $4
				",
				&[
					&last_user_id,
					&last_other_user_id,
					&last_room_id,
					&DEFAULT_BATCH_SIZE,
				],
			)?;
			let Some(next) = rows.last().map(|row| {
				(
					row.get::<_, String>(0),
					row.get::<_, String>(1),
					row.get::<_, String>(2),
				)
			}) else {
				break;
			};
			let rows = rows
				.into_iter()
				.map(users_who_share_private_room_from_row)
				.collect();
			f(rows)?;
			last_user_id = next.0;
			last_other_user_id = next.1;
			last_room_id = next.2;
		}

		Ok(())
	}

	pub fn user_directory(&self) -> Result<Vec<SynapseUserDirectoryEntry>> {
		if !self.table_exists("user_directory")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, room_id, display_name, avatar_url
			FROM user_directory
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(user_directory_entry_from_row).collect())
	}

	pub fn for_each_user_directory_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseUserDirectoryEntry>) -> Result<()>,
	{
		if !self.table_exists("user_directory")? {
			return Ok(());
		}

		let mut last_user_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT user_id, room_id, display_name, avatar_url
				FROM user_directory
				WHERE user_id > $1
				ORDER BY user_id
				LIMIT $2
				",
				&[&last_user_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_user_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let rows = rows.into_iter().map(user_directory_entry_from_row).collect();
			f(rows)?;
			last_user_id = next_user_id;
		}

		Ok(())
	}

	pub fn user_directory_search(&self) -> Result<Vec<SynapseUserDirectorySearch>> {
		if !self.table_exists("user_directory_search")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, vector::text
			FROM user_directory_search
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| rows.into_iter().map(user_directory_search_from_row).collect())
	}

	pub fn for_each_user_directory_search_batch<F>(&self, mut f: F) -> Result<()>
	where
		F: FnMut(Vec<SynapseUserDirectorySearch>) -> Result<()>,
	{
		if !self.table_exists("user_directory_search")? {
			return Ok(());
		}

		let mut last_user_id = String::new();
		loop {
			let rows = self.query(
				"
				SELECT user_id, vector::text
				FROM user_directory_search
				WHERE user_id > $1
				ORDER BY user_id
				LIMIT $2
				",
				&[&last_user_id, &DEFAULT_BATCH_SIZE],
			)?;
			let Some(next_user_id) = rows.last().map(|row| row.get(0)) else {
				break;
			};
			let rows = rows.into_iter().map(user_directory_search_from_row).collect();
			f(rows)?;
			last_user_id = next_user_id;
		}

		Ok(())
	}

	pub fn user_directory_stale_remote_users(
		&self,
	) -> Result<Vec<SynapseUserDirectoryStaleRemoteUser>> {
		if !self.table_exists("user_directory_stale_remote_users")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT user_id, user_server_name, next_try_at_ts, retry_counter
			FROM user_directory_stale_remote_users
			ORDER BY user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserDirectoryStaleRemoteUser {
					user_id: row.get(0),
					user_server_name: row.get(1),
					next_try_at_ts: int_value(&row, 2),
					retry_counter: int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn user_directory_stream_positions(
		&self,
	) -> Result<Vec<SynapseUserDirectoryStreamPosition>> {
		if !self.table_exists("user_directory_stream_pos")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, stream_id
			FROM user_directory_stream_pos
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseUserDirectoryStreamPosition {
					lock: row.get(0),
					stream_id: optional_int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn room_stats_current(&self) -> Result<Vec<SynapseRoomStatsCurrent>> {
		if !self.table_exists("room_stats_current")? {
			return Ok(Vec::new());
		}

		let knocked_members = if self.columns("room_stats_current")?.contains("knocked_members") {
			"knocked_members"
		} else {
			"NULL::bigint"
		};
		let query = format!(
			"
			SELECT room_id, current_state_events, joined_members, invited_members,
			       left_members, banned_members, local_users_in_room,
			       completed_delta_stream_id, {knocked_members}
			FROM room_stats_current
			ORDER BY room_id
			"
		);
		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomStatsCurrent {
					room_id: row.get(0),
					current_state_events: int_value(&row, 1),
					joined_members: int_value(&row, 2),
					invited_members: int_value(&row, 3),
					left_members: int_value(&row, 4),
					banned_members: int_value(&row, 5),
					local_users_in_room: int_value(&row, 6),
					completed_delta_stream_id: int_value(&row, 7),
					knocked_members: optional_int_value(&row, 8),
				})
				.collect()
		})
	}

	pub fn room_stats_state(&self) -> Result<Vec<SynapseRoomStatsState>> {
		if !self.table_exists("room_stats_state")? {
			return Ok(Vec::new());
		}

		let room_type = if self.columns("room_stats_state")?.contains("room_type") {
			"room_type"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT room_id, name, canonical_alias, join_rules, history_visibility,
			       encryption, avatar, guest_access, is_federatable, topic,
			       {room_type}
			FROM room_stats_state
			ORDER BY room_id
			"
		);
		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomStatsState {
					room_id: row.get(0),
					name: row.get(1),
					canonical_alias: row.get(2),
					join_rules: row.get(3),
					history_visibility: row.get(4),
					encryption: row.get(5),
					avatar: row.get(6),
					guest_access: row.get(7),
					is_federatable: optional_bool_value(&row, 8),
					topic: row.get(9),
					room_type: row.get(10),
				})
				.collect()
		})
	}

	pub fn room_stats_earliest_tokens(&self) -> Result<Vec<SynapseRoomStatsEarliestToken>> {
		if !self.table_exists("room_stats_earliest_token")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, token
			FROM room_stats_earliest_token
			ORDER BY room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomStatsEarliestToken {
					room_id: row.get(0),
					token: int_value(&row, 1),
				})
				.collect()
		})
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

	pub fn receipts_graph(&self) -> Result<Vec<SynapseReceiptGraph>> {
		if !self.table_exists("receipts_graph")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, receipt_type, user_id, event_ids, data, thread_id
			FROM receipts_graph
			ORDER BY room_id, receipt_type, user_id, thread_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| {
					let event_ids = row
						.try_get::<_, String>(3)
						.ok()
						.and_then(|json| serde_json::from_str(&json).ok())
						.unwrap_or_default();
					SynapseReceiptGraph {
						room_id: row.get(0),
						receipt_type: row.get(1),
						user_id: row.get(2),
						event_ids,
						data: json_from_text(&row, 4),
						thread_id: row.get(5),
					}
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

	pub fn event_push_summaries(&self) -> Result<Vec<SynapseEventPushSummary>> {
		if !self.table_exists("event_push_summary")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("event_push_summary")?;
		let unread_count = if columns.contains("unread_count") {
			"unread_count"
		} else {
			"NULL::bigint"
		};
		let last_receipt_stream_ordering = if columns.contains("last_receipt_stream_ordering") {
			"last_receipt_stream_ordering"
		} else {
			"NULL::bigint"
		};
		let thread_id = if columns.contains("thread_id") {
			"thread_id"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT user_id, room_id, notif_count, stream_ordering, {unread_count},
			       {last_receipt_stream_ordering}, {thread_id}
			FROM event_push_summary
			ORDER BY user_id, room_id, stream_ordering
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventPushSummary {
					user_id: row.get(0),
					room_id: row.get(1),
					notif_count: int_value(&row, 2),
					stream_ordering: int_value(&row, 3),
					unread_count: optional_int_value(&row, 4),
					last_receipt_stream_ordering: optional_int_value(&row, 5),
					thread_id: row.get(6),
				})
				.collect()
		})
	}

	pub fn event_push_actions(&self) -> Result<Vec<SynapseEventPushAction>> {
		if !self.table_exists("event_push_actions")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("event_push_actions")?;
		let thread_id = if columns.contains("thread_id") {
			"thread_id"
		} else {
			"NULL::text"
		};
		let query = format!(
			"
			SELECT room_id, event_id, user_id, profile_tag, actions, topological_ordering,
			       stream_ordering, notif, highlight, unread, {thread_id}
			FROM event_push_actions
			ORDER BY stream_ordering, room_id, event_id, user_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventPushAction {
					room_id: row.get(0),
					event_id: row.get(1),
					user_id: row.get(2),
					profile_tag: row.get(3),
					actions: json_from_text(&row, 4),
					topological_ordering: optional_int_value(&row, 5),
					stream_ordering: optional_int_value(&row, 6),
					notif: optional_bool_value(&row, 7),
					highlight: optional_bool_value(&row, 8),
					unread: optional_bool_value(&row, 9),
					thread_id: row.get(10),
				})
				.collect()
		})
	}

	pub fn event_push_actions_staging(&self) -> Result<Vec<SynapseEventPushActionStaging>> {
		if !self.table_exists("event_push_actions_staging")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("event_push_actions_staging")?;
		let thread_id = if columns.contains("thread_id") {
			"thread_id"
		} else {
			"NULL::text"
		};
		let inserted_ts = if columns.contains("inserted_ts") {
			"inserted_ts"
		} else {
			"NULL::bigint"
		};
		let query = format!(
			"
			SELECT event_id, user_id, actions, notif, highlight, unread, {thread_id}, {inserted_ts}
			FROM event_push_actions_staging
			ORDER BY event_id, user_id
			"
		);

		self.query(&query, &[]).map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventPushActionStaging {
					event_id: row.get(0),
					user_id: row.get(1),
					actions: json_from_text(&row, 2),
					notif: bool_value(&row, 3),
					highlight: bool_value(&row, 4),
					unread: optional_bool_value(&row, 5),
					thread_id: row.get(6),
					inserted_ts: optional_int_value(&row, 7),
				})
				.collect()
		})
	}

	pub fn event_push_summary_stream_positions(
		&self,
	) -> Result<Vec<SynapseEventPushSummaryStreamPosition>> {
		if !self.table_exists("event_push_summary_stream_ordering")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT Lock, stream_ordering
			FROM event_push_summary_stream_ordering
			ORDER BY Lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventPushSummaryStreamPosition {
					lock: row.get(0),
					stream_ordering: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connections(&self) -> Result<Vec<SynapseSlidingSyncConnection>> {
		if !self.table_exists("sliding_sync_connections")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT connection_key, user_id, effective_device_id, conn_id, created_ts, last_used_ts
			FROM sliding_sync_connections
			ORDER BY connection_key
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnection {
					connection_key: int_value(&row, 0),
					user_id: row.get(1),
					effective_device_id: row.get(2),
					conn_id: row.get(3),
					created_ts: int_value(&row, 4),
					last_used_ts: optional_int_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connection_positions(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionPosition>> {
		if !self.table_exists("sliding_sync_connection_positions")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT connection_position, connection_key, created_ts
			FROM sliding_sync_connection_positions
			ORDER BY connection_position
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnectionPosition {
					connection_position: int_value(&row, 0),
					connection_key: int_value(&row, 1),
					created_ts: int_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connection_streams(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionStream>> {
		if !self.table_exists("sliding_sync_connection_streams")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT connection_position, stream, room_id, room_status, last_token
			FROM sliding_sync_connection_streams
			ORDER BY connection_position, stream, room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnectionStream {
					connection_position: int_value(&row, 0),
					stream: row.get(1),
					room_id: row.get(2),
					room_status: row.get(3),
					last_token: row.get(4),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connection_room_configs(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionRoomConfig>> {
		if !self.table_exists("sliding_sync_connection_room_configs")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT connection_position, room_id, timeline_limit, required_state_id
			FROM sliding_sync_connection_room_configs
			ORDER BY connection_position, room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnectionRoomConfig {
					connection_position: int_value(&row, 0),
					room_id: row.get(1),
					timeline_limit: int_value(&row, 2),
					required_state_id: int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connection_required_state(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionRequiredState>> {
		if !self.table_exists("sliding_sync_connection_required_state")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT required_state_id, connection_key, required_state
			FROM sliding_sync_connection_required_state
			ORDER BY required_state_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnectionRequiredState {
					required_state_id: int_value(&row, 0),
					connection_key: int_value(&row, 1),
					required_state: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn sliding_sync_connection_lazy_members(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionLazyMember>> {
		if !self.table_exists("sliding_sync_connection_lazy_members")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT connection_key, connection_position, room_id, user_id, last_seen_ts
			FROM sliding_sync_connection_lazy_members
			ORDER BY connection_key, room_id, user_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncConnectionLazyMember {
					connection_key: int_value(&row, 0),
					connection_position: optional_int_value(&row, 1),
					room_id: row.get(2),
					user_id: row.get(3),
					last_seen_ts: int_value(&row, 4),
				})
				.collect()
		})
	}

	pub fn sliding_sync_membership_snapshots(
		&self,
	) -> Result<Vec<SynapseSlidingSyncMembershipSnapshot>> {
		if !self.table_exists("sliding_sync_membership_snapshots")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, user_id, sender, membership_event_id, membership, forgotten,
			       event_stream_ordering, event_instance_name, has_known_state, room_type,
			       room_name, is_encrypted, tombstone_successor_room_id
			FROM sliding_sync_membership_snapshots
			ORDER BY room_id, user_id, event_stream_ordering
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncMembershipSnapshot {
					room_id: row.get(0),
					user_id: row.get(1),
					sender: row.get(2),
					membership_event_id: row.get(3),
					membership: row.get(4),
					forgotten: bool_value(&row, 5),
					event_stream_ordering: int_value(&row, 6),
					event_instance_name: row.get(7),
					has_known_state: bool_value(&row, 8),
					room_type: row.get(9),
					room_name: row.get(10),
					is_encrypted: bool_value(&row, 11),
					tombstone_successor_room_id: row.get(12),
				})
				.collect()
		})
	}

	pub fn sliding_sync_joined_rooms(&self) -> Result<Vec<SynapseSlidingSyncJoinedRoom>> {
		if !self.table_exists("sliding_sync_joined_rooms")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id, event_stream_ordering, bump_stamp, room_type, room_name,
			       is_encrypted, tombstone_successor_room_id
			FROM sliding_sync_joined_rooms
			ORDER BY room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncJoinedRoom {
					room_id: row.get(0),
					event_stream_ordering: int_value(&row, 1),
					bump_stamp: optional_int_value(&row, 2),
					room_type: row.get(3),
					room_name: row.get(4),
					is_encrypted: bool_value(&row, 5),
					tombstone_successor_room_id: row.get(6),
				})
				.collect()
		})
	}

	pub fn sliding_sync_joined_rooms_to_recalculate(
		&self,
	) -> Result<Vec<SynapseSlidingSyncJoinedRoomToRecalculate>> {
		if !self.table_exists("sliding_sync_joined_rooms_to_recalculate")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT room_id
			FROM sliding_sync_joined_rooms_to_recalculate
			ORDER BY room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSlidingSyncJoinedRoomToRecalculate {
					room_id: row.get(0),
				})
				.collect()
		})
	}

	pub fn stream_positions(&self) -> Result<Vec<SynapseStreamPosition>> {
		if !self.table_exists("stream_positions")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_name, instance_name, stream_id
			FROM stream_positions
			ORDER BY stream_name, instance_name
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseStreamPosition {
					stream_name: row.get(0),
					instance_name: row.get(1),
					stream_id: int_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn delayed_events_stream_positions(
		&self,
	) -> Result<Vec<SynapseDelayedEventsStreamPosition>> {
		if !self.table_exists("delayed_events_stream_pos")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, stream_id
			FROM delayed_events_stream_pos
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDelayedEventsStreamPosition {
					lock: row.get(0),
					stream_id: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn event_push_summary_last_receipt_stream_ids(
		&self,
	) -> Result<Vec<SynapseEventPushSummaryLastReceiptStreamId>> {
		if !self.table_exists("event_push_summary_last_receipt_stream_id")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, stream_id
			FROM event_push_summary_last_receipt_stream_id
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseEventPushSummaryLastReceiptStreamId {
					lock: row.get(0),
					stream_id: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn room_forgetter_stream_positions(
		&self,
	) -> Result<Vec<SynapseRoomForgetterStreamPosition>> {
		if !self.table_exists("room_forgetter_stream_pos")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, stream_id
			FROM room_forgetter_stream_pos
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseRoomForgetterStreamPosition {
					lock: row.get(0),
					stream_id: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn stats_incremental_positions(&self) -> Result<Vec<SynapseStatsIncrementalPosition>> {
		if !self.table_exists("stats_incremental_position")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, stream_id
			FROM stats_incremental_position
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseStatsIncrementalPosition {
					lock: row.get(0),
					stream_id: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn applied_schema_deltas(&self) -> Result<Vec<SynapseAppliedSchemaDelta>> {
		if !self.table_exists("applied_schema_deltas")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT version, file
			FROM applied_schema_deltas
			ORDER BY version, file
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseAppliedSchemaDelta {
					version: int_value(&row, 0),
					file: row.get(1),
				})
				.collect()
		})
	}

	pub fn schema_versions(&self) -> Result<Vec<SynapseSchemaVersion>> {
		if !self.table_exists("schema_version")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, version, upgraded
			FROM schema_version
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSchemaVersion {
					lock: row.get(0),
					version: int_value(&row, 1),
					upgraded: bool_value(&row, 2),
				})
				.collect()
		})
	}

	pub fn schema_compat_versions(&self) -> Result<Vec<SynapseSchemaCompatVersion>> {
		if !self.table_exists("schema_compat_version")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT lock, compat_version
			FROM schema_compat_version
			ORDER BY lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseSchemaCompatVersion {
					lock: row.get(0),
					compat_version: int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn background_updates(&self) -> Result<Vec<SynapseBackgroundUpdate>> {
		if !self.table_exists("background_updates")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT update_name, progress_json, depends_on, ordering
			FROM background_updates
			ORDER BY ordering, update_name
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseBackgroundUpdate {
					update_name: row.get(0),
					progress_json: json_from_text(&row, 1),
					depends_on: row.get(2),
					ordering: int_value(&row, 3),
				})
				.collect()
		})
	}

	pub fn scheduled_tasks(&self) -> Result<Vec<SynapseScheduledTask>> {
		if !self.table_exists("scheduled_tasks")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT id, action, status, timestamp, resource_id, params, result, error
			FROM scheduled_tasks
			ORDER BY timestamp, id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseScheduledTask {
					id: row.get(0),
					action: row.get(1),
					status: row.get(2),
					timestamp: int_value(&row, 3),
					resource_id: row.get(4),
					params: optional_json_from_text(&row, 5),
					result: optional_json_from_text(&row, 6),
					error: row.get(7),
				})
				.collect()
		})
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

	pub fn deleted_pushers(&self) -> Result<Vec<SynapseDeletedPusher>> {
		if !self.table_exists("deleted_pushers")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT stream_id, app_id, pushkey, user_id
			FROM deleted_pushers
			ORDER BY stream_id, user_id, app_id, pushkey
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseDeletedPusher {
					stream_id: int_value(&row, 0),
					app_id: row.get(1),
					pushkey: row.get(2),
					user_id: row.get(3),
				})
				.collect()
		})
	}

	pub fn application_service_txns(&self) -> Result<Vec<SynapseApplicationServiceTxn>> {
		if !self.table_exists("application_services_txns")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT as_id, txn_id, event_ids
			FROM application_services_txns
			ORDER BY as_id, txn_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseApplicationServiceTxn {
					as_id: row.get(0),
					txn_id: int_value(&row, 1),
					event_ids: json_from_text(&row, 2),
				})
				.collect()
		})
	}

	pub fn application_service_state(&self) -> Result<Vec<SynapseApplicationServiceState>> {
		if !self.table_exists("application_services_state")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT as_id, state, read_receipt_stream_id, presence_stream_id,
			       to_device_stream_id, device_list_stream_id
			FROM application_services_state
			ORDER BY as_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseApplicationServiceState {
					as_id: row.get(0),
					state: row.get(1),
					read_receipt_stream_id: optional_int_value(&row, 2),
					presence_stream_id: optional_int_value(&row, 3),
					to_device_stream_id: optional_int_value(&row, 4),
					device_list_stream_id: optional_int_value(&row, 5),
				})
				.collect()
		})
	}

	pub fn appservice_stream_position(
		&self,
	) -> Result<Vec<SynapseApplicationServiceStreamPosition>> {
		if !self.table_exists("appservice_stream_position")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT Lock, stream_ordering
			FROM appservice_stream_position
			ORDER BY Lock
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseApplicationServiceStreamPosition {
					lock: row.get(0),
					stream_ordering: optional_int_value(&row, 1),
				})
				.collect()
		})
	}

	pub fn appservice_room_list(&self) -> Result<Vec<SynapseApplicationServiceRoom>> {
		if !self.table_exists("appservice_room_list")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT appservice_id, network_id, room_id
			FROM appservice_room_list
			ORDER BY appservice_id, network_id, room_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseApplicationServiceRoom {
					appservice_id: row.get(0),
					network_id: row.get(1),
					room_id: row.get(2),
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

	pub fn server_signature_keys(&self) -> Result<Vec<SynapseServerSignatureKey>> {
		if !self.table_exists("server_signature_keys")? {
			return Ok(Vec::new());
		}

		self.query(
			"
			SELECT server_name, key_id, from_server, ts_added_ms, verify_key,
			       ts_valid_until_ms
			FROM server_signature_keys
			ORDER BY server_name, key_id
			",
			&[],
		)
		.map(|rows| {
			rows.into_iter()
				.map(|row| SynapseServerSignatureKey {
					server_name: row.get(0),
					key_id: row.get(1),
					from_server: row.get(2),
					ts_added_ms: optional_int_value(&row, 3),
					verify_key: row.try_get::<_, Option<Vec<u8>>>(4).ok().flatten(),
					ts_valid_until_ms: optional_int_value(&row, 5),
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

fn device_list_change_in_room_from_row(row: Row) -> SynapseDeviceListChangeInRoom {
	SynapseDeviceListChangeInRoom {
		user_id: row.get(0),
		device_id: row.get(1),
		room_id: row.get(2),
		stream_id: int_value(&row, 3),
		converted_to_destinations: bool_value(&row, 4),
		opentracing_context: row.get(5),
		instance_name: row.get(6),
		inserted_ts: optional_int_value(&row, 7),
	}
}

fn event_auth_from_row(row: Row) -> SynapseEventAuth {
	SynapseEventAuth {
		event_id: row.get(0),
		auth_id: row.get(1),
		room_id: row.get(2),
	}
}

fn event_auth_chain_from_row(row: Row) -> SynapseEventAuthChain {
	SynapseEventAuthChain {
		event_id: row.get(0),
		chain_id: int_value(&row, 1),
		sequence_number: int_value(&row, 2),
	}
}

fn event_auth_chain_link_from_row(row: Row) -> SynapseEventAuthChainLink {
	SynapseEventAuthChainLink {
		origin_chain_id: int_value(&row, 0),
		origin_sequence_number: int_value(&row, 1),
		target_chain_id: int_value(&row, 2),
		target_sequence_number: int_value(&row, 3),
	}
}

fn current_state_delta_from_row(row: Row) -> SynapseCurrentStateDelta {
	SynapseCurrentStateDelta {
		stream_id: int_value(&row, 0),
		room_id: row.get(1),
		event_type: row.get(2),
		state_key: row.get(3),
		event_id: row.get(4),
		prev_event_id: row.get(5),
		instance_name: row.get(6),
	}
}

fn state_event_from_row(row: Row) -> SynapseStateEvent {
	SynapseStateEvent {
		event_id: row.get(0),
		room_id: row.get(1),
		event_type: row.get(2),
		state_key: row.get(3),
		prev_state: row.get(4),
	}
}

fn stream_ordering_extremity_from_row(row: Row) -> SynapseStreamOrderingExtremity {
	SynapseStreamOrderingExtremity {
		stream_ordering: int_value(&row, 0),
		room_id: row.get(1),
		event_id: row.get(2),
	}
}

fn ex_outlier_stream_from_row(row: Row) -> SynapseExOutlierStream {
	SynapseExOutlierStream {
		event_stream_ordering: int_value(&row, 0),
		event_id: row.get(1),
		state_group: int_value(&row, 2),
		instance_name: row.get(3),
	}
}

fn state_group_from_row(row: Row) -> SynapseStateGroup {
	SynapseStateGroup {
		id: int_value(&row, 0),
		room_id: row.get(1),
		event_id: row.get(2),
	}
}

fn state_group_edge_from_row(row: Row) -> SynapseStateGroupEdge {
	SynapseStateGroupEdge {
		state_group: int_value(&row, 0),
		prev_state_group: int_value(&row, 1),
	}
}

fn event_to_state_group_from_row(row: Row) -> SynapseEventToStateGroup {
	SynapseEventToStateGroup {
		event_id: row.get(0),
		state_group: int_value(&row, 1),
	}
}

fn state_group_state_from_row(row: Row) -> SynapseStateGroupState {
	SynapseStateGroupState {
		state_group: int_value(&row, 0),
		room_id: row.get(1),
		event_type: row.get(2),
		state_key: row.get(3),
		event_id: row.get(4),
	}
}

fn users_in_public_room_from_row(row: Row) -> SynapseUsersInPublicRoom {
	SynapseUsersInPublicRoom {
		user_id: row.get(0),
		room_id: row.get(1),
	}
}

fn users_who_share_private_room_from_row(row: Row) -> SynapseUsersWhoSharePrivateRoom {
	SynapseUsersWhoSharePrivateRoom {
		user_id: row.get(0),
		other_user_id: row.get(1),
		room_id: row.get(2),
	}
}

fn user_directory_entry_from_row(row: Row) -> SynapseUserDirectoryEntry {
	SynapseUserDirectoryEntry {
		user_id: row.get(0),
		room_id: row.get(1),
		display_name: row.get(2),
		avatar_url: row.get(3),
	}
}

fn user_directory_search_from_row(row: Row) -> SynapseUserDirectorySearch {
	SynapseUserDirectorySearch {
		user_id: row.get(0),
		vector: row.get(1),
	}
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
	fn imports_local_current_membership_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_local_membership_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE local_current_membership (
					room_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					membership TEXT NOT NULL,
					event_stream_ordering BIGINT
				);
				INSERT INTO local_current_membership VALUES (
					'!room:example.com',
					'@alice:example.com',
					'$member:example.com',
					'join',
					2
				);
				"#
			))
			.expect("seed postgres local current membership table");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rows = source
			.local_current_membership()
			.expect("read postgres local current membership");
		assert_eq!(rows.len(), 1);
		assert_eq!(rows[0].room_id, "!room:example.com");
		assert_eq!(rows[0].user_id, "@alice:example.com");
		assert_eq!(rows[0].event_id, "$member:example.com");
		assert_eq!(rows[0].membership, "join");
		assert_eq!(rows[0].event_stream_ordering, Some(2));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_partial_state_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_partial_state_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE partial_state_rooms (
					room_id TEXT NOT NULL,
					device_lists_stream_id BIGINT,
					join_event_id TEXT,
					joined_via TEXT
				);
				INSERT INTO partial_state_rooms VALUES (
					'!partial:example.com',
					42,
					'$join:example.com',
					'remote.example'
				);

				CREATE TABLE partial_state_rooms_servers (
					room_id TEXT NOT NULL,
					server_name TEXT NOT NULL
				);
				INSERT INTO partial_state_rooms_servers VALUES (
					'!partial:example.com',
					'remote.example'
				);

				CREATE TABLE partial_state_events (
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL
				);
				INSERT INTO partial_state_events VALUES (
					'!partial:example.com',
					'$partialevent:example.com'
				);

				CREATE TABLE un_partial_stated_room_stream (
					stream_id BIGINT NOT NULL,
					instance_name TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO un_partial_stated_room_stream VALUES (
					43,
					'main',
					'!partial:example.com'
				);

				CREATE TABLE un_partial_stated_event_stream (
					stream_id BIGINT NOT NULL,
					instance_name TEXT NOT NULL,
					event_id TEXT NOT NULL,
					rejection_status_changed BOOLEAN NOT NULL
				);
				INSERT INTO un_partial_stated_event_stream VALUES (
					44,
					'main',
					'$partialevent:example.com',
					TRUE
				);
				"#
			))
			.expect("seed postgres partial-state tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rooms = source
			.partial_state_rooms()
			.expect("read postgres partial state rooms");
		assert_eq!(rooms.len(), 1);
		assert_eq!(rooms[0].room_id, "!partial:example.com");
		assert_eq!(rooms[0].device_lists_stream_id, Some(42));
		assert_eq!(rooms[0].join_event_id.as_deref(), Some("$join:example.com"));
		assert_eq!(rooms[0].joined_via.as_deref(), Some("remote.example"));

		let room_servers = source
			.partial_state_room_servers()
			.expect("read postgres partial state room servers");
		assert_eq!(room_servers.len(), 1);
		assert_eq!(room_servers[0].room_id, "!partial:example.com");
		assert_eq!(room_servers[0].server_name, "remote.example");

		let events = source
			.partial_state_events()
			.expect("read postgres partial state events");
		assert_eq!(events.len(), 1);
		assert_eq!(events[0].room_id, "!partial:example.com");
		assert_eq!(events[0].event_id, "$partialevent:example.com");

		let unstated_rooms = source
			.un_partial_stated_rooms()
			.expect("read postgres un-partial-stated rooms");
		assert_eq!(unstated_rooms.len(), 1);
		assert_eq!(unstated_rooms[0].stream_id, 43);
		assert_eq!(unstated_rooms[0].instance_name, "main");
		assert_eq!(unstated_rooms[0].room_id, "!partial:example.com");

		let unstated_events = source
			.un_partial_stated_events()
			.expect("read postgres un-partial-stated events");
		assert_eq!(unstated_events.len(), 1);
		assert_eq!(unstated_events[0].stream_id, 44);
		assert_eq!(unstated_events[0].instance_name, "main");
		assert_eq!(unstated_events[0].event_id, "$partialevent:example.com");
		assert!(unstated_events[0].rejection_status_changed);

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

	#[test]
	fn imports_event_reports_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_reports_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE event_reports (
					id BIGINT NOT NULL PRIMARY KEY,
					received_ts BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					reason TEXT,
					content TEXT
				);
				INSERT INTO event_reports VALUES (
					1,
					123456,
					'!room:example.com',
					'$event:example.com',
					'@alice:example.com',
					'bad event',
					'{{"score":-100,"reason":"bad event"}}'
				);
				"#
			))
			.expect("seed postgres event reports table");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let reports = source.event_reports().expect("read postgres event reports");
		assert_eq!(reports.len(), 1);
		assert_eq!(reports[0].id, 1);
		assert_eq!(reports[0].received_ts, 123456);
		assert_eq!(reports[0].room_id, "!room:example.com");
		assert_eq!(reports[0].event_id, "$event:example.com");
		assert_eq!(reports[0].user_id, "@alice:example.com");
		assert_eq!(reports[0].reason.as_deref(), Some("bad event"));
		assert_eq!(reports[0].content["score"], -100);
		assert_eq!(reports[0].content["reason"], "bad event");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_event_graph_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_event_graph_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE rejections (
					event_id TEXT NOT NULL,
					reason TEXT NOT NULL,
					last_check TEXT NOT NULL
				);
				INSERT INTO rejections VALUES (
					'$rejected:example.com',
					'auth_error',
					'1234'
				);

				CREATE TABLE event_backward_extremities (
					event_id TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO event_backward_extremities VALUES (
					'$backward:example.com',
					'!room:example.com'
				);

				CREATE TABLE timeline_gaps (
					room_id TEXT NOT NULL,
					instance_name TEXT NOT NULL,
					stream_ordering BIGINT NOT NULL
				);
				INSERT INTO timeline_gaps VALUES (
					'!room:example.com',
					'main',
					42
				);
				"#
			))
			.expect("seed postgres event graph metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rejected = source.rejected_events().expect("read postgres rejected events");
		assert_eq!(rejected.len(), 1);
		assert_eq!(rejected[0].event_id, "$rejected:example.com");
		assert_eq!(rejected[0].reason, "auth_error");
		assert_eq!(rejected[0].last_check, "1234");

		let backward = source
			.backward_extremities()
			.expect("read postgres backward extremities");
		assert_eq!(backward.len(), 1);
		assert_eq!(backward[0].event_id, "$backward:example.com");
		assert_eq!(backward[0].room_id, "!room:example.com");

		let gaps = source.timeline_gaps().expect("read postgres timeline gaps");
		assert_eq!(gaps.len(), 1);
		assert_eq!(gaps[0].room_id, "!room:example.com");
		assert_eq!(gaps[0].instance_name, "main");
		assert_eq!(gaps[0].stream_ordering, 42);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_event_auth_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_event_auth_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE event_auth (
					event_id TEXT NOT NULL,
					auth_id TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO event_auth VALUES (
					'$event:example.com',
					'$create:example.com',
					'!room:example.com'
				);

				CREATE TABLE event_auth_chains (
					event_id TEXT NOT NULL,
					chain_id BIGINT NOT NULL,
					sequence_number BIGINT NOT NULL
				);
				INSERT INTO event_auth_chains VALUES (
					'$create:example.com',
					7,
					8
				);

				CREATE TABLE event_auth_chain_links (
					origin_chain_id BIGINT NOT NULL,
					origin_sequence_number BIGINT NOT NULL,
					target_chain_id BIGINT NOT NULL,
					target_sequence_number BIGINT NOT NULL
				);
				INSERT INTO event_auth_chain_links VALUES (7, 8, 9, 10);

				CREATE TABLE event_auth_chain_to_calculate (
					event_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					type TEXT NOT NULL,
					state_key TEXT NOT NULL
				);
				INSERT INTO event_auth_chain_to_calculate VALUES (
					'$member:example.com',
					'!room:example.com',
					'm.room.member',
					'@alice:example.com'
				);
				"#
			))
			.expect("seed postgres event auth metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut auth_edges = Vec::new();
		source
			.for_each_event_auth_batch(|rows| {
				auth_edges.extend(rows);
				Ok(())
			})
			.expect("read postgres event auth rows");
		assert_eq!(auth_edges.len(), 1);
		assert_eq!(auth_edges[0].event_id, "$event:example.com");
		assert_eq!(auth_edges[0].auth_id, "$create:example.com");
		assert_eq!(auth_edges[0].room_id.as_deref(), Some("!room:example.com"));

		let mut chains = Vec::new();
		source
			.for_each_event_auth_chains_batch(|rows| {
				chains.extend(rows);
				Ok(())
			})
			.expect("read postgres event auth chain rows");
		assert_eq!(chains.len(), 1);
		assert_eq!(chains[0].event_id, "$create:example.com");
		assert_eq!(chains[0].chain_id, 7);
		assert_eq!(chains[0].sequence_number, 8);

		let mut links = Vec::new();
		source
			.for_each_event_auth_chain_links_batch(|rows| {
				links.extend(rows);
				Ok(())
			})
			.expect("read postgres event auth chain link rows");
		assert_eq!(links.len(), 1);
		assert_eq!(links[0].origin_chain_id, 7);
		assert_eq!(links[0].origin_sequence_number, 8);
		assert_eq!(links[0].target_chain_id, 9);
		assert_eq!(links[0].target_sequence_number, 10);

		let pending = source
			.event_auth_chain_to_calculate()
			.expect("read postgres pending event auth chain rows");
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].event_id, "$member:example.com");
		assert_eq!(pending[0].room_id, "!room:example.com");
		assert_eq!(pending[0].event_type, "m.room.member");
		assert_eq!(pending[0].state_key, "@alice:example.com");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_state_stream_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_state_stream_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE current_state_delta_stream (
					stream_id BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					type TEXT NOT NULL,
					state_key TEXT NOT NULL,
					event_id TEXT,
					prev_event_id TEXT,
					instance_name TEXT
				);
				INSERT INTO current_state_delta_stream VALUES (
					77,
					'!room:example.com',
					'm.room.topic',
					'',
					'$event:example.com',
					'$create:example.com',
					'master'
				);

				CREATE TABLE stream_ordering_to_exterm (
					stream_ordering BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL
				);
				INSERT INTO stream_ordering_to_exterm VALUES (
					101,
					'!room:example.com',
					'$event:example.com'
				);

				CREATE TABLE ex_outlier_stream (
					event_stream_ordering BIGINT NOT NULL,
					event_id TEXT NOT NULL,
					state_group BIGINT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO ex_outlier_stream VALUES (
					102,
					'$outlier:example.com',
					7,
					'master'
				);
				"#
			))
			.expect("seed postgres state stream metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut deltas = Vec::new();
		source
			.for_each_current_state_delta_stream_batch(|rows| {
				deltas.extend(rows);
				Ok(())
			})
			.expect("read postgres current state delta stream");
		assert_eq!(deltas.len(), 1);
		assert_eq!(deltas[0].stream_id, 77);
		assert_eq!(deltas[0].room_id, "!room:example.com");
		assert_eq!(deltas[0].event_type, "m.room.topic");
		assert_eq!(deltas[0].event_id.as_deref(), Some("$event:example.com"));
		assert_eq!(deltas[0].prev_event_id.as_deref(), Some("$create:example.com"));
		assert_eq!(deltas[0].instance_name.as_deref(), Some("master"));

		let mut extremities = Vec::new();
		source
			.for_each_stream_ordering_to_extremity_batch(|rows| {
				extremities.extend(rows);
				Ok(())
			})
			.expect("read postgres state stream extremities");
		assert_eq!(extremities.len(), 1);
		assert_eq!(extremities[0].stream_ordering, 101);
		assert_eq!(extremities[0].room_id, "!room:example.com");
		assert_eq!(extremities[0].event_id, "$event:example.com");

		let mut outliers = Vec::new();
		source
			.for_each_ex_outlier_stream_batch(|rows| {
				outliers.extend(rows);
				Ok(())
			})
			.expect("read postgres ex-outlier stream");
		assert_eq!(outliers.len(), 1);
		assert_eq!(outliers[0].event_stream_ordering, 102);
		assert_eq!(outliers[0].event_id, "$outlier:example.com");
		assert_eq!(outliers[0].state_group, 7);
		assert_eq!(outliers[0].instance_name.as_deref(), Some("master"));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_state_events_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_state_events_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE state_events (
					event_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					type TEXT NOT NULL,
					state_key TEXT NOT NULL,
					prev_state TEXT
				);
				INSERT INTO state_events VALUES (
					'$a:example.com',
					'!room:example.com',
					'm.room.topic',
					'',
					'$create:example.com'
				);
				INSERT INTO state_events VALUES (
					'$b:example.com',
					'!room:example.com',
					'm.room.name',
					'',
					NULL
				);
				"#
			))
			.expect("seed postgres state events table");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut rows = Vec::new();
		source
			.for_each_state_events_batch(|batch| {
				rows.extend(batch);
				Ok(())
			})
			.expect("read postgres state events");
		assert_eq!(rows.len(), 2);
		assert_eq!(rows[0].event_id, "$a:example.com");
		assert_eq!(rows[0].room_id, "!room:example.com");
		assert_eq!(rows[0].event_type, "m.room.topic");
		assert_eq!(rows[0].prev_state.as_deref(), Some("$create:example.com"));
		assert_eq!(rows[1].event_id, "$b:example.com");
		assert_eq!(rows[1].event_type, "m.room.name");
		assert_eq!(rows[1].prev_state, None);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_state_group_history_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_state_group_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE state_groups (
					id BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL
				);
				INSERT INTO state_groups VALUES (
					7,
					'!room:example.com',
					'$event:example.com'
				);

				CREATE TABLE state_group_edges (
					state_group BIGINT NOT NULL,
					prev_state_group BIGINT NOT NULL
				);
				INSERT INTO state_group_edges VALUES (8, 7);

				CREATE TABLE event_to_state_groups (
					event_id TEXT NOT NULL,
					state_group BIGINT NOT NULL
				);
				INSERT INTO event_to_state_groups VALUES (
					'$event:example.com',
					7
				);

				CREATE TABLE state_groups_state (
					state_group BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					type TEXT NOT NULL,
					state_key TEXT NOT NULL,
					event_id TEXT NOT NULL
				);
				INSERT INTO state_groups_state VALUES (
					7,
					'!room:example.com',
					'm.room.topic',
					'',
					'$event:example.com'
				);
				"#
			))
			.expect("seed postgres state group history tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut groups = Vec::new();
		source
			.for_each_state_groups_batch(|rows| {
				groups.extend(rows);
				Ok(())
			})
			.expect("read postgres state groups");
		assert_eq!(groups.len(), 1);
		assert_eq!(groups[0].id, 7);
		assert_eq!(groups[0].room_id, "!room:example.com");
		assert_eq!(groups[0].event_id, "$event:example.com");

		let mut edges = Vec::new();
		source
			.for_each_state_group_edges_batch(|rows| {
				edges.extend(rows);
				Ok(())
			})
			.expect("read postgres state group edges");
		assert_eq!(edges.len(), 1);
		assert_eq!(edges[0].state_group, 8);
		assert_eq!(edges[0].prev_state_group, 7);

		let mut event_groups = Vec::new();
		source
			.for_each_event_to_state_groups_batch(|rows| {
				event_groups.extend(rows);
				Ok(())
			})
			.expect("read postgres event state groups");
		assert_eq!(event_groups.len(), 1);
		assert_eq!(event_groups[0].event_id, "$event:example.com");
		assert_eq!(event_groups[0].state_group, 7);

		let mut state = Vec::new();
		source
			.for_each_state_groups_state_batch(|rows| {
				state.extend(rows);
				Ok(())
			})
			.expect("read postgres state group state rows");
		assert_eq!(state.len(), 1);
		assert_eq!(state[0].state_group, 7);
		assert_eq!(state[0].room_id, "!room:example.com");
		assert_eq!(state[0].event_type, "m.room.topic");
		assert_eq!(state[0].state_key, "");
		assert_eq!(state[0].event_id, "$event:example.com");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_event_relation_thread_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_threads_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE event_relations (
					event_id TEXT NOT NULL,
					relates_to_id TEXT NOT NULL,
					relation_type TEXT NOT NULL,
					aggregation_key TEXT
				);
				INSERT INTO event_relations VALUES (
					'$thread:example.com',
					'$event:example.com',
					'm.thread',
					NULL
				);

				CREATE TABLE threads (
					room_id TEXT NOT NULL,
					thread_id TEXT NOT NULL,
					latest_event_id TEXT NOT NULL,
					topological_ordering BIGINT NOT NULL,
					stream_ordering BIGINT NOT NULL
				);
				INSERT INTO threads VALUES (
					'!room:example.com',
					'$event:example.com',
					'$thread:example.com',
					1,
					43
				);
				"#
			))
			.expect("seed postgres thread tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let relations = source.event_relations().expect("read postgres event relations");
		assert_eq!(relations.len(), 1);
		assert_eq!(relations[0].relation_type, "m.thread");
		assert_eq!(relations[0].relates_to_id, "$event:example.com");

		let threads = source.threads().expect("read postgres threads");
		assert_eq!(threads.len(), 1);
		assert_eq!(threads[0].room_id, "!room:example.com");
		assert_eq!(threads[0].thread_id, "$event:example.com");
		assert_eq!(threads[0].latest_event_id, "$thread:example.com");
		assert_eq!(threads[0].stream_ordering, 43);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_room_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_room_metadata_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE rooms (
					room_id TEXT NOT NULL,
					is_public BOOLEAN,
					creator TEXT,
					room_version TEXT,
					has_auth_chain_index BOOLEAN
				);
				INSERT INTO rooms VALUES (
					'!room:example.com', true, '@alice:example.com', '1', true
				);

				CREATE TABLE room_depth (
					room_id TEXT NOT NULL,
					min_depth BIGINT
				);
				INSERT INTO room_depth VALUES ('!room:example.com', 12);
				"#
			))
			.expect("seed postgres room metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rooms = source.room_metadata().expect("read postgres room metadata");
		assert_eq!(rooms.len(), 1);
		assert_eq!(rooms[0].room_id, "!room:example.com");
		assert_eq!(rooms[0].is_public, Some(true));
		assert_eq!(rooms[0].creator.as_deref(), Some("@alice:example.com"));
		assert_eq!(rooms[0].room_version.as_deref(), Some("1"));
		assert_eq!(rooms[0].has_auth_chain_index, Some(true));

		let depths = source.room_depths().expect("read postgres room depths");
		assert_eq!(depths.len(), 1);
		assert_eq!(depths[0].room_id, "!room:example.com");
		assert_eq!(depths[0].min_depth, Some(12));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_user_directory_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_directory_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE users_in_public_rooms (
					user_id TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO users_in_public_rooms VALUES (
					'@alice:example.com',
					'!room:example.com'
				);

				CREATE TABLE users_who_share_private_rooms (
					user_id TEXT NOT NULL,
					other_user_id TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO users_who_share_private_rooms VALUES (
					'@alice:example.com',
					'@bob:example.com',
					'!room:example.com'
				);

				CREATE TABLE user_directory (
					user_id TEXT NOT NULL,
					room_id TEXT,
					display_name TEXT,
					avatar_url TEXT
				);
				INSERT INTO user_directory VALUES (
					'@alice:example.com',
					'!room:example.com',
					'Alice',
					'mxc://example.com/avatar'
				);

				CREATE TABLE user_directory_search (
					user_id TEXT NOT NULL,
					vector tsvector
				);
				INSERT INTO user_directory_search VALUES (
					'@alice:example.com',
					to_tsvector('simple', 'alice')
				);

				CREATE TABLE user_directory_stale_remote_users (
					user_id TEXT NOT NULL,
					user_server_name TEXT NOT NULL,
					next_try_at_ts BIGINT NOT NULL,
					retry_counter INTEGER NOT NULL
				);
				INSERT INTO user_directory_stale_remote_users VALUES (
					'@remote:remote.example',
					'remote.example',
					123456,
					2
				);

				CREATE TABLE user_directory_stream_pos (
					lock CHAR(1) NOT NULL,
					stream_id BIGINT
				);
				INSERT INTO user_directory_stream_pos VALUES ('X', 99);

				CREATE TABLE room_stats_current (
					room_id TEXT NOT NULL,
					current_state_events INTEGER NOT NULL,
					joined_members INTEGER NOT NULL,
					invited_members INTEGER NOT NULL,
					left_members INTEGER NOT NULL,
					banned_members INTEGER NOT NULL,
					local_users_in_room INTEGER NOT NULL,
					completed_delta_stream_id BIGINT NOT NULL,
					knocked_members INTEGER
				);
				INSERT INTO room_stats_current VALUES (
					'!room:example.com',
					2,
					1,
					0,
					0,
					0,
					1,
					77,
					0
				);

				CREATE TABLE room_stats_state (
					room_id TEXT NOT NULL,
					name TEXT,
					canonical_alias TEXT,
					join_rules TEXT,
					history_visibility TEXT,
					encryption TEXT,
					avatar TEXT,
					guest_access TEXT,
					is_federatable BOOLEAN,
					topic TEXT,
					room_type TEXT
				);
				INSERT INTO room_stats_state VALUES (
					'!room:example.com',
					'Room',
					'#test:example.com',
					'public',
					'shared',
					NULL,
					'mxc://example.com/room',
					'can_join',
					true,
					'Topic',
					NULL
				);

				CREATE TABLE room_stats_earliest_token (
					room_id TEXT NOT NULL,
					token BIGINT NOT NULL
				);
				INSERT INTO room_stats_earliest_token VALUES (
					'!room:example.com',
					1
				);
				"#
			))
			.expect("seed postgres user directory metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut public_users = Vec::new();
		source
			.for_each_users_in_public_rooms_batch(|rows| {
				public_users.extend(rows);
				Ok(())
			})
			.expect("read postgres users in public rooms");
		assert_eq!(public_users.len(), 1);
		assert_eq!(public_users[0].user_id, "@alice:example.com");
		assert_eq!(public_users[0].room_id, "!room:example.com");

		let mut private_users = Vec::new();
		source
			.for_each_users_who_share_private_rooms_batch(|rows| {
				private_users.extend(rows);
				Ok(())
			})
			.expect("read postgres users who share private rooms");
		assert_eq!(private_users.len(), 1);
		assert_eq!(private_users[0].other_user_id, "@bob:example.com");

		let mut directory = Vec::new();
		source
			.for_each_user_directory_batch(|rows| {
				directory.extend(rows);
				Ok(())
			})
			.expect("read postgres user directory");
		assert_eq!(directory.len(), 1);
		assert_eq!(directory[0].display_name.as_deref(), Some("Alice"));

		let mut search = Vec::new();
		source
			.for_each_user_directory_search_batch(|rows| {
				search.extend(rows);
				Ok(())
			})
			.expect("read postgres user directory search");
		assert_eq!(search.len(), 1);
		assert_eq!(search[0].user_id, "@alice:example.com");
		assert!(search[0].vector.as_deref().unwrap_or_default().contains("alice"));

		let stale = source
			.user_directory_stale_remote_users()
			.expect("read postgres stale remote users");
		assert_eq!(stale.len(), 1);
		assert_eq!(stale[0].user_server_name, "remote.example");

		let stream_pos = source
			.user_directory_stream_positions()
			.expect("read postgres user directory stream positions");
		assert_eq!(stream_pos.len(), 1);
		assert_eq!(stream_pos[0].stream_id, Some(99));

		let stats = source.room_stats_current().expect("read postgres room stats");
		assert_eq!(stats.len(), 1);
		assert_eq!(stats[0].joined_members, 1);

		let state = source.room_stats_state().expect("read postgres room stats state");
		assert_eq!(state.len(), 1);
		assert_eq!(state[0].name.as_deref(), Some("Room"));
		assert_eq!(state[0].is_federatable, Some(true));

		let tokens = source
			.room_stats_earliest_tokens()
			.expect("read postgres room stats earliest tokens");
		assert_eq!(tokens.len(), 1);
		assert_eq!(tokens[0].token, 1);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_identity_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_identity_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE account_validity (
					user_id TEXT PRIMARY KEY,
					expiration_ts_ms BIGINT NOT NULL,
					email_sent BOOLEAN NOT NULL,
					renewal_token TEXT,
					token_used_ts_ms BIGINT
				);
				INSERT INTO account_validity VALUES (
					'@alice:example.com',
					4102444800000,
					true,
					'renew-token',
					1234
				);

				CREATE TABLE user_threepids (
					user_id TEXT NOT NULL,
					medium TEXT NOT NULL,
					address TEXT NOT NULL,
					validated_at BIGINT,
					added_at BIGINT
				);
				INSERT INTO user_threepids VALUES (
					'@alice:example.com',
					'email',
					'alice@example.com',
					1000,
					2000
				);

				CREATE TABLE threepid_validation_session (
					session_id TEXT NOT NULL,
					medium TEXT NOT NULL,
					address TEXT NOT NULL,
					client_secret TEXT NOT NULL,
					last_send_attempt BIGINT NOT NULL,
					validated_at BIGINT
				);
				INSERT INTO threepid_validation_session VALUES (
					'validation-session',
					'email',
					'pending@example.com',
					'client-secret',
					1,
					NULL
				);

				CREATE TABLE user_threepid_id_server (
					user_id TEXT NOT NULL,
					medium TEXT NOT NULL,
					address TEXT NOT NULL,
					id_server TEXT NOT NULL
				);
				INSERT INTO user_threepid_id_server VALUES (
					'@alice:example.com',
					'email',
					'alice@example.com',
					'id.example.com'
				);

				CREATE TABLE user_external_ids (
					auth_provider TEXT NOT NULL,
					external_id TEXT NOT NULL,
					user_id TEXT NOT NULL
				);
				INSERT INTO user_external_ids VALUES (
					'oidc',
					'alice-oidc',
					'@alice:example.com'
				);

				CREATE TABLE device_auth_providers (
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					auth_provider_id TEXT NOT NULL,
					auth_provider_session_id TEXT NOT NULL
				);
				INSERT INTO device_auth_providers VALUES (
					'@alice:example.com',
					'DEVICE',
					'oidc',
					'session'
				);
				"#
			))
			.expect("seed postgres identity metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let account_validity = source
			.account_validity()
			.expect("read postgres account validity");
		assert_eq!(account_validity.len(), 1);
		assert_eq!(account_validity[0].user_id, "@alice:example.com");
		assert_eq!(account_validity[0].expiration_ts_ms, 4102444800000);
		assert!(account_validity[0].email_sent);
		assert_eq!(account_validity[0].renewal_token.as_deref(), Some("renew-token"));
		assert_eq!(account_validity[0].token_used_ts_ms, Some(1234));

		let threepids = source.threepids().expect("read postgres threepids");
		assert_eq!(threepids.len(), 1);
		assert_eq!(threepids[0].user_id, "@alice:example.com");
		assert_eq!(threepids[0].medium, "email");
		assert_eq!(threepids[0].address, "alice@example.com");
		assert_eq!(threepids[0].added_at, Some(2000));

		let validation_sessions = source
			.threepid_validation_sessions()
			.expect("read postgres threepid validation sessions");
		assert_eq!(validation_sessions.len(), 1);
		assert_eq!(validation_sessions[0].session_id, "validation-session");
		assert_eq!(validation_sessions[0].medium, "email");
		assert_eq!(validation_sessions[0].client_secret, "client-secret");
		assert_eq!(validation_sessions[0].last_send_attempt, 1);
		assert_eq!(validation_sessions[0].validated_at, None);

		let id_servers = source
			.user_threepid_id_servers()
			.expect("read postgres threepid identity servers");
		assert_eq!(id_servers.len(), 1);
		assert_eq!(id_servers[0].user_id, "@alice:example.com");
		assert_eq!(id_servers[0].id_server, "id.example.com");

		let external_ids = source
			.user_external_ids()
			.expect("read postgres external ids");
		assert_eq!(external_ids.len(), 1);
		assert_eq!(external_ids[0].auth_provider, "oidc");
		assert_eq!(external_ids[0].external_id, "alice-oidc");
		assert_eq!(external_ids[0].user_id, "@alice:example.com");

		let auth_providers = source
			.device_auth_providers()
			.expect("read postgres device auth providers");
		assert_eq!(auth_providers.len(), 1);
		assert_eq!(auth_providers[0].user_id, "@alice:example.com");
		assert_eq!(auth_providers[0].device_id, "DEVICE");
		assert_eq!(auth_providers[0].auth_provider_id, "oidc");
		assert_eq!(auth_providers[0].auth_provider_session_id, "session");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_room_tag_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_room_tags_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE room_tags (
					user_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					tag TEXT NOT NULL,
					content TEXT NOT NULL
				);
				INSERT INTO room_tags VALUES (
					'@alice:example.com',
					'!room:example.com',
					'm.favourite',
					'{{"order":0.5}}'
				);

				CREATE TABLE room_tags_revisions (
					user_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					stream_id BIGINT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO room_tags_revisions VALUES (
					'@alice:example.com',
					'!room:example.com',
					79,
					'master'
				);
				"#
			))
			.expect("seed postgres room tag tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let tags = source.room_tags().expect("read postgres room tags");
		assert_eq!(tags.len(), 1);
		assert_eq!(tags[0].tag, "m.favourite");
		assert_eq!(tags[0].content["order"], 0.5);

		let revisions = source
			.room_tag_revisions()
			.expect("read postgres room tag revisions");
		assert_eq!(revisions.len(), 1);
		assert_eq!(revisions[0].stream_id, 79);
		assert_eq!(revisions[0].instance_name.as_deref(), Some("master"));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_admin_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_admin_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE ratelimit_override (
					user_id TEXT NOT NULL,
					messages_per_second BIGINT,
					burst_count BIGINT
				);
				INSERT INTO ratelimit_override VALUES (
					'@alice:example.com',
					5,
					20
				);

				CREATE TABLE monthly_active_users (
					user_id TEXT NOT NULL,
					timestamp BIGINT NOT NULL
				);
				INSERT INTO monthly_active_users VALUES (
					'@alice:example.com',
					123456
				);

				CREATE TABLE user_daily_visits (
					user_id TEXT NOT NULL,
					device_id TEXT,
					timestamp BIGINT NOT NULL,
					user_agent TEXT
				);
				INSERT INTO user_daily_visits VALUES (
					'@alice:example.com',
					'DEVICE',
					123456,
					'Element'
				);

				CREATE TABLE user_ips (
					user_id TEXT NOT NULL,
					access_token TEXT NOT NULL,
					device_id TEXT,
					ip TEXT NOT NULL,
					user_agent TEXT NOT NULL,
					last_seen BIGINT NOT NULL
				);
				INSERT INTO user_ips VALUES (
					'@alice:example.com',
					'token',
					'DEVICE',
					'192.0.2.10',
					'Element',
					5678
				);

				CREATE TABLE user_stats_current (
					user_id TEXT NOT NULL,
					joined_rooms BIGINT NOT NULL,
					completed_delta_stream_id BIGINT NOT NULL
				);
				INSERT INTO user_stats_current VALUES (
					'@alice:example.com',
					3,
					42
				);

				CREATE TABLE deleted_pushers (
					stream_id BIGINT NOT NULL,
					app_id TEXT NOT NULL,
					pushkey TEXT NOT NULL,
					user_id TEXT NOT NULL
				);
				INSERT INTO deleted_pushers VALUES (
					7,
					'com.example.app',
					'old-pushkey',
					'@alice:example.com'
				);
				"#
			))
			.expect("seed postgres admin metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rate_limits = source
			.ratelimit_overrides()
			.expect("read postgres ratelimit overrides");
		assert_eq!(rate_limits.len(), 1);
		assert_eq!(rate_limits[0].user_id, "@alice:example.com");
		assert_eq!(rate_limits[0].messages_per_second, Some(5));
		assert_eq!(rate_limits[0].burst_count, Some(20));

		let monthly_active = source
			.monthly_active_users()
			.expect("read postgres monthly active users");
		assert_eq!(monthly_active.len(), 1);
		assert_eq!(monthly_active[0].user_id, "@alice:example.com");
		assert_eq!(monthly_active[0].timestamp, 123456);

		let daily_visits = source
			.user_daily_visits()
			.expect("read postgres user daily visits");
		assert_eq!(daily_visits.len(), 1);
		assert_eq!(daily_visits[0].user_id, "@alice:example.com");
		assert_eq!(daily_visits[0].device_id.as_deref(), Some("DEVICE"));
		assert_eq!(daily_visits[0].timestamp, 123456);
		assert_eq!(daily_visits[0].user_agent.as_deref(), Some("Element"));

		let user_ips = source.user_ips().expect("read postgres user ips");
		assert_eq!(user_ips.len(), 1);
		assert_eq!(user_ips[0].user_id, "@alice:example.com");
		assert_eq!(user_ips[0].access_token, "token");
		assert_eq!(user_ips[0].device_id.as_deref(), Some("DEVICE"));
		assert_eq!(user_ips[0].ip, "192.0.2.10");
		assert_eq!(user_ips[0].user_agent, "Element");
		assert_eq!(user_ips[0].last_seen, 5678);

		let user_stats = source
			.user_stats_current()
			.expect("read postgres user stats current");
		assert_eq!(user_stats.len(), 1);
		assert_eq!(user_stats[0].user_id, "@alice:example.com");
		assert_eq!(user_stats[0].joined_rooms, 3);
		assert_eq!(user_stats[0].completed_delta_stream_id, 42);

		let deleted_pushers = source
			.deleted_pushers()
			.expect("read postgres deleted pushers");
		assert_eq!(deleted_pushers.len(), 1);
		assert_eq!(deleted_pushers[0].stream_id, 7);
		assert_eq!(deleted_pushers[0].app_id, "com.example.app");
		assert_eq!(deleted_pushers[0].pushkey, "old-pushkey");
		assert_eq!(deleted_pushers[0].user_id, "@alice:example.com");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_ui_auth_session_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_uiaa_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE ui_auth_sessions (
					session_id TEXT NOT NULL,
					creation_time BIGINT NOT NULL,
					serverdict TEXT NOT NULL,
					clientdict TEXT NOT NULL,
					uri TEXT NOT NULL,
					method TEXT NOT NULL,
					description TEXT NOT NULL
				);
				INSERT INTO ui_auth_sessions VALUES (
					'uiaa-session',
					123456,
					'{{"user_id":"@alice:example.com"}}',
					'{{"auth":{{"type":"m.login.password"}}}}',
					'/_matrix/client/v3/account/password',
					'POST',
					'Change password'
				);

				CREATE TABLE ui_auth_sessions_credentials (
					session_id TEXT NOT NULL,
					stage_type TEXT NOT NULL,
					result TEXT NOT NULL
				);
				INSERT INTO ui_auth_sessions_credentials VALUES (
					'uiaa-session',
					'm.login.password',
					'{{"user_id":"@alice:example.com"}}'
				);

				CREATE TABLE ui_auth_sessions_ips (
					session_id TEXT NOT NULL,
					ip TEXT NOT NULL,
					user_agent TEXT NOT NULL
				);
				INSERT INTO ui_auth_sessions_ips VALUES (
					'uiaa-session',
					'127.0.0.1',
					'Element'
				);
				"#
			))
			.expect("seed postgres ui auth session tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let sessions = source
			.ui_auth_sessions()
			.expect("read postgres ui auth sessions");
		assert_eq!(sessions.len(), 1);
		assert_eq!(sessions[0].session_id, "uiaa-session");
		assert_eq!(sessions[0].creation_time, 123456);
		assert_eq!(sessions[0].serverdict["user_id"], "@alice:example.com");
		assert_eq!(sessions[0].clientdict["auth"]["type"], "m.login.password");
		assert_eq!(sessions[0].uri, "/_matrix/client/v3/account/password");
		assert_eq!(sessions[0].method, "POST");
		assert_eq!(sessions[0].description, "Change password");

		let credentials = source
			.ui_auth_session_credentials()
			.expect("read postgres ui auth credentials");
		assert_eq!(credentials.len(), 1);
		assert_eq!(credentials[0].session_id, "uiaa-session");
		assert_eq!(credentials[0].stage_type, "m.login.password");
		assert_eq!(credentials[0].result["user_id"], "@alice:example.com");

		let ips = source
			.ui_auth_session_ips()
			.expect("read postgres ui auth ips");
		assert_eq!(ips.len(), 1);
		assert_eq!(ips[0].session_id, "uiaa-session");
		assert_eq!(ips[0].ip, "127.0.0.1");
		assert_eq!(ips[0].user_agent, "Element");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_device_federation_queue_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_device_fed_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE device_federation_inbox (
					origin TEXT NOT NULL,
					message_id TEXT NOT NULL,
					received_ts BIGINT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO device_federation_inbox VALUES (
					'remote.example',
					'msg1',
					100,
					'main'
				);

				CREATE TABLE device_federation_outbox (
					destination TEXT NOT NULL,
					stream_id BIGINT NOT NULL,
					queued_ts BIGINT NOT NULL,
					messages_json TEXT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO device_federation_outbox VALUES (
					'remote.example',
					101,
					123456,
					'{{"messages":[{{"type":"m.device_list_update"}}]}}',
					'main'
				);

				CREATE TABLE device_lists_remote_extremeties (
					user_id TEXT NOT NULL,
					stream_id TEXT NOT NULL
				);
				INSERT INTO device_lists_remote_extremeties VALUES (
					'@bob:remote.example',
					'opaque-stream'
				);

				CREATE TABLE device_lists_remote_resync (
					user_id TEXT NOT NULL,
					added_ts BIGINT NOT NULL
				);
				INSERT INTO device_lists_remote_resync VALUES (
					'@bob:remote.example',
					123457
				);

				CREATE TABLE user_signature_stream (
					stream_id BIGINT NOT NULL,
					from_user_id TEXT NOT NULL,
					user_ids TEXT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO user_signature_stream VALUES (
					102,
					'@alice:example.com',
					'["@alice:example.com","@bob:remote.example"]',
					'main'
				);
				"#
			))
			.expect("seed postgres device federation queue tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let inbox = source
			.device_federation_inbox()
			.expect("read postgres device federation inbox");
		assert_eq!(inbox.len(), 1);
		assert_eq!(inbox[0].origin, "remote.example");
		assert_eq!(inbox[0].message_id, "msg1");
		assert_eq!(inbox[0].received_ts, 100);
		assert_eq!(inbox[0].instance_name.as_deref(), Some("main"));

		let outbox = source
			.device_federation_outbox()
			.expect("read postgres device federation outbox");
		assert_eq!(outbox.len(), 1);
		assert_eq!(outbox[0].destination, "remote.example");
		assert_eq!(outbox[0].stream_id, 101);
		assert_eq!(outbox[0].queued_ts, 123456);
		assert_eq!(outbox[0].messages_json["messages"][0]["type"], "m.device_list_update");
		assert_eq!(outbox[0].instance_name.as_deref(), Some("main"));

		let extremities = source
			.device_list_remote_extremities()
			.expect("read postgres remote device list extremities");
		assert_eq!(extremities.len(), 1);
		assert_eq!(extremities[0].user_id, "@bob:remote.example");
		assert_eq!(extremities[0].stream_id, "opaque-stream");

		let resync = source
			.device_list_remote_resync()
			.expect("read postgres remote device list resync");
		assert_eq!(resync.len(), 1);
		assert_eq!(resync[0].user_id, "@bob:remote.example");
		assert_eq!(resync[0].added_ts, 123457);

		let signature_stream = source
			.user_signature_stream()
			.expect("read postgres user signature stream");
		assert_eq!(signature_stream.len(), 1);
		assert_eq!(signature_stream[0].stream_id, 102);
		assert_eq!(signature_stream[0].from_user_id, "@alice:example.com");
		assert_eq!(signature_stream[0].user_ids[0], "@alice:example.com");
		assert_eq!(signature_stream[0].user_ids[1], "@bob:remote.example");
		assert_eq!(signature_stream[0].instance_name.as_deref(), Some("main"));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_server_key_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_server_keys_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE server_keys_json (
					server_name TEXT NOT NULL,
					key_id TEXT NOT NULL,
					from_server TEXT NOT NULL,
					ts_added_ms BIGINT NOT NULL,
					ts_valid_until_ms BIGINT NOT NULL,
					key_json BYTEA NOT NULL
				);
				INSERT INTO server_keys_json VALUES (
					'remote.example',
					'ed25519:1',
					'remote.example',
					1000,
					9000,
					convert_to('{{"server_name":"remote.example","valid_until_ts":9000,"verify_keys":{{"ed25519:1":{{"key":"YWJj"}}}}}}','UTF8')
				);

				CREATE TABLE server_signature_keys (
					server_name TEXT,
					key_id TEXT,
					from_server TEXT,
					ts_added_ms BIGINT,
					verify_key BYTEA,
					ts_valid_until_ms BIGINT
				);
				INSERT INTO server_signature_keys VALUES (
					'remote.example',
					'ed25519:1',
					'matrix.org',
					1000,
					decode('616263','hex'),
					9000
				);
				"#
			))
			.expect("seed postgres server key tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let keys = source.server_keys().expect("read postgres server keys");
		assert_eq!(keys.len(), 1);
		assert_eq!(keys[0].server_name, "remote.example");
		assert_eq!(keys[0].key_json["verify_keys"]["ed25519:1"]["key"], "YWJj");

		let signature_keys = source
			.server_signature_keys()
			.expect("read postgres server signature keys");
		assert_eq!(signature_keys.len(), 1);
		assert_eq!(signature_keys[0].server_name.as_deref(), Some("remote.example"));
		assert_eq!(signature_keys[0].key_id.as_deref(), Some("ed25519:1"));
		assert_eq!(signature_keys[0].from_server.as_deref(), Some("matrix.org"));
		assert_eq!(signature_keys[0].verify_key.as_deref(), Some(&b"abc"[..]));

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_notification_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_notification_metadata_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE push_rules_stream (
					stream_id BIGINT NOT NULL,
					event_stream_ordering BIGINT NOT NULL,
					user_id TEXT NOT NULL,
					rule_id TEXT NOT NULL,
					op TEXT NOT NULL,
					priority_class SMALLINT,
					priority INTEGER,
					conditions TEXT,
					actions TEXT,
					instance_name TEXT
				);
				INSERT INTO push_rules_stream VALUES (
					501,
					42,
					'@alice:example.com',
					'global/content/contains-tea',
					'ADD',
					4,
					10,
					'[{{"kind":"event_match","key":"content.body","pattern":"tea"}}]',
					'["notify"]',
					'main'
				);

				CREATE TABLE event_push_summary (
					user_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					notif_count BIGINT NOT NULL,
					stream_ordering BIGINT NOT NULL,
					unread_count BIGINT,
					last_receipt_stream_ordering BIGINT,
					thread_id TEXT
				);
				INSERT INTO event_push_summary VALUES (
					'@alice:example.com',
					'!room:example.com',
					4,
					50,
					7,
					NULL,
					'main'
				);

				CREATE TABLE event_push_actions (
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					profile_tag VARCHAR(32),
					actions TEXT NOT NULL,
					topological_ordering BIGINT,
					stream_ordering BIGINT,
					notif SMALLINT,
					highlight SMALLINT,
					unread SMALLINT,
					thread_id TEXT
				);
				INSERT INTO event_push_actions VALUES (
					'!room:example.com',
					'$event:example.com',
					'@alice:example.com',
					'',
					'[]',
					1,
					42,
					1,
					1,
					1,
					'main'
				);

				CREATE TABLE event_push_actions_staging (
					event_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					actions TEXT NOT NULL,
					notif SMALLINT NOT NULL,
					highlight SMALLINT NOT NULL,
					unread SMALLINT,
					thread_id TEXT,
					inserted_ts BIGINT
				);
				INSERT INTO event_push_actions_staging VALUES (
					'$event:example.com',
					'@alice:example.com',
					'["notify"]',
					1,
					0,
					1,
					'main',
					1234
				);

				CREATE TABLE event_push_summary_stream_ordering (
					Lock CHAR(1) NOT NULL,
					stream_ordering BIGINT NOT NULL
				);
				INSERT INTO event_push_summary_stream_ordering VALUES ('X', 50);
				"#
			))
			.expect("seed postgres notification metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let rule_stream = source.push_rules_stream().expect("read postgres push rule stream");
		assert_eq!(rule_stream.len(), 1);
		assert_eq!(rule_stream[0].stream_id, 501);
		assert_eq!(rule_stream[0].conditions.as_ref().unwrap()[0]["pattern"], "tea");
		assert_eq!(rule_stream[0].actions.as_ref().unwrap()[0], "notify");

		let summaries = source
			.event_push_summaries()
			.expect("read postgres event push summaries");
		assert_eq!(summaries.len(), 1);
		assert_eq!(summaries[0].notif_count, 4);
		assert_eq!(summaries[0].thread_id.as_deref(), Some("main"));

		let actions = source
			.event_push_actions()
			.expect("read postgres event push actions");
		assert_eq!(actions.len(), 1);
		assert_eq!(actions[0].event_id, "$event:example.com");
		assert_eq!(actions[0].highlight, Some(true));

		let staging = source
			.event_push_actions_staging()
			.expect("read postgres event push action staging");
		assert_eq!(staging.len(), 1);
		assert_eq!(staging[0].actions[0], "notify");
		assert_eq!(staging[0].inserted_ts, Some(1234));

		let positions = source
			.event_push_summary_stream_positions()
			.expect("read postgres event push summary stream positions");
		assert_eq!(positions.len(), 1);
		assert_eq!(positions[0].lock, "X");
		assert_eq!(positions[0].stream_ordering, 50);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_sliding_sync_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_sliding_sync_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE sliding_sync_connections (
					connection_key BIGINT NOT NULL,
					user_id TEXT NOT NULL,
					effective_device_id TEXT NOT NULL,
					conn_id TEXT NOT NULL,
					created_ts BIGINT NOT NULL,
					last_used_ts BIGINT
				);
				INSERT INTO sliding_sync_connections VALUES (
					700, '@alice:example.com', 'DEVICE', 'conn', 1000, 1001
				);

				CREATE TABLE sliding_sync_connection_positions (
					connection_position BIGINT NOT NULL,
					connection_key BIGINT NOT NULL,
					created_ts BIGINT NOT NULL
				);
				INSERT INTO sliding_sync_connection_positions VALUES (701, 700, 1002);

				CREATE TABLE sliding_sync_connection_streams (
					connection_position BIGINT NOT NULL,
					stream TEXT NOT NULL,
					room_id TEXT NOT NULL,
					room_status TEXT NOT NULL,
					last_token TEXT
				);
				INSERT INTO sliding_sync_connection_streams VALUES (
					701, 'main', '!room:example.com', 'live', 's123'
				);

				CREATE TABLE sliding_sync_connection_room_configs (
					connection_position BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					timeline_limit BIGINT NOT NULL,
					required_state_id BIGINT NOT NULL
				);
				INSERT INTO sliding_sync_connection_room_configs VALUES (
					701, '!room:example.com', 20, 702
				);

				CREATE TABLE sliding_sync_connection_required_state (
					required_state_id BIGINT NOT NULL,
					connection_key BIGINT NOT NULL,
					required_state TEXT NOT NULL
				);
				INSERT INTO sliding_sync_connection_required_state VALUES (
					702, 700, '[["m.room.member","$ME"]]'
				);

				CREATE TABLE sliding_sync_connection_lazy_members (
					connection_key BIGINT NOT NULL,
					connection_position BIGINT,
					room_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					last_seen_ts BIGINT NOT NULL
				);
				INSERT INTO sliding_sync_connection_lazy_members VALUES (
					700, 701, '!room:example.com', '@bob:example.com', 1003
				);

				CREATE TABLE sliding_sync_membership_snapshots (
					room_id TEXT NOT NULL,
					user_id TEXT NOT NULL,
					sender TEXT NOT NULL,
					membership_event_id TEXT NOT NULL,
					membership TEXT NOT NULL,
					forgotten INTEGER NOT NULL,
					event_stream_ordering BIGINT NOT NULL,
					event_instance_name TEXT NOT NULL,
					has_known_state BOOLEAN NOT NULL,
					room_type TEXT,
					room_name TEXT,
					is_encrypted BOOLEAN NOT NULL,
					tombstone_successor_room_id TEXT
				);
				INSERT INTO sliding_sync_membership_snapshots VALUES (
					'!room:example.com', '@alice:example.com', '@alice:example.com',
					'$member:example.com', 'join', 0, 42, 'master', true, NULL, 'Room', true, NULL
				);

				CREATE TABLE sliding_sync_joined_rooms (
					room_id TEXT NOT NULL,
					event_stream_ordering BIGINT NOT NULL,
					bump_stamp BIGINT,
					room_type TEXT,
					room_name TEXT,
					is_encrypted BOOLEAN NOT NULL,
					tombstone_successor_room_id TEXT
				);
				INSERT INTO sliding_sync_joined_rooms VALUES (
					'!room:example.com', 42, 43, NULL, 'Room', true, NULL
				);

				CREATE TABLE sliding_sync_joined_rooms_to_recalculate (
					room_id TEXT NOT NULL
				);
				INSERT INTO sliding_sync_joined_rooms_to_recalculate VALUES ('!room:example.com');
				"#
			))
			.expect("seed postgres sliding sync tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let connections = source
			.sliding_sync_connections()
			.expect("read postgres sliding sync connections");
		assert_eq!(connections.len(), 1);
		assert_eq!(connections[0].connection_key, 700);
		assert_eq!(connections[0].user_id, "@alice:example.com");

		let positions = source
			.sliding_sync_connection_positions()
			.expect("read postgres sliding sync positions");
		assert_eq!(positions.len(), 1);
		assert_eq!(positions[0].connection_position, 701);

		let streams = source
			.sliding_sync_connection_streams()
			.expect("read postgres sliding sync streams");
		assert_eq!(streams.len(), 1);
		assert_eq!(streams[0].room_status, "live");

		let room_configs = source
			.sliding_sync_connection_room_configs()
			.expect("read postgres sliding sync room configs");
		assert_eq!(room_configs.len(), 1);
		assert_eq!(room_configs[0].timeline_limit, 20);

		let required_state = source
			.sliding_sync_connection_required_state()
			.expect("read postgres sliding sync required state");
		assert_eq!(required_state.len(), 1);
		assert_eq!(required_state[0].required_state[0][1], "$ME");

		let lazy_members = source
			.sliding_sync_connection_lazy_members()
			.expect("read postgres sliding sync lazy members");
		assert_eq!(lazy_members.len(), 1);
		assert_eq!(lazy_members[0].user_id, "@bob:example.com");

		let snapshots = source
			.sliding_sync_membership_snapshots()
			.expect("read postgres sliding sync membership snapshots");
		assert_eq!(snapshots.len(), 1);
		assert!(snapshots[0].has_known_state);
		assert!(snapshots[0].is_encrypted);

		let joined_rooms = source
			.sliding_sync_joined_rooms()
			.expect("read postgres sliding sync joined rooms");
		assert_eq!(joined_rooms.len(), 1);
		assert_eq!(joined_rooms[0].bump_stamp, Some(43));

		let recalculations = source
			.sliding_sync_joined_rooms_to_recalculate()
			.expect("read postgres sliding sync recalculations");
		assert_eq!(recalculations.len(), 1);
		assert_eq!(recalculations[0].room_id, "!room:example.com");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_stream_position_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_stream_positions_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE stream_positions (
					stream_name TEXT NOT NULL,
					instance_name TEXT NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO stream_positions VALUES ('events', 'master', 3019780);
				INSERT INTO stream_positions VALUES ('backfill', 'master', -10);

				CREATE TABLE delayed_events_stream_pos (
					lock CHAR(1) NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO delayed_events_stream_pos VALUES ('X', 12);

				CREATE TABLE event_push_summary_last_receipt_stream_id (
					lock CHAR(1) NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO event_push_summary_last_receipt_stream_id VALUES ('X', 13);

				CREATE TABLE room_forgetter_stream_pos (
					lock CHAR(1) NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO room_forgetter_stream_pos VALUES ('X', 14);

				CREATE TABLE stats_incremental_position (
					lock CHAR(1) NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO stats_incremental_position VALUES ('X', 15);
				"#
			))
			.expect("seed postgres stream position tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let stream_positions = source.stream_positions().expect("read postgres stream positions");
		assert_eq!(stream_positions.len(), 2);
		assert_eq!(stream_positions[0].stream_name, "backfill");
		assert_eq!(stream_positions[0].stream_id, -10);
		assert_eq!(stream_positions[1].stream_name, "events");
		assert_eq!(stream_positions[1].stream_id, 3019780);

		let delayed = source
			.delayed_events_stream_positions()
			.expect("read postgres delayed event stream positions");
		assert_eq!(delayed.len(), 1);
		assert_eq!(delayed[0].stream_id, 12);

		let push_receipts = source
			.event_push_summary_last_receipt_stream_ids()
			.expect("read postgres event push summary last receipt stream ids");
		assert_eq!(push_receipts.len(), 1);
		assert_eq!(push_receipts[0].stream_id, 13);

		let room_forgetter = source
			.room_forgetter_stream_positions()
			.expect("read postgres room forgetter stream positions");
		assert_eq!(room_forgetter.len(), 1);
		assert_eq!(room_forgetter[0].stream_id, 14);

		let stats = source
			.stats_incremental_positions()
			.expect("read postgres stats incremental positions");
		assert_eq!(stats.len(), 1);
		assert_eq!(stats[0].stream_id, 15);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_schema_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_schema_metadata_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE applied_schema_deltas (
					version INTEGER NOT NULL,
					file TEXT NOT NULL
				);
				INSERT INTO applied_schema_deltas VALUES (
					82, '82/01_add_example.sql'
				);

				CREATE TABLE schema_version (
					lock CHAR(1) NOT NULL,
					version INTEGER NOT NULL,
					upgraded BOOLEAN NOT NULL
				);
				INSERT INTO schema_version VALUES ('X', 82, true);

				CREATE TABLE schema_compat_version (
					lock CHAR(1) NOT NULL,
					compat_version INTEGER NOT NULL
				);
				INSERT INTO schema_compat_version VALUES ('X', 80);

				CREATE TABLE background_updates (
					update_name TEXT NOT NULL,
					progress_json TEXT NOT NULL,
					depends_on TEXT,
					ordering INTEGER NOT NULL
				);
				INSERT INTO background_updates VALUES (
					'populate_stats', '{{"position":42}}', NULL, 1
				);

				CREATE TABLE scheduled_tasks (
					id TEXT NOT NULL,
					action TEXT NOT NULL,
					status TEXT NOT NULL,
					timestamp BIGINT NOT NULL,
					resource_id TEXT,
					params TEXT,
					result TEXT,
					error TEXT
				);
				INSERT INTO scheduled_tasks VALUES (
					'task-1', 'purge_history', 'scheduled', 123456,
					'!room:example.com', '{{"days":30}}', NULL, NULL
				);
				"#
			))
			.expect("seed postgres schema metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let deltas = source
			.applied_schema_deltas()
			.expect("read postgres applied schema deltas");
		assert_eq!(deltas.len(), 1);
		assert_eq!(deltas[0].version, 82);
		assert_eq!(deltas[0].file, "82/01_add_example.sql");

		let versions = source.schema_versions().expect("read postgres schema versions");
		assert_eq!(versions.len(), 1);
		assert_eq!(versions[0].lock, "X");
		assert_eq!(versions[0].version, 82);
		assert!(versions[0].upgraded);

		let compat = source
			.schema_compat_versions()
			.expect("read postgres schema compat versions");
		assert_eq!(compat.len(), 1);
		assert_eq!(compat[0].compat_version, 80);

		let updates = source
			.background_updates()
			.expect("read postgres background updates");
		assert_eq!(updates.len(), 1);
		assert_eq!(updates[0].progress_json["position"], 42);

		let tasks = source.scheduled_tasks().expect("read postgres scheduled tasks");
		assert_eq!(tasks.len(), 1);
		assert_eq!(tasks[0].action, "purge_history");
		assert_eq!(tasks[0].params.as_ref().expect("task params")["days"], 30);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_receipt_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_receipts_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE receipts_linearized (
					stream_id BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					receipt_type TEXT NOT NULL,
					user_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					thread_id TEXT,
					event_stream_ordering BIGINT,
					data TEXT NOT NULL
				);
				INSERT INTO receipts_linearized VALUES (
					77,
					'!room:example.com',
					'm.read',
					'@alice:example.com',
					'$event:example.com',
					NULL,
					42,
					'{{"ts":1234}}'
				);

				CREATE TABLE receipts_graph (
					room_id TEXT NOT NULL,
					receipt_type TEXT NOT NULL,
					user_id TEXT NOT NULL,
					event_ids TEXT NOT NULL,
					data TEXT NOT NULL,
					thread_id TEXT
				);
				INSERT INTO receipts_graph VALUES (
					'!room:example.com',
					'm.read',
					'@alice:example.com',
					'["$event:example.com"]',
					'{{"ts":1234}}',
					NULL
				);
				"#
			))
			.expect("seed postgres receipt tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let receipts = source.receipts().expect("read postgres linearized receipts");
		assert_eq!(receipts.len(), 1);
		assert_eq!(receipts[0].stream_id, 77);
		assert_eq!(receipts[0].event_stream_ordering, Some(42));
		assert_eq!(receipts[0].data["ts"], 1234);

		let graph = source.receipts_graph().expect("read postgres graph receipts");
		assert_eq!(graph.len(), 1);
		assert_eq!(graph[0].room_id, "!room:example.com");
		assert_eq!(graph[0].event_ids, vec!["$event:example.com".to_owned()]);
		assert_eq!(graph[0].data["ts"], 1234);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_federation_metadata_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_federation_metadata_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE received_transactions (
					transaction_id TEXT,
					origin TEXT,
					ts BIGINT,
					response_code INTEGER,
					response_json BYTEA,
					has_been_referenced SMALLINT DEFAULT 0
				);
				INSERT INTO received_transactions VALUES (
					'txn1',
					'remote.example',
					123460,
					200,
					decode('7b7d','hex'),
					1
				);

				CREATE TABLE destinations (
					destination TEXT NOT NULL,
					retry_last_ts BIGINT,
					retry_interval BIGINT,
					failure_ts BIGINT,
					last_successful_stream_ordering BIGINT
				);
				INSERT INTO destinations VALUES (
					'remote.example',
					123461,
					60000,
					123400,
					88
				);

				CREATE TABLE destination_rooms (
					destination TEXT NOT NULL,
					room_id TEXT NOT NULL,
					stream_ordering BIGINT NOT NULL
				);
				INSERT INTO destination_rooms VALUES (
					'remote.example',
					'!room:example.com',
					89
				);

				CREATE TABLE event_failed_pull_attempts (
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					num_attempts INT NOT NULL,
					last_attempt_ts BIGINT NOT NULL,
					last_cause TEXT NOT NULL
				);
				INSERT INTO event_failed_pull_attempts VALUES (
					'!room:example.com',
					'$missing:example.com',
					2,
					123462,
					'404'
				);

				CREATE TABLE cache_invalidation_stream_by_instance (
					stream_id BIGINT NOT NULL,
					instance_name TEXT NOT NULL,
					cache_func TEXT NOT NULL,
					keys TEXT[],
					invalidation_ts BIGINT
				);
				INSERT INTO cache_invalidation_stream_by_instance VALUES (
					301,
					'master',
					'get_server_key_json_for_remote',
					ARRAY['remote.example','ed25519:key'],
					123463
				);

				CREATE TABLE federation_stream_position (
					type TEXT NOT NULL,
					stream_id BIGINT NOT NULL,
					instance_name TEXT NOT NULL
				);
				INSERT INTO federation_stream_position VALUES (
					'events',
					89,
					'master'
				);

				CREATE TABLE federation_inbound_events_staging (
					origin TEXT NOT NULL,
					room_id TEXT NOT NULL,
					event_id TEXT NOT NULL,
					received_ts BIGINT NOT NULL,
					event_json TEXT NOT NULL,
					internal_metadata TEXT NOT NULL
				);
				INSERT INTO federation_inbound_events_staging VALUES (
					'remote.example',
					'!room:example.com',
					'$staged:example.com',
					123464,
					'{{"type":"m.room.message","room_id":"!room:example.com"}}',
					'{{"outlier":true}}'
				);
				"#
			))
			.expect("seed postgres federation metadata tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let received = source
			.received_transactions()
			.expect("read postgres received transactions");
		assert_eq!(received.len(), 1);
		assert_eq!(received[0].transaction_id.as_deref(), Some("txn1"));
		assert_eq!(received[0].origin.as_deref(), Some("remote.example"));
		assert_eq!(received[0].response_json.as_deref(), Some(&b"{}"[..]));
		assert!(received[0].has_been_referenced);

		let destinations = source.destinations().expect("read postgres destinations");
		assert_eq!(destinations.len(), 1);
		assert_eq!(destinations[0].destination, "remote.example");
		assert_eq!(destinations[0].retry_interval, Some(60000));

		let destination_rooms = source
			.destination_rooms()
			.expect("read postgres destination rooms");
		assert_eq!(destination_rooms.len(), 1);
		assert_eq!(destination_rooms[0].room_id, "!room:example.com");
		assert_eq!(destination_rooms[0].stream_ordering, 89);

		let failed = source
			.event_failed_pull_attempts()
			.expect("read postgres failed pull attempts");
		assert_eq!(failed.len(), 1);
		assert_eq!(failed[0].event_id, "$missing:example.com");
		assert_eq!(failed[0].num_attempts, 2);

		let cache = source
			.cache_invalidations()
			.expect("read postgres cache invalidations");
		assert_eq!(cache.len(), 1);
		assert_eq!(
			cache[0].keys.as_deref(),
			Some(&["remote.example".to_owned(), "ed25519:key".to_owned()][..])
		);

		let stream_positions = source
			.federation_stream_positions()
			.expect("read postgres federation stream positions");
		assert_eq!(stream_positions.len(), 1);
		assert_eq!(stream_positions[0].stream_type, "events");
		assert_eq!(stream_positions[0].instance_name.as_deref(), Some("master"));

		let inbound = source
			.federation_inbound_events()
			.expect("read postgres federation inbound events");
		assert_eq!(inbound.len(), 1);
		assert_eq!(inbound[0].event_id, "$staged:example.com");
		assert_eq!(inbound[0].event_json["type"], "m.room.message");
		assert_eq!(inbound[0].internal_metadata["outlier"], true);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_remote_device_keys_in_batches_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_remote_device_cache_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE device_lists_remote_cache (
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					content TEXT NOT NULL
				);
				INSERT INTO device_lists_remote_cache VALUES (
					'@bob:remote.example',
					'REMOTE',
					'{{"keys":{{"ed25519:REMOTE":"remote-key"}}}}'
				);
				"#
			))
			.expect("seed postgres remote device cache table");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let mut keys = Vec::new();
		source
			.for_each_remote_device_keys_batch(|rows| {
				keys.extend(rows);
				Ok(())
			})
			.expect("read postgres remote device cache");
		assert_eq!(keys.len(), 1);
		assert_eq!(keys[0].user_id, "@bob:remote.example");
		assert_eq!(keys[0].device_id, "REMOTE");
		assert_eq!(keys[0].key_json["keys"]["ed25519:REMOTE"], "remote-key");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_device_list_stream_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_device_list_stream_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE device_lists_stream (
					stream_id BIGINT NOT NULL,
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO device_lists_stream VALUES (
					201,
					'@alice:example.com',
					'DEVICE',
					'main'
				);

				CREATE TABLE device_lists_outbound_pokes (
					destination TEXT NOT NULL,
					stream_id BIGINT NOT NULL,
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					sent BOOLEAN NOT NULL,
					ts BIGINT NOT NULL,
					opentracing_context TEXT,
					instance_name TEXT
				);
				INSERT INTO device_lists_outbound_pokes VALUES (
					'remote.example',
					202,
					'@alice:example.com',
					'DEVICE',
					false,
					123458,
					'{{"trace":"ctx"}}',
					'main'
				);

				CREATE TABLE device_lists_outbound_last_success (
					destination TEXT NOT NULL,
					user_id TEXT NOT NULL,
					stream_id BIGINT NOT NULL
				);
				INSERT INTO device_lists_outbound_last_success VALUES (
					'remote.example',
					'@alice:example.com',
					203
				);

				CREATE TABLE device_lists_remote_pending (
					stream_id BIGINT NOT NULL,
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO device_lists_remote_pending VALUES (
					204,
					'@bob:remote.example',
					'REMOTE',
					'main'
				);

				CREATE TABLE device_lists_changes_in_room (
					user_id TEXT NOT NULL,
					device_id TEXT NOT NULL,
					room_id TEXT NOT NULL,
					stream_id BIGINT NOT NULL,
					converted_to_destinations BOOLEAN NOT NULL,
					opentracing_context TEXT,
					instance_name TEXT,
					inserted_ts BIGINT
				);
				INSERT INTO device_lists_changes_in_room VALUES (
					'@alice:example.com',
					'DEVICE',
					'!room:example.com',
					207,
					false,
					'{{"trace":"room"}}',
					'main',
					123459
				);

				CREATE TABLE device_lists_changes_converted_stream_position (
					stream_id BIGINT NOT NULL,
					room_id TEXT NOT NULL,
					instance_name TEXT
				);
				INSERT INTO device_lists_changes_converted_stream_position VALUES (
					205,
					'!room:example.com',
					'main'
				);

				CREATE TABLE device_lists_changes_in_room_max_pruned_stream_id (
					stream_id BIGINT NOT NULL
				);
				INSERT INTO device_lists_changes_in_room_max_pruned_stream_id VALUES (206);
				"#
			))
			.expect("seed postgres device list stream tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let stream_updates = source
			.device_list_stream_updates()
			.expect("read postgres device list stream updates");
		assert_eq!(stream_updates.len(), 1);
		assert_eq!(stream_updates[0].stream_id, 201);
		assert_eq!(stream_updates[0].user_id, "@alice:example.com");
		assert_eq!(stream_updates[0].device_id, "DEVICE");
		assert_eq!(stream_updates[0].instance_name.as_deref(), Some("main"));

		let outbound_pokes = source
			.device_list_outbound_pokes()
			.expect("read postgres outbound device list pokes");
		assert_eq!(outbound_pokes.len(), 1);
		assert_eq!(outbound_pokes[0].destination, "remote.example");
		assert_eq!(outbound_pokes[0].stream_id, 202);
		assert_eq!(outbound_pokes[0].user_id, "@alice:example.com");
		assert_eq!(outbound_pokes[0].device_id, "DEVICE");
		assert!(!outbound_pokes[0].sent);
		assert_eq!(outbound_pokes[0].ts, 123458);
		assert_eq!(
			outbound_pokes[0].opentracing_context.as_deref(),
			Some("{\"trace\":\"ctx\"}")
		);
		assert_eq!(outbound_pokes[0].instance_name.as_deref(), Some("main"));

		let last_success = source
			.device_list_outbound_last_success()
			.expect("read postgres device list last success");
		assert_eq!(last_success.len(), 1);
		assert_eq!(last_success[0].destination, "remote.example");
		assert_eq!(last_success[0].user_id, "@alice:example.com");
		assert_eq!(last_success[0].stream_id, 203);

		let remote_pending = source
			.device_list_remote_pending()
			.expect("read postgres remote pending device list updates");
		assert_eq!(remote_pending.len(), 1);
		assert_eq!(remote_pending[0].stream_id, 204);
		assert_eq!(remote_pending[0].user_id, "@bob:remote.example");
		assert_eq!(remote_pending[0].device_id, "REMOTE");
		assert_eq!(remote_pending[0].instance_name.as_deref(), Some("main"));

		let mut room_changes = Vec::new();
		source
			.for_each_device_list_changes_in_room_batch(|rows| {
				room_changes.extend(rows);
				Ok(())
			})
			.expect("read postgres device list room changes");
		assert_eq!(room_changes.len(), 1);
		assert_eq!(room_changes[0].stream_id, 207);
		assert_eq!(room_changes[0].user_id, "@alice:example.com");
		assert_eq!(room_changes[0].device_id, "DEVICE");
		assert_eq!(room_changes[0].room_id, "!room:example.com");
		assert!(!room_changes[0].converted_to_destinations);
		assert_eq!(
			room_changes[0].opentracing_context.as_deref(),
			Some("{\"trace\":\"room\"}")
		);
		assert_eq!(room_changes[0].instance_name.as_deref(), Some("main"));
		assert_eq!(room_changes[0].inserted_ts, Some(123459));

		let converted_positions = source
			.device_list_changes_converted_positions()
			.expect("read postgres device list converted positions");
		assert_eq!(converted_positions.len(), 1);
		assert_eq!(converted_positions[0].stream_id, 205);
		assert_eq!(converted_positions[0].room_id, "!room:example.com");
		assert_eq!(converted_positions[0].instance_name.as_deref(), Some("main"));

		let max_pruned = source
			.device_list_changes_max_pruned()
			.expect("read postgres device list max pruned stream");
		assert_eq!(max_pruned.len(), 1);
		assert_eq!(max_pruned[0].stream_id, 206);

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}

	#[test]
	fn imports_appservice_delivery_rows_when_postgres_available() {
		let Ok(url) = env::var("CONTINUWUITY_TEST_POSTGRES_URL") else {
			return;
		};

		let mut client = Client::connect(&url, NoTls).expect("connect to postgres test database");
		let schema = format!("continuwuity_migration_appservice_test_{}", process::id());
		client
			.batch_execute(&format!(
				r#"
				DROP SCHEMA IF EXISTS {schema} CASCADE;
				CREATE SCHEMA {schema};
				SET search_path TO {schema};

				CREATE TABLE application_services_txns (
					as_id TEXT NOT NULL,
					txn_id BIGINT NOT NULL,
					event_ids TEXT NOT NULL
				);
				INSERT INTO application_services_txns VALUES (
					'bridge',
					11,
					'["$event:example.com"]'
				);

				CREATE TABLE application_services_state (
					as_id TEXT NOT NULL,
					state TEXT,
					read_receipt_stream_id BIGINT,
					presence_stream_id BIGINT,
					to_device_stream_id BIGINT,
					device_list_stream_id BIGINT
				);
				INSERT INTO application_services_state VALUES (
					'bridge',
					'up',
					77,
					88,
					99,
					101
				);

				CREATE TABLE appservice_stream_position (
					Lock CHAR(1) NOT NULL,
					stream_ordering BIGINT
				);
				INSERT INTO appservice_stream_position VALUES (
					'X',
					42
				);

				CREATE TABLE appservice_room_list (
					appservice_id TEXT NOT NULL,
					network_id TEXT NOT NULL,
					room_id TEXT NOT NULL
				);
				INSERT INTO appservice_room_list VALUES (
					'bridge',
					'irc',
					'!room:example.com'
				);
				"#
			))
			.expect("seed postgres appservice delivery tables");

		let source = PostgresSource {
			client: RefCell::new(client),
		};

		let txns = source
			.application_service_txns()
			.expect("read postgres appservice txns");
		assert_eq!(txns.len(), 1);
		assert_eq!(txns[0].as_id, "bridge");
		assert_eq!(txns[0].txn_id, 11);
		assert_eq!(txns[0].event_ids[0], "$event:example.com");

		let states = source
			.application_service_state()
			.expect("read postgres appservice state");
		assert_eq!(states.len(), 1);
		assert_eq!(states[0].as_id, "bridge");
		assert_eq!(states[0].state.as_deref(), Some("up"));
		assert_eq!(states[0].read_receipt_stream_id, Some(77));
		assert_eq!(states[0].presence_stream_id, Some(88));
		assert_eq!(states[0].to_device_stream_id, Some(99));
		assert_eq!(states[0].device_list_stream_id, Some(101));

		let positions = source
			.appservice_stream_position()
			.expect("read postgres appservice stream position");
		assert_eq!(positions.len(), 1);
		assert_eq!(positions[0].lock, "X");
		assert_eq!(positions[0].stream_ordering, Some(42));

		let rooms = source
			.appservice_room_list()
			.expect("read postgres appservice room list");
		assert_eq!(rooms.len(), 1);
		assert_eq!(rooms[0].appservice_id, "bridge");
		assert_eq!(rooms[0].network_id, "irc");
		assert_eq!(rooms[0].room_id, "!room:example.com");

		source
			.client
			.borrow_mut()
			.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
			.expect("drop postgres test schema");
	}
}
