use std::{
	collections::{BTreeMap, BTreeSet},
	fs,
	path::{Path, PathBuf},
	str::FromStr,
	time::{SystemTime, UNIX_EPOCH},
};

use base64::{
	Engine,
	prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD},
};
use conduwuit_core::utils::hash;
use conduwuit_database as database;
use database::{Json, serialize_to_vec};
use rust_rocksdb as rocksdb;
use ruma::{
	RoomVersionId,
	canonical_json::{CanonicalJsonValue, redact_content_in_place},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
	Error, Result,
	sqlite::{
		SynapseAccessToken, SynapseAccountData, SynapseBlockedRoom, SynapseCrossSigningKey, SynapseDevice,
		SynapseDehydratedDevice, SynapseDeviceKey, SynapseErasedUser, SynapseEventEdge, SynapseEventRelation,
		SynapseFallbackKey, SynapseFilter, SynapseForgottenRoom, SynapseForwardExtremity,
		SynapseIgnoredUser, SynapseKeySignature, SynapseLoginToken, SynapseMedia,
		SynapseNotificationCount, SynapseOneTimeKey, SynapseOpenIdToken, SynapsePresence, SynapseProfile,
		SynapsePublicRoom, SynapsePusher, SynapsePushRule, SynapseReceipt, SynapseRedaction,
		SynapseRegistrationToken, SynapseRoomAlias, SynapseRoomEvent, SynapseRoomKeyBackup,
		SynapseRoomKeyBackupVersion, SynapseRoomState, SynapseRoomTag, SynapseServerKey, SynapseThreepid,
		SynapseToDeviceMessage, SynapseUrlPreview, SynapseUser,
	},
};

const REQUIRED_CFS: &[&str] = &[
	"global",
	"bannedroomids",
	"userid_password",
	"userid_lock",
	"userid_erased",
	"registrationtoken_info",
	"userid_displayname",
	"userid_avatarurl",
	"email_localpart",
	"localpart_email",
	"userid_devicelistversion",
	"userid_dehydrateddevice",
	"userdeviceid_metadata",
	"userdeviceid_token",
	"token_userdeviceid",
	"openidtoken_expiresatuserid",
	"logintoken_expiresatuserid",
	"keyid_key",
	"onetimekeyid_onetimekeys",
	"fallbackkeyid_fallbackkey",
	"userid_lastonetimekeyupdate",
	"userid_masterkeyid",
	"userid_selfsigningkeyid",
	"userid_usersigningkeyid",
	"keychangeid_userid",
	"backupid_algorithm",
	"backupid_etag",
	"backupkeyid_backup",
	"todeviceid_events",
	"userfilterid_filter",
	"roomuserdataid_accountdata",
	"roomusertype_roomuserdataid",
	"presenceid_presence",
	"userid_presenceid",
	"mediaid_file",
	"mediaid_user",
	"url_previews",
	"roomid_shortroomid",
	"eventid_shorteventid",
	"shorteventid_eventid",
	"eventid_pduid",
	"pduid_pdu",
	"tokenids",
	"roomid_pduleaves",
	"tofrom_relation",
	"threadid_userids",
	"statekey_shortstatekey",
	"shortstatekey_statekey",
	"shorteventid_shortstatehash",
	"roomid_shortstatehash",
	"shortstatehash_statediff",
	"alias_userid",
	"alias_roomid",
	"aliasid_alias",
	"publicroomids",
	"userroomid_joined",
	"roomuserid_joined",
	"roomuseroncejoinedids",
	"roomid_joinedcount",
	"roomid_invitedcount",
	"roomserverids",
	"serverroomids",
	"userroomid_invitestate",
	"roomuserid_invitecount",
	"userroomid_invitesender",
	"userroomid_leftstate",
	"roomuserid_leftcount",
	"userroomid_knockedstate",
	"roomuserid_knockedcount",
	"readreceiptid_readreceipt",
	"referencedevents",
	"roomuserid_privateread",
	"roomuserid_lastprivatereadupdate",
	"userroomid_notificationcount",
	"userroomid_highlightcount",
	"senderkey_pusher",
	"pushkey_deviceid",
	"id_appserviceregistrations",
	"server_signingkeys",
];

#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
	pub users: u64,
	pub locked_users: u64,
	pub erased_users: u64,
	pub registration_tokens: u64,
	pub profiles: u64,
	pub threepids: u64,
	pub devices: u64,
	pub dehydrated_devices: u64,
	pub device_keys: u64,
	pub one_time_keys: u64,
	pub fallback_keys: u64,
	pub cross_signing_keys: u64,
	pub key_signatures: u64,
	pub room_key_backup_versions: u64,
	pub room_key_backups: u64,
	pub to_device_messages: u64,
	pub access_tokens: u64,
	pub open_id_tokens: u64,
	pub login_tokens: u64,
	pub account_data: u64,
	pub push_rules: u64,
	pub ignored_users: u64,
	pub room_tags: u64,
	pub filters: u64,
	pub presence: u64,
	pub media: u64,
	pub url_previews: u64,
	pub room_events: u64,
	pub event_edges: u64,
	pub redactions: u64,
	pub search_indexed_events: u64,
	pub event_relations: u64,
	pub thread_summaries: u64,
	pub room_state: u64,
	pub forward_extremities: u64,
	pub forgotten_rooms: u64,
	pub blocked_rooms: u64,
	pub room_aliases: u64,
	pub public_rooms: u64,
	pub receipts: u64,
	pub notification_counts: u64,
	pub pushers: u64,
	pub appservices: u64,
	pub signing_keys: u64,
	pub server_keys: u64,
	pub skipped: BTreeMap<String, u64>,
	pub warnings: Vec<String>,
}

pub struct ContinuwuityStore {
	path: PathBuf,
	db: rocksdb::DB,
	counter: u64,
}

impl ContinuwuityStore {
	pub fn open(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref().to_owned();
		let mut opts = rocksdb::Options::default();
		opts.create_if_missing(true);
		opts.create_missing_column_families(true);

		let mut names = rocksdb::DB::list_cf(&opts, &path)
			.unwrap_or_default()
			.into_iter()
			.collect::<BTreeSet<_>>();
		names.insert("default".to_owned());
		for name in REQUIRED_CFS {
			names.insert((*name).to_owned());
		}

		let descriptors = names
			.into_iter()
			.map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()));
		let db = rocksdb::DB::open_cf_descriptors(&opts, &path, descriptors)
			.map_err(|e| Error::rocksdb(&path, e))?;
		let counter = db
			.cf_handle("global")
			.and_then(|cf| db.get_cf(&cf, b"c").ok().flatten())
			.and_then(|value| value.as_slice().try_into().ok().map(u64::from_be_bytes))
			.unwrap_or_default();

		Ok(Self { path, db, counter })
	}

	pub fn import_users(
		&mut self,
		users: Vec<SynapseUser>,
		server_name: Option<&str>,
		password_pepper: Option<&str>,
		report: &mut ImportReport,
	) -> Result<()> {
		let pepper = password_pepper.unwrap_or_default();
		let locking_user = migration_user_id(server_name);
		if server_name.is_none() && users.iter().any(|user| user.locked) {
			report.warn(
				"Synapse locked-user metadata imported with fallback locking user @synapse-migration:unknown.invalid"
					.to_owned(),
			);
		}
		for user in users {
			if !user.name.starts_with('@') {
				report.skip("users.invalid_user_id");
				continue;
			}
			if user.admin {
				report.warn(format!(
					"Synapse admin user {} imported as a normal account; add them to admins_list or the admin room",
					user.name
				));
			}
			if user.shadow_banned {
				report.warn(format!(
					"Synapse shadow-ban flag for {} has no continuwuity equivalent",
					user.name
				));
			}
			if user.appservice_id.is_some() || user.user_type.as_deref() == Some("support") {
				report.warn(format!(
					"Synapse user {} has special account metadata that may need manual review",
					user.name
				));
			}

			let password = if user.deactivated {
				Vec::new()
			} else if let Some(password_hash) = user.password_hash.filter(|hash| !hash.is_empty()) {
				hash::synapse_bcrypt_password_hash(&password_hash, pepper)?.into_bytes()
			} else {
				Vec::new()
			};

			self.put_raw("userid_password", user.name.as_bytes(), &password)?;
			if user.locked {
				let lock = serde_json::to_vec(&json!({
					"suspended": true,
					"suspended_at": 0_u64,
					"suspended_by": &locking_user,
				}))?;
				self.put_raw("userid_lock", user.name.as_bytes(), &lock)?;
				report.locked_users = report.locked_users.saturating_add(1);
			}
			report.users = report.users.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_erased_users(
		&self,
		users: Vec<SynapseErasedUser>,
		report: &mut ImportReport,
	) -> Result<()> {
		for user in users {
			if !user.user_id.starts_with('@') {
				report.skip("erased_users.invalid_user_id");
				continue;
			}

			self.put_raw("userid_erased", user.user_id.as_bytes(), b"")?;
			report.erased_users = report.erased_users.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_registration_tokens(
		&self,
		tokens: Vec<SynapseRegistrationToken>,
		server_name: Option<&str>,
		report: &mut ImportReport,
	) -> Result<()> {
		let creator = migration_user_id(server_name);
		if server_name.is_none() && !tokens.is_empty() {
			report.warn(
				"Synapse registration token creator metadata imported with fallback server name unknown.invalid"
					.to_owned(),
			);
		}

		for token in tokens {
			if token.token.trim().is_empty() {
				report.skip("registration_tokens.empty_token");
				continue;
			}
			if token.pending < 0 || token.completed < 0 {
				report.skip("registration_tokens.invalid_counts");
				continue;
			}
			let Some(expires) = registration_token_expires(&token, report) else {
				continue;
			};

			let info = json!({
				"creator": creator,
				"uses": u64::try_from(token.completed).unwrap_or_default(),
				"expires": expires,
			});
			self.put_raw(
				"registrationtoken_info",
				token.token.as_bytes(),
				&serde_json::to_vec(&info)?,
			)?;
			report.registration_tokens = report.registration_tokens.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_profiles(
		&self,
		profiles: Vec<SynapseProfile>,
		report: &mut ImportReport,
	) -> Result<()> {
		for profile in profiles {
			if !profile.user_id.starts_with('@') {
				report.skip("profiles.invalid_user_id");
				continue;
			}
			if let Some(displayname) = profile.displayname {
				self.put_raw("userid_displayname", profile.user_id.as_bytes(), displayname.as_bytes())?;
			}
			if let Some(avatar_url) = profile.avatar_url {
				self.put_raw("userid_avatarurl", profile.user_id.as_bytes(), avatar_url.as_bytes())?;
			}
			report.profiles = report.profiles.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_threepids(
		&self,
		threepids: Vec<SynapseThreepid>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut localparts_with_primary_email = BTreeSet::<String>::new();

		for threepid in threepids {
			if threepid.medium != "email" {
				report.skip("threepids.unsupported_medium");
				continue;
			}
			let Some(localpart) = user_id_localpart(&threepid.user_id) else {
				report.skip("threepids.invalid_user_id");
				continue;
			};
			let email = threepid.address.trim().to_ascii_lowercase();
			if !valid_email_address(&email) {
				report.skip("threepids.invalid_email");
				continue;
			}

			self.put_raw("email_localpart", email.as_bytes(), localpart.as_bytes())?;
			if localparts_with_primary_email.insert(localpart.to_owned()) {
				self.put_raw("localpart_email", localpart.as_bytes(), email.as_bytes())?;
			} else {
				report.warn(format!(
					"Synapse user {} has multiple email threepids; imported {} for email login but kept the newest address as the account email",
					threepid.user_id, email
				));
			}
			report.threepids = report.threepids.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_devices(
		&self,
		devices: Vec<SynapseDevice>,
		report: &mut ImportReport,
	) -> Result<()> {
		for device in devices {
			if device.hidden {
				report.skip("devices.hidden");
				continue;
			}
			if !device.user_id.starts_with('@') || device.device_id.is_empty() {
				report.skip("devices.invalid_id");
				continue;
			}

			let key = serialize_to_vec((&device.user_id, &device.device_id))?;
			let metadata = json!({
				"device_id": device.device_id,
				"display_name": device.display_name,
				"last_seen_ip": device.ip,
				"last_seen_ts": device.last_seen,
			});
			self.put_raw("userdeviceid_metadata", &key, &serde_json::to_vec(&metadata)?)?;
			self.put_raw(
				"userid_devicelistversion",
				device.user_id.as_bytes(),
				&1_u64.to_be_bytes(),
			)?;
			report.devices = report.devices.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_dehydrated_devices(
		&self,
		devices: Vec<SynapseDehydratedDevice>,
		report: &mut ImportReport,
	) -> Result<()> {
		for device in devices {
			if !device.user_id.starts_with('@') || device.device_id.is_empty() {
				report.skip("dehydrated_devices.invalid");
				continue;
			}

			let value = json!({
				"device_id": device.device_id,
				"device_data": device.device_data,
			});
			self.put_raw(
				"userid_dehydrateddevice",
				device.user_id.as_bytes(),
				&serde_json::to_vec(&value)?,
			)?;
			report.dehydrated_devices = report.dehydrated_devices.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_device_keys(
		&mut self,
		device_keys: Vec<SynapseDeviceKey>,
		signatures: Vec<SynapseKeySignature>,
		report: &mut ImportReport,
	) -> Result<()> {
		let signatures = signatures_by_target(signatures);
		let mut updated_users = BTreeSet::new();

		for device_key in device_keys {
			if !device_key.user_id.starts_with('@') || device_key.device_id.is_empty() {
				report.skip("device_keys.invalid");
				continue;
			}
			let mut key_json = device_key.key_json;
			report.key_signatures = report.key_signatures.saturating_add(apply_key_signatures(
				&mut key_json,
				signatures.get(&(device_key.user_id.clone(), device_key.device_id.clone())),
			));

			let key = serialize_to_vec((&device_key.user_id, &device_key.device_id))?;
			self.put_raw("keyid_key", &key, &serde_json::to_vec(&key_json)?)?;
			updated_users.insert(device_key.user_id);
			report.device_keys = report.device_keys.saturating_add(1);
		}

		self.mark_key_updates(updated_users)
	}

	pub fn import_one_time_keys(
		&mut self,
		keys: Vec<SynapseOneTimeKey>,
		report: &mut ImportReport,
	) -> Result<()> {
		for key in keys {
			if !key.user_id.starts_with('@')
				|| key.device_id.is_empty()
				|| key.algorithm.is_empty()
				|| key.key_id.is_empty()
			{
				report.skip("one_time_keys.invalid");
				continue;
			}

			let key_id = format!("{}:{}", key.algorithm, key.key_id);
			let mut db_key = key.user_id.as_bytes().to_vec();
			db_key.push(0xFF);
			db_key.extend_from_slice(key.device_id.as_bytes());
			db_key.push(0xFF);
			db_key.extend_from_slice(serde_json::to_string(&key_id)?.as_bytes());

			self.put_raw(
				"onetimekeyid_onetimekeys",
				&db_key,
				&serde_json::to_vec(&key.key_json)?,
			)?;
			let count = self.next_count()?;
			self.put_raw(
				"userid_lastonetimekeyupdate",
				key.user_id.as_bytes(),
				&count.to_be_bytes(),
			)?;
			report.one_time_keys = report.one_time_keys.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_fallback_keys(
		&self,
		keys: Vec<SynapseFallbackKey>,
		report: &mut ImportReport,
	) -> Result<()> {
		for key in keys {
			if !key.user_id.starts_with('@')
				|| key.device_id.is_empty()
				|| key.algorithm.is_empty()
				|| key.key_id.is_empty()
			{
				report.skip("fallback_keys.invalid");
				continue;
			}

			let db_key = serialize_to_vec((&key.user_id, &key.device_id, &key.algorithm))?;
			let key_id = format!("{}:{}", key.algorithm, key.key_id);
			let value = serialize_to_vec((key.used, &key_id, Json(&key.key_json)))?;
			self.put_raw("fallbackkeyid_fallbackkey", &db_key, &value)?;
			report.fallback_keys = report.fallback_keys.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_cross_signing_keys(
		&mut self,
		keys: Vec<SynapseCrossSigningKey>,
		signatures: Vec<SynapseKeySignature>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut latest = BTreeMap::<(String, String), SynapseCrossSigningKey>::new();
		for key in keys {
			if !key.user_id.starts_with('@') {
				report.skip("cross_signing_keys.invalid_user_id");
				continue;
			}
			let map_key = (key.user_id.clone(), key.key_type.clone());
			if latest
				.get(&map_key)
				.is_none_or(|existing| key.stream_id >= existing.stream_id)
			{
				latest.insert(map_key, key);
			}
		}

		let signatures = signatures_by_target(signatures);
		let mut updated_users = BTreeSet::new();
		for key in latest.into_values() {
			let Some(cf) = cross_signing_index_cf(&key.key_type) else {
				report.skip("cross_signing_keys.unsupported_type");
				continue;
			};
			let mut key_data = key.key_data;
			let Some(public_key) = cross_signing_public_key(&key_data) else {
				report.skip("cross_signing_keys.invalid_key_data");
				continue;
			};
			report.key_signatures = report.key_signatures.saturating_add(apply_key_signatures(
				&mut key_data,
				signatures.get(&(key.user_id.clone(), public_key.clone())),
			));

			let db_key = serialize_to_vec((&key.user_id, &public_key))?;
			self.put_raw("keyid_key", &db_key, &serde_json::to_vec(&key_data)?)?;
			self.put_raw(cf, key.user_id.as_bytes(), &db_key)?;
			updated_users.insert(key.user_id);
			report.cross_signing_keys = report.cross_signing_keys.saturating_add(1);
		}

		self.mark_key_updates(updated_users)
	}

	pub fn import_room_key_backups(
		&mut self,
		versions: Vec<SynapseRoomKeyBackupVersion>,
		keys: Vec<SynapseRoomKeyBackup>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut active_versions = BTreeSet::<(String, i64)>::new();

		for version in versions {
			if !version.user_id.starts_with('@') || version.version <= 0 || version.algorithm.is_empty() {
				report.skip("room_key_backup_versions.invalid");
				continue;
			}
			if version.auth_data.is_null() {
				report.skip("room_key_backup_versions.invalid_auth_data");
				continue;
			}

			let version_id = version.version.to_string();
			let key = serialize_to_vec((&version.user_id, &version_id))?;
			let metadata = json!({
				"algorithm": version.algorithm,
				"auth_data": version.auth_data,
			});
			let etag = version
				.etag
				.and_then(|etag| u64::try_from(etag).ok())
				.unwrap_or_default();

			self.put_raw("backupid_algorithm", &key, &serde_json::to_vec(&metadata)?)?;
			self.put_raw("backupid_etag", &key, &etag.to_be_bytes())?;
			self.reserve_count(u64::try_from(version.version).unwrap_or_default())?;
			active_versions.insert((version.user_id, version.version));
			report.room_key_backup_versions =
				report.room_key_backup_versions.saturating_add(1);
		}

		for key in keys {
			if !key.user_id.starts_with('@')
				|| key.version <= 0
				|| !key.room_id.starts_with('!')
				|| key.session_id.is_empty()
			{
				report.skip("room_key_backups.invalid");
				continue;
			}
			if !active_versions.contains(&(key.user_id.clone(), key.version)) {
				report.skip("room_key_backups.missing_version");
				continue;
			}
			if key.session_data.is_null() {
				report.skip("room_key_backups.invalid_session_data");
				continue;
			}

			let version_id = key.version.to_string();
			let db_key = serialize_to_vec((&key.user_id, &version_id, &key.room_id, &key.session_id))?;
			let value = json!({
				"first_message_index": key.first_message_index.unwrap_or_default(),
				"forwarded_count": key.forwarded_count.unwrap_or_default(),
				"is_verified": key.is_verified,
				"session_data": key.session_data,
			});
			self.put_raw("backupkeyid_backup", &db_key, &serde_json::to_vec(&value)?)?;
			report.room_key_backups = report.room_key_backups.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_to_device_messages(
		&mut self,
		messages: Vec<SynapseToDeviceMessage>,
		report: &mut ImportReport,
	) -> Result<()> {
		for message in messages {
			if !message.user_id.starts_with('@') || message.device_id.is_empty() {
				report.skip("to_device_messages.invalid_target");
				continue;
			}
			let Some(count) = positive_stream_ordering(Some(message.stream_id)) else {
				report.skip("to_device_messages.invalid_stream_id");
				continue;
			};
			if !valid_to_device_message(&message.message_json) {
				report.skip("to_device_messages.invalid_json");
				continue;
			}

			let key = serialize_to_vec((&message.user_id, &message.device_id, count))?;
			self.put_raw(
				"todeviceid_events",
				&key,
				&serde_json::to_vec(&message.message_json)?,
			)?;
			self.reserve_count(count)?;
			report.to_device_messages = report.to_device_messages.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_access_tokens(
		&self,
		tokens: Vec<SynapseAccessToken>,
		report: &mut ImportReport,
	) -> Result<()> {
		let now = now_millis();
		for token in tokens {
			if token
				.valid_until_ms
				.is_some_and(|valid_until| valid_until > 0 && valid_until < now)
			{
				report.skip("access_tokens.expired");
				continue;
			}
			let Some(device_id) = token.device_id.filter(|device_id| !device_id.is_empty()) else {
				report.skip("access_tokens.no_device");
				continue;
			};
			if !token.user_id.starts_with('@') || token.token.is_empty() {
				report.skip("access_tokens.invalid");
				continue;
			}

			let userdeviceid = serialize_to_vec((&token.user_id, &device_id))?;
			self.put_raw("userdeviceid_token", &userdeviceid, token.token.as_bytes())?;
			self.put_raw("token_userdeviceid", token.token.as_bytes(), &userdeviceid)?;
			report.access_tokens = report.access_tokens.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_open_id_tokens(
		&self,
		tokens: Vec<SynapseOpenIdToken>,
		report: &mut ImportReport,
	) -> Result<()> {
		for token in tokens {
			if token.token.is_empty() || !token.user_id.starts_with('@') {
				report.skip("open_id_tokens.invalid");
				continue;
			}
			let Some(expires_at) = u64::try_from(token.ts_valid_until_ms).ok() else {
				report.skip("open_id_tokens.invalid_expiry");
				continue;
			};
			if token.ts_valid_until_ms <= now_millis() {
				report.skip("open_id_tokens.expired");
				continue;
			}

			let mut value = expires_at.to_be_bytes().to_vec();
			value.extend_from_slice(token.user_id.as_bytes());
			self.put_raw("openidtoken_expiresatuserid", token.token.as_bytes(), &value)?;
			report.open_id_tokens = report.open_id_tokens.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_login_tokens(
		&self,
		tokens: Vec<SynapseLoginToken>,
		report: &mut ImportReport,
	) -> Result<()> {
		let now = now_millis();
		for token in tokens {
			if token.token.is_empty() || !token.user_id.starts_with('@') {
				report.skip("login_tokens.invalid");
				continue;
			}
			let Some(expires_at) = u64::try_from(token.expiry_ts).ok() else {
				report.skip("login_tokens.invalid_expiry");
				continue;
			};
			if token.used_ts.is_some() {
				report.skip("login_tokens.used");
				continue;
			}
			if token.expiry_ts <= now {
				report.skip("login_tokens.expired");
				continue;
			}

			let value = serialize_to_vec((expires_at, &token.user_id))?;
			self.put_raw("logintoken_expiresatuserid", token.token.as_bytes(), &value)?;
			report.login_tokens = report.login_tokens.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_account_data(
		&mut self,
		rows: Vec<SynapseAccountData>,
		report: &mut ImportReport,
	) -> Result<()> {
		for row in rows {
			if !row.user_id.starts_with('@') || row.event_type.is_empty() {
				report.skip("account_data.invalid");
				continue;
			}

			self.put_account_data_event(
				row.room_id.as_deref(),
				&row.user_id,
				&row.event_type,
				row.content,
			)?;
			report.account_data = report.account_data.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_push_rules(
		&mut self,
		rows: Vec<SynapsePushRule>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut grouped = BTreeMap::<String, Vec<SynapsePushRule>>::new();

		for row in rows {
			if !row.user_id.starts_with('@') || row.rule_id.is_empty() {
				report.skip("push_rules.invalid");
				continue;
			}

			grouped.entry(row.user_id.clone()).or_default().push(row);
		}

		for (user_id, rules) in grouped {
			let mut global = empty_push_rules_global();
			let mut imported = 0_u64;

			for rule in rules {
				let Some(kind) = push_rule_kind(rule.priority_class) else {
					report.skip("push_rules.unknown_class");
					continue;
				};
				let Some(template) = push_rule_template(&user_id, &rule, kind, report) else {
					continue;
				};
				let rule_array = global
					.get_mut(kind)
					.and_then(Value::as_array_mut)
					.expect("push rule kind arrays are initialized");
				rule_array.push(template);
				imported = imported.saturating_add(1);
			}

			if imported == 0 {
				continue;
			}

			self.put_account_data_event(None, &user_id, "m.push_rules", json!({ "global": global }))?;
			report.push_rules = report.push_rules.saturating_add(imported);
		}

		Ok(())
	}

	pub fn import_ignored_users(
		&mut self,
		rows: Vec<SynapseIgnoredUser>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();

		for row in rows {
			if !row.ignorer_user_id.starts_with('@') || !row.ignored_user_id.starts_with('@') {
				report.skip("ignored_users.invalid");
				continue;
			}

			grouped
				.entry(row.ignorer_user_id)
				.or_default()
				.insert(row.ignored_user_id);
			report.ignored_users = report.ignored_users.saturating_add(1);
		}

		for (user_id, ignored_users) in grouped {
			let mut content = self
				.account_data_content(None, &user_id, "m.ignored_user_list")?
				.unwrap_or_else(|| json!({ "ignored_users": {} }));
			if !content.is_object() {
				content = json!({ "ignored_users": {} });
			}

			let content_object = content.as_object_mut().expect("object checked above");
			let existing_ignored = content_object
				.entry("ignored_users")
				.or_insert_with(|| json!({}));
			if !existing_ignored.is_object() {
				*existing_ignored = json!({});
			}
			let ignored_object = existing_ignored.as_object_mut().expect("object checked above");
			for ignored_user_id in ignored_users {
				ignored_object.entry(ignored_user_id).or_insert_with(|| json!({}));
			}

			self.put_account_data_event(None, &user_id, "m.ignored_user_list", content)?;
		}

		Ok(())
	}

	pub fn import_room_tags(
		&mut self,
		rows: Vec<SynapseRoomTag>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut grouped = BTreeMap::<(String, String), BTreeMap<String, Value>>::new();

		for row in rows {
			if !row.user_id.starts_with('@') || !row.room_id.starts_with('!') || row.tag.is_empty() {
				report.skip("room_tags.invalid");
				continue;
			}
			if !row.content.is_object() {
				report.skip("room_tags.invalid_content");
				continue;
			}

			grouped
				.entry((row.user_id, row.room_id))
				.or_default()
				.insert(row.tag, row.content);
			report.room_tags = report.room_tags.saturating_add(1);
		}

		for ((user_id, room_id), tags) in grouped {
			let mut content = self
				.account_data_content(Some(&room_id), &user_id, "m.tag")?
				.unwrap_or_else(|| json!({ "tags": {} }));
			if !content.is_object() {
				content = json!({ "tags": {} });
			}

			let content_object = content.as_object_mut().expect("object checked above");
			let existing_tags = content_object.entry("tags").or_insert_with(|| json!({}));
			if !existing_tags.is_object() {
				*existing_tags = json!({});
			}
			let tag_object = existing_tags.as_object_mut().expect("object checked above");
			for (tag, tag_content) in tags {
				tag_object.insert(tag, tag_content);
			}

			self.put_account_data_event(Some(&room_id), &user_id, "m.tag", content)?;
		}

		Ok(())
	}

	pub fn import_filters(
		&self,
		filters: Vec<SynapseFilter>,
		report: &mut ImportReport,
	) -> Result<()> {
		for filter in filters {
			if !filter.user_id.starts_with('@') || filter.filter_id < 0 {
				report.skip("filters.invalid");
				continue;
			}
			if !filter.filter_json.is_object() {
				report.skip("filters.invalid_json");
				continue;
			}

			let filter_id = filter.filter_id.to_string();
			let key = serialize_to_vec((&filter.user_id, &filter_id))?;
			self.put_raw(
				"userfilterid_filter",
				&key,
				&serde_json::to_vec(&filter.filter_json)?,
			)?;
			report.filters = report.filters.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_presence(
		&mut self,
		presence: Vec<SynapsePresence>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut latest = BTreeMap::<String, SynapsePresence>::new();

		for presence in presence {
			if !presence.user_id.starts_with('@') {
				report.skip("presence.invalid_user_id");
				continue;
			}
			if !valid_presence_state(&presence.state) {
				report.skip("presence.invalid_state");
				continue;
			}
			if positive_stream_ordering(Some(presence.stream_id)).is_none() {
				report.skip("presence.invalid_stream_id");
				continue;
			}

			let key = presence.user_id.clone();
			if latest
				.get(&key)
				.is_none_or(|existing| presence.stream_id >= existing.stream_id)
			{
				latest.insert(key, presence);
			}
		}

		for presence in latest.into_values() {
			let count = positive_stream_ordering(Some(presence.stream_id))
				.expect("presence stream_id was already validated");
			let last_active_ts = presence
				.last_active_ts
				.and_then(|ts| u64::try_from(ts).ok())
				.unwrap_or_default();
			let status_msg = presence.status_msg.filter(|msg| !msg.is_empty());
			let value = json!({
				"state": presence.state,
				"currently_active": presence.currently_active.unwrap_or(false),
				"last_active_ts": last_active_ts,
				"status_msg": status_msg,
			});

			self.reserve_count(count)?;
			self.put_raw(
				"presenceid_presence",
				&presenceid_key(count, &presence.user_id),
				&serde_json::to_vec(&value)?,
			)?;
			self.put_raw("userid_presenceid", presence.user_id.as_bytes(), &count.to_be_bytes())?;
			report.presence = report.presence.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_media(
		&self,
		media: Vec<SynapseMedia>,
		report: &mut ImportReport,
	) -> Result<()> {
		for media in media {
			if !media.source_path.exists() {
				report.skip("media.missing_file");
				continue;
			}

			let mxc = format!("mxc://{}/{}", media.mxc_server, media.media_id);
			let metadata_key = media_metadata_key(&mxc, media.content_type.as_deref())?;
			self.put_raw("mediaid_file", &metadata_key, &[])?;

			if let Some(user_id) = media.user_id.filter(|user_id| user_id.starts_with('@')) {
				let owner_key = serialize_to_vec((&mxc, &user_id))?;
				self.put_raw("mediaid_user", &owner_key, user_id.as_bytes())?;
			}

			let destination = self.media_file_path(&metadata_key);
			if let Some(parent) = destination.parent() {
				fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
			}
			fs::copy(&media.source_path, &destination).map_err(|e| Error::io(&destination, e))?;
			report.media = report.media.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_url_previews(
		&self,
		previews: Vec<SynapseUrlPreview>,
		report: &mut ImportReport,
	) -> Result<()> {
		for preview in previews {
			if preview.url.is_empty() {
				report.skip("url_previews.invalid_url");
				continue;
			}
			if !preview.og.is_object() {
				report.skip("url_previews.invalid_og");
				continue;
			}

			let Some(value) = encode_url_preview(&preview.og, preview.download_ts) else {
				report.skip("url_previews.empty_og");
				continue;
			};

			self.put_raw("url_previews", preview.url.as_bytes(), &value)?;
			report.url_previews = report.url_previews.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_room_events(
		&mut self,
		events: Vec<SynapseRoomEvent>,
		report: &mut ImportReport,
	) -> Result<()> {
		for event in events {
			if !event.event_id.starts_with('$') || !event.room_id.starts_with('!') {
				report.skip("room_events.invalid_id");
				continue;
			}
			if positive_stream_ordering(Some(event.stream_ordering)).is_none() {
				report.skip("room_events.invalid_stream_ordering");
				continue;
			}
			if self
				.get_raw_cf("eventid_shorteventid", event.event_id.as_bytes())?
				.is_some()
			{
				report.skip("room_events.existing_event");
				continue;
			}
			let shorteventid =
				self.available_shorteventid(&event.event_id, Some(event.stream_ordering), report)?;

			self.store_room_event(&event.event_id, &event.room_id, shorteventid, event.json)?;
			report.room_events = report.room_events.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_event_edges(
		&self,
		edges: Vec<SynapseEventEdge>,
		report: &mut ImportReport,
	) -> Result<()> {
		for edge in edges {
			let Some(room_id) = edge.room_id.filter(|room_id| room_id.starts_with('!')) else {
				report.skip("event_edges.invalid_room_id");
				continue;
			};
			if !edge.event_id.starts_with('$') || !edge.prev_event_id.starts_with('$') {
				report.skip("event_edges.invalid_event_id");
				continue;
			}
			if self.get_raw_cf("eventid_pduid", edge.event_id.as_bytes())?.is_none() {
				report.skip("event_edges.missing_event");
				continue;
			}

			let key = serialize_to_vec((&room_id, &edge.prev_event_id))?;
			self.put_raw("referencedevents", &key, &[])?;
			report.event_edges = report.event_edges.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_forward_extremities(
		&self,
		rows: Vec<SynapseForwardExtremity>,
		report: &mut ImportReport,
	) -> Result<()> {
		for row in rows {
			if !row.event_id.starts_with('$') || !row.room_id.starts_with('!') {
				report.skip("forward_extremities.invalid_id");
				continue;
			}
			if self.get_raw_cf("eventid_pduid", row.event_id.as_bytes())?.is_none() {
				report.skip("forward_extremities.missing_event");
				continue;
			}

			let key = serialize_to_vec((&row.room_id, &row.event_id))?;
			self.put_raw("roomid_pduleaves", &key, row.event_id.as_bytes())?;
			report.forward_extremities = report.forward_extremities.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_event_relations(
		&self,
		relations: Vec<SynapseEventRelation>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut threads = BTreeMap::<String, ThreadSummary>::new();

		for relation in relations {
			if !relation.event_id.starts_with('$') || !relation.relates_to_id.starts_with('$') {
				report.skip("event_relations.invalid_event_id");
				continue;
			}
			if relation.relation_type.is_empty() {
				report.skip("event_relations.missing_relation_type");
				continue;
			}

			let Some(from) = self.existing_shorteventid(&relation.event_id)? else {
				report.skip("event_relations.missing_relation_event");
				continue;
			};
			let Some(to) = self.existing_shorteventid(&relation.relates_to_id)? else {
				report.skip("event_relations.missing_target_event");
				continue;
			};

			self.put_raw("tofrom_relation", &relation_key(to, from), &[])?;
			report.event_relations = report.event_relations.saturating_add(1);

			if relation.relation_type == "m.thread" {
				self.record_thread_relation(relation, from, &mut threads, report)?;
			}
		}

		for thread in threads.into_values() {
			self.store_thread_summary(thread, report)?;
		}

		Ok(())
	}

	pub fn import_redactions(
		&self,
		redactions: Vec<SynapseRedaction>,
		report: &mut ImportReport,
	) -> Result<()> {
		for redaction in redactions {
			if !redaction.event_id.starts_with('$') || !redaction.redacts.starts_with('$') {
				report.skip("redactions.invalid_event_id");
				continue;
			}

			let Some(redaction_pduid) = self.event_pduid(&redaction.event_id)? else {
				report.skip("redactions.missing_redaction_event");
				continue;
			};
			let Some(redaction_json) = self.pdu_json(&redaction_pduid)? else {
				report.skip("redactions.missing_redaction_json");
				continue;
			};
			let Some(target_pduid) = self.event_pduid(&redaction.redacts)? else {
				report.skip("redactions.missing_target_event");
				continue;
			};
			let Some(mut target_json) = self.pdu_json(&target_pduid)? else {
				report.skip("redactions.missing_target_json");
				continue;
			};

			if let Some(body) = searchable_body_from_value(&target_json) {
				self.deindex_search_body(&target_pduid, &body)?;
			}
			self.redact_pdu_json(&mut target_json, redaction_json, report)?;
			self.put_raw("pduid_pdu", &target_pduid, &serde_json::to_vec(&target_json)?)?;
			report.redactions = report.redactions.saturating_add(1);
		}

		Ok(())
	}

	pub fn rebuild_search_index(&self, report: &mut ImportReport) -> Result<()> {
		for (pduid, pdu) in self.scan_cf("pduid_pdu")? {
			let Some(body) = searchable_body(&pdu)? else {
				continue;
			};
			if pduid.len() < size_of::<u64>() * 2 {
				report.skip("search_index.invalid_pduid");
				continue;
			}

			let shortroomid = &pduid[..size_of::<u64>()];
			let mut indexed = false;
			for word in tokenize_search_body(&body) {
				let mut key = Vec::with_capacity(
					size_of::<u64>() + word.len() + 1 + pduid.len(),
				);
				key.extend_from_slice(shortroomid);
				key.extend_from_slice(word.as_bytes());
				key.push(0xFF);
				key.extend_from_slice(&pduid);
				self.put_raw("tokenids", &key, &[])?;
				indexed = true;
			}
			if indexed {
				report.search_indexed_events = report.search_indexed_events.saturating_add(1);
			}
		}

		Ok(())
	}

	pub fn import_room_state(
		&mut self,
		state: Vec<SynapseRoomState>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut rooms = BTreeMap::<String, BTreeMap<(String, String), StateEntry>>::new();
		let mut memberships = BTreeMap::<String, MembershipSummary>::new();

		for row in state {
			if !row.event_id.starts_with('$') || !row.room_id.starts_with('!') {
				report.skip("room_state.invalid_id");
				continue;
			}
			if row.event_type.is_empty() {
				report.skip("room_state.invalid_state_key");
				continue;
			}

			let Some(shorteventid) = self.ensure_room_event(
				&row.event_id,
				&row.room_id,
				row.stream_ordering,
				row.json.clone(),
				report,
			)?
			else {
				report.skip("room_state.missing_event_json");
				continue;
			};
			let shortstatekey = self.shortstatekey_for(&row.event_type, &row.state_key)?;

			rooms.entry(row.room_id.clone()).or_default().insert(
				(row.event_type.clone(), row.state_key.clone()),
				StateEntry { shortstatekey, shorteventid },
			);

			if row.event_type == "m.room.member" && row.state_key.starts_with('@') {
				let room_id = row.room_id.clone();
				self.record_membership(row, report, memberships.entry(room_id).or_default())?;
			}

			report.room_state = report.room_state.saturating_add(1);
		}

		for (room_id, state) in rooms {
			let shortstatehash = self.next_count()?;
			let mut compressed = BTreeSet::<[u8; 16]>::new();
			for entry in state.values() {
				compressed
					.insert(compressed_state_event(entry.shortstatekey, entry.shorteventid));
				self.put_raw(
					"shorteventid_shortstatehash",
					&entry.shorteventid.to_be_bytes(),
					&shortstatehash.to_be_bytes(),
				)?;
			}

			self.put_raw(
				"roomid_shortstatehash",
				room_id.as_bytes(),
				&shortstatehash.to_be_bytes(),
			)?;
			self.put_raw(
				"shortstatehash_statediff",
				&shortstatehash.to_be_bytes(),
				&state_diff_value(&compressed),
			)?;
		}

		for (room_id, summary) in memberships {
			self.put_raw(
				"roomid_joinedcount",
				room_id.as_bytes(),
				&summary.joined_count.to_be_bytes(),
			)?;
			self.put_raw(
				"roomid_invitedcount",
				room_id.as_bytes(),
				&summary.invited_count.to_be_bytes(),
			)?;
			self.put_raw(
				"roomuserid_knockedcount",
				room_id.as_bytes(),
				&summary.knocked_count.to_be_bytes(),
			)?;

			for server in summary.joined_servers {
				let roomserver = serialize_to_vec((&room_id, &server))?;
				let serverroom = serialize_to_vec((&server, &room_id))?;
				self.put_raw("roomserverids", &roomserver, &[])?;
				self.put_raw("serverroomids", &serverroom, &[])?;
			}
		}

		Ok(())
	}

	pub fn import_forgotten_rooms(
		&self,
		rooms: Vec<SynapseForgottenRoom>,
		report: &mut ImportReport,
	) -> Result<()> {
		for room in rooms {
			if !room.user_id.starts_with('@') || !room.room_id.starts_with('!') {
				report.skip("forgotten_rooms.invalid_id");
				continue;
			}

			let userroom = serialize_to_vec((&room.user_id, &room.room_id))?;
			let roomuser = serialize_to_vec((&room.room_id, &room.user_id))?;
			self.remove_raw("userroomid_leftstate", &userroom)?;
			self.remove_raw("roomuserid_leftcount", &roomuser)?;
			report.forgotten_rooms = report.forgotten_rooms.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_blocked_rooms(
		&self,
		blocked_rooms: Vec<SynapseBlockedRoom>,
		report: &mut ImportReport,
	) -> Result<()> {
		for blocked_room in blocked_rooms {
			if !blocked_room.room_id.starts_with('!') {
				report.skip("blocked_rooms.invalid_room_id");
				continue;
			}

			self.put_raw("bannedroomids", blocked_room.room_id.as_bytes(), &[])?;
			report.blocked_rooms = report.blocked_rooms.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_receipts(
		&mut self,
		receipts: Vec<SynapseReceipt>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut public = BTreeMap::<(String, String), SynapseReceipt>::new();
		let mut private = BTreeMap::<(String, String), SynapseReceipt>::new();

		for receipt in receipts {
			if !receipt.room_id.starts_with('!')
				|| !receipt.user_id.starts_with('@')
				|| !receipt.event_id.starts_with('$')
			{
				report.skip("receipts.invalid_id");
				continue;
			}

			match receipt.receipt_type.as_str() {
				| "m.read" => keep_preferred_receipt(&mut public, receipt),
				| "m.read.private" => keep_preferred_receipt(&mut private, receipt),
				| _ => report.skip("receipts.unsupported_type"),
			}
		}

		for receipt in public.into_values() {
			let count = self.receipt_count(&receipt)?;
			let key = serialize_to_vec((&receipt.room_id, count, &receipt.user_id))?;
			let event = public_receipt_event(&receipt);
			self.put_raw(
				"readreceiptid_readreceipt",
				&key,
				&serde_json::to_vec(&event)?,
			)?;
			report.receipts = report.receipts.saturating_add(1);
		}

		for receipt in private.into_values() {
			let Some(pdu_count) = self.pdu_count_for_receipt(&receipt)? else {
				report.skip("receipts.private_missing_event");
				continue;
			};
			let key = serialize_to_vec((&receipt.room_id, &receipt.user_id))?;
			let update_count = self.receipt_count(&receipt)?;
			self.put_raw("roomuserid_privateread", &key, &pdu_count.to_be_bytes())?;
			self.put_raw(
				"roomuserid_lastprivatereadupdate",
				&key,
				&update_count.to_be_bytes(),
			)?;
			report.receipts = report.receipts.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_notification_counts(
		&self,
		counts: Vec<SynapseNotificationCount>,
		report: &mut ImportReport,
	) -> Result<()> {
		for count in counts {
			if !count.user_id.starts_with('@') || !count.room_id.starts_with('!') {
				report.skip("notification_counts.invalid_id");
				continue;
			}
			if count.notification_count < 0 || count.highlight_count < 0 {
				report.skip("notification_counts.invalid_count");
				continue;
			}

			let userroom = serialize_to_vec((&count.user_id, &count.room_id))?;
			if count.notification_count > 0 {
				let value = u64::try_from(count.notification_count)
					.unwrap_or(u64::MAX)
					.to_be_bytes();
				self.put_raw("userroomid_notificationcount", &userroom, &value)?;
			}
			if count.highlight_count > 0 {
				let value = u64::try_from(count.highlight_count)
					.unwrap_or(u64::MAX)
					.to_be_bytes();
				self.put_raw("userroomid_highlightcount", &userroom, &value)?;
			}
			report.notification_counts = report.notification_counts.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_room_aliases(
		&mut self,
		aliases: Vec<SynapseRoomAlias>,
		report: &mut ImportReport,
	) -> Result<()> {
		for alias in aliases {
			if !alias.room_id.starts_with('!') {
				report.skip("room_aliases.invalid_room_id");
				continue;
			}
			let Some(localpart) = room_alias_localpart(&alias.room_alias) else {
				report.skip("room_aliases.invalid_alias");
				continue;
			};
			if alias.servers.is_empty() {
				report.warn(format!(
					"Synapse room alias {} has no room_alias_servers rows; continuwuity will resolve it from room state only",
					alias.room_alias
				));
			}

			if let Some(creator) = alias.creator.as_deref().filter(|creator| creator.starts_with('@'))
			{
				self.put_raw("alias_userid", localpart.as_bytes(), creator.as_bytes())?;
			} else {
				report.skip("room_aliases.missing_creator");
			}

			self.put_raw("alias_roomid", localpart.as_bytes(), alias.room_id.as_bytes())?;

			let mut aliasid = alias.room_id.as_bytes().to_vec();
			aliasid.push(0xFF);
			aliasid.extend_from_slice(&self.next_count()?.to_be_bytes());
			self.put_raw("aliasid_alias", &aliasid, alias.room_alias.as_bytes())?;
			report.room_aliases = report.room_aliases.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_public_rooms(
		&self,
		rooms: Vec<SynapsePublicRoom>,
		report: &mut ImportReport,
	) -> Result<()> {
		for room in rooms {
			if !room.room_id.starts_with('!') {
				report.skip("public_rooms.invalid_room_id");
				continue;
			}

			self.put_raw("publicroomids", room.room_id.as_bytes(), &[])?;
			report.public_rooms = report.public_rooms.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_pushers(
		&self,
		pushers: Vec<SynapsePusher>,
		report: &mut ImportReport,
	) -> Result<()> {
		for pusher in pushers {
			if !pusher.user_id.starts_with('@')
				|| pusher.pushkey.is_empty()
				|| pusher.app_id.is_empty()
			{
				report.skip("pushers.invalid");
				continue;
			}

			let key = serialize_to_vec((&pusher.user_id, &pusher.pushkey))?;
			self.put_raw(
				"senderkey_pusher",
				&key,
				&serde_json::to_vec(&pusher_json(&pusher))?,
			)?;
			if let Some(device_id) = pusher.device_id.filter(|device_id| !device_id.is_empty()) {
				self.put_raw("pushkey_deviceid", pusher.pushkey.as_bytes(), device_id.as_bytes())?;
			}
			report.pushers = report.pushers.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_server_keys(
		&self,
		keys: Vec<SynapseServerKey>,
		report: &mut ImportReport,
	) -> Result<()> {
		let mut by_server = BTreeMap::<String, Value>::new();

		for key in keys {
			if key.server_name.is_empty() || key.key_id.is_empty() {
				report.skip("server_keys.invalid");
				continue;
			}
			let Some(normalized) = normalize_server_key_json(&key) else {
				report.skip("server_keys.invalid_json");
				continue;
			};
			merge_server_key_json(
				by_server
					.entry(key.server_name.clone())
					.or_insert_with(|| base_server_key_json(&key.server_name)),
				normalized,
			);
			report.server_keys = report.server_keys.saturating_add(1);
		}

		for (server_name, keys) in by_server {
			self.put_raw(
				"server_signingkeys",
				server_name.as_bytes(),
				&serde_json::to_vec(&keys)?,
			)?;
		}

		Ok(())
	}

	pub fn import_appservices(
		&self,
		paths: &[PathBuf],
		report: &mut ImportReport,
	) -> Result<()> {
		for path in paths {
			let body = fs::read(path).map_err(|e| Error::io(path, e))?;
			let registration =
				serde_saphyr::from_slice::<SynapseAppserviceRegistration>(&body).map_err(|e| {
					Error::Yaml {
						path: path.to_owned(),
						source: e,
					}
				})?;
			let Some(id) = registration.id.filter(|id| !id.is_empty()) else {
				report.skip("appservices.missing_id");
				continue;
			};

			self.put_raw("id_appserviceregistrations", id.as_bytes(), &body)?;
			report.appservices = report.appservices.saturating_add(1);
		}

		Ok(())
	}

	pub fn import_signing_key(
		&self,
		body: &[u8],
		report: &mut ImportReport,
	) -> Result<()> {
		let keys = synapse_signing_keys(body, report);
		let Some(key) = keys.first() else {
			return Err(Error::Message(
				"Synapse signing key import selected but no usable ed25519 signing key was found"
					.to_owned(),
			));
		};
		if keys.len() > 1 {
			report.warn(
				"Synapse has multiple active signing keys; imported the first because continuwuity supports one active Ed25519 keypair"
					.to_owned(),
			);
		}

		let value = serialize_to_vec((&key.version, &key.der))?;
		self.put_raw("global", b"keypair", &value)?;
		report.signing_keys = report.signing_keys.saturating_add(1);

		Ok(())
	}

	fn record_membership(
		&mut self,
		row: SynapseRoomState,
		report: &mut ImportReport,
		summary: &mut MembershipSummary,
	) -> Result<()> {
		let userroom = serialize_to_vec((&row.state_key, &row.room_id))?;
		let roomuser = serialize_to_vec((&row.room_id, &row.state_key))?;
		let membership = row.membership.as_deref().unwrap_or_default();

		match membership {
			| "join" => {
				self.put_raw("userroomid_joined", &userroom, &[])?;
				self.put_raw("roomuserid_joined", &roomuser, &[])?;
				self.put_raw("roomuseroncejoinedids", &userroom, &[])?;
				if let Some(server) = server_name_from_user_id(&row.state_key) {
					summary.joined_servers.insert(server.to_owned());
				}
				summary.joined_count = summary.joined_count.saturating_add(1);
			},
			| "invite" => {
				self.put_raw("userroomid_invitestate", &userroom, b"[]")?;
				let count = self.next_count()?.to_be_bytes();
				self.put_raw("roomuserid_invitecount", &roomuser, &count)?;
				if let Some(sender) =
					event_sender(row.json.as_ref()).filter(|sender| sender.starts_with('@'))
				{
					self.put_raw("userroomid_invitesender", &userroom, sender.as_bytes())?;
				}
				summary.invited_count = summary.invited_count.saturating_add(1);
			},
			| "knock" => {
				self.put_raw("userroomid_knockedstate", &userroom, b"[]")?;
				let count = self.next_count()?.to_be_bytes();
				self.put_raw("roomuserid_knockedcount", &roomuser, &count)?;
				summary.knocked_count = summary.knocked_count.saturating_add(1);
			},
			| "leave" | "ban" => {
				if let Some(json) = row.json {
					self.put_raw("userroomid_leftstate", &userroom, &serde_json::to_vec(&json)?)?;
				} else {
					self.put_raw("userroomid_leftstate", &userroom, b"null")?;
				}
				let count = self.next_count()?.to_be_bytes();
				self.put_raw("roomuserid_leftcount", &roomuser, &count)?;
			},
			| "" => report.skip("room_state.member_without_membership"),
			| _ => report.skip("room_state.unknown_membership"),
		}

		Ok(())
	}

	fn ensure_room_event(
		&mut self,
		event_id: &str,
		room_id: &str,
		stream_ordering: Option<i64>,
		json: Option<Value>,
		report: &mut ImportReport,
	) -> Result<Option<u64>> {
		if let Some(value) = self.get_raw_cf("eventid_shorteventid", event_id.as_bytes())? {
			if let Ok(bytes) = value.as_slice().try_into() {
				return Ok(Some(u64::from_be_bytes(bytes)));
			}
			report.skip("room_state.corrupt_existing_event");
			return Ok(None);
		}

		let Some(json) = json else {
			return Ok(None);
		};

		let shorteventid = self.available_shorteventid(event_id, stream_ordering, report)?;
		self.store_room_event(event_id, room_id, shorteventid, json)?;

		Ok(Some(shorteventid))
	}

	fn store_room_event(
		&mut self,
		event_id: &str,
		room_id: &str,
		shorteventid: u64,
		json: Value,
	) -> Result<()> {
		let shortroomid = self.shortroomid_for(room_id)?;
		self.reserve_count(shorteventid)?;

		let pdu_id = pdu_id(shortroomid, shorteventid);
		let json = event_json(event_id, room_id, json)?;

		self.put_raw("eventid_shorteventid", event_id.as_bytes(), &shorteventid.to_be_bytes())?;
		self.put_raw("shorteventid_eventid", &shorteventid.to_be_bytes(), event_id.as_bytes())?;
		self.put_raw("eventid_pduid", event_id.as_bytes(), &pdu_id)?;
		self.put_raw("pduid_pdu", &pdu_id, &json.bytes)?;

		Ok(())
	}

	fn available_shorteventid(
		&mut self,
		event_id: &str,
		stream_ordering: Option<i64>,
		report: &mut ImportReport,
	) -> Result<u64> {
		if let Some(shorteventid) = positive_stream_ordering(stream_ordering) {
			let key = shorteventid.to_be_bytes();
			match self.get_raw_cf("shorteventid_eventid", &key)? {
				| Some(existing) if existing == event_id.as_bytes() => {
					self.reserve_count(shorteventid)?;
					return Ok(shorteventid);
				},
				| Some(_) => {
					report.warn(format!(
						"Synapse stream_ordering {shorteventid} was already present for a different event; allocated a new shorteventid for {event_id}"
					));
				},
				| None => {
					self.reserve_count(shorteventid)?;
					return Ok(shorteventid);
				},
			}
		}

		loop {
			let shorteventid = self.next_count()?;
			if self
				.get_raw_cf("shorteventid_eventid", &shorteventid.to_be_bytes())?
				.is_none()
			{
				return Ok(shorteventid);
			}
		}
	}

	fn receipt_count(&mut self, receipt: &SynapseReceipt) -> Result<u64> {
		if let Some(stream_id) = positive_stream_ordering(Some(receipt.stream_id)) {
			self.reserve_count(stream_id)?;
			Ok(stream_id)
		} else {
			self.next_count()
		}
	}

	fn pdu_count_for_receipt(&self, receipt: &SynapseReceipt) -> Result<Option<u64>> {
		let Some(pdu_id) = self.get_raw_cf("eventid_pduid", receipt.event_id.as_bytes())? else {
			return Ok(None);
		};
		if pdu_id.len() < 16 {
			return Ok(None);
		}
		Ok(pdu_id[8..16].try_into().ok().map(u64::from_be_bytes))
	}

	fn record_thread_relation(
		&self,
		relation: SynapseEventRelation,
		from: u64,
		threads: &mut BTreeMap<String, ThreadSummary>,
		report: &mut ImportReport,
	) -> Result<()> {
		let Some(root_pduid) = self.event_pduid(&relation.relates_to_id)? else {
			report.skip("event_relations.missing_thread_root");
			return Ok(());
		};
		let Some(root_json) = self.pdu_json(&root_pduid)? else {
			report.skip("event_relations.missing_thread_root_json");
			return Ok(());
		};
		let Some(event_pduid) = self.event_pduid(&relation.event_id)? else {
			report.skip("event_relations.missing_thread_event");
			return Ok(());
		};
		let Some(event_json) = self.pdu_json(&event_pduid)? else {
			report.skip("event_relations.missing_thread_event_json");
			return Ok(());
		};

		let entry =
			threads
				.entry(relation.relates_to_id.clone())
				.or_insert_with(|| ThreadSummary {
					root_pduid,
					reply_count: 0,
					latest_count: 0,
					latest_content: Value::Null,
					participants: BTreeSet::new(),
				});

		if let Some(sender) = event_sender(Some(&root_json)).filter(|sender| sender.starts_with('@')) {
			entry.participants.insert(sender.to_owned());
		}
		if let Some(sender) = event_sender(Some(&event_json)).filter(|sender| sender.starts_with('@')) {
			entry.participants.insert(sender.to_owned());
		}
		entry.reply_count = entry.reply_count.saturating_add(1);
		if from >= entry.latest_count {
			entry.latest_count = from;
			entry.latest_content = event_json.get("content").cloned().unwrap_or(Value::Null);
		}

		Ok(())
	}

	fn store_thread_summary(
		&self,
		thread: ThreadSummary,
		report: &mut ImportReport,
	) -> Result<()> {
		let users = thread
			.participants
			.iter()
			.map(String::as_bytes)
			.collect::<Vec<_>>()
			.join(&[0xFF][..]);

		self.put_raw("threadid_userids", &thread.root_pduid, &users)?;
		self.update_thread_unsigned(&thread)?;
		report.thread_summaries = report.thread_summaries.saturating_add(1);

		Ok(())
	}

	fn update_thread_unsigned(&self, thread: &ThreadSummary) -> Result<()> {
		let Some(mut root_json) = self.pdu_json(&thread.root_pduid)? else {
			return Ok(());
		};
		let Some(root_object) = root_json.as_object_mut() else {
			return Ok(());
		};
		let unsigned = object_field(root_object, "unsigned");
		let relations = object_field(unsigned, "m.relations");
		relations.insert(
			"m.thread".to_owned(),
			json!({
				"latest_event": thread.latest_content.clone(),
				"count": thread.reply_count,
				"current_user_participated": true,
			}),
		);

		self.put_raw("pduid_pdu", &thread.root_pduid, &serde_json::to_vec(&root_json)?)
	}

	fn redact_pdu_json(
		&self,
		target_json: &mut Value,
		redaction_json: Value,
		report: &mut ImportReport,
	) -> Result<()> {
		let event_type = target_json
			.get("type")
			.and_then(Value::as_str)
			.unwrap_or_default()
			.to_owned();
		let room_version = self.room_version_for_pdu(target_json, report);
		let rules = room_version
			.rules()
			.or_else(|| RoomVersionId::V11.rules())
			.expect("known fallback room version has rules");
		let Some(object) = target_json.as_object_mut() else {
			return Ok(());
		};
		let mut content = match object
			.remove("content")
			.map(CanonicalJsonValue::try_from)
			.transpose()
		{
			| Ok(Some(CanonicalJsonValue::Object(content))) => content,
			| Ok(Some(_)) | Ok(None) => BTreeMap::new(),
			| Err(_) => {
				report.skip("redactions.noncanonical_content");
				BTreeMap::new()
			},
		};

		redact_content_in_place(&mut content, &rules.redaction, event_type);
		object.insert(
			"content".to_owned(),
			Value::from(CanonicalJsonValue::Object(content)),
		);

		let unsigned = object_field(object, "unsigned");
		unsigned.insert("redacted_because".to_owned(), redaction_json);

		Ok(())
	}

	fn room_version_for_pdu(
		&self,
		target_json: &Value,
		report: &mut ImportReport,
	) -> RoomVersionId {
		let Some(room_id) = target_json.get("room_id").and_then(Value::as_str) else {
			report.skip("redactions.missing_room_id");
			return RoomVersionId::V11;
		};

		self.room_version_for_room(room_id, report).unwrap_or(RoomVersionId::V11)
	}

	fn room_version_for_room(
		&self,
		room_id: &str,
		report: &mut ImportReport,
	) -> Option<RoomVersionId> {
		let rows = self.scan_cf("pduid_pdu").ok()?;
		for (_, pdu) in rows {
			let Ok(json) = serde_json::from_slice::<Value>(&pdu) else {
				continue;
			};
			if json.get("type").and_then(Value::as_str) != Some("m.room.create") {
				continue;
			}
			if json.get("room_id").and_then(Value::as_str) != Some(room_id) {
				continue;
			}

			let version = json
				.get("content")
				.and_then(|content| content.get("room_version"))
				.and_then(Value::as_str)
				.unwrap_or("1");
			return RoomVersionId::from_str(version)
				.map_err(|_| report.skip("redactions.invalid_room_version"))
				.ok();
		}

		None
	}

	fn deindex_search_body(&self, pduid: &[u8], body: &str) -> Result<()> {
		if pduid.len() < size_of::<u64>() * 2 {
			return Ok(());
		}
		let shortroomid = &pduid[..size_of::<u64>()];
		for word in tokenize_search_body(body) {
			let mut key = Vec::with_capacity(size_of::<u64>() + word.len() + 1 + pduid.len());
			key.extend_from_slice(shortroomid);
			key.extend_from_slice(word.as_bytes());
			key.push(0xFF);
			key.extend_from_slice(pduid);
			self.remove_raw("tokenids", &key)?;
		}

		Ok(())
	}

	fn existing_shorteventid(&self, event_id: &str) -> Result<Option<u64>> {
		let Some(value) = self.get_raw_cf("eventid_shorteventid", event_id.as_bytes())? else {
			return Ok(None);
		};

		Ok(value.as_slice().try_into().ok().map(u64::from_be_bytes))
	}

	fn event_pduid(&self, event_id: &str) -> Result<Option<Vec<u8>>> {
		self.get_raw_cf("eventid_pduid", event_id.as_bytes())
	}

	fn pdu_json(&self, pduid: &[u8]) -> Result<Option<Value>> {
		self.get_raw_cf("pduid_pdu", pduid)?
			.map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
			.transpose()
	}

	fn account_data_content(
		&self,
		room_id: Option<&str>,
		user_id: &str,
		event_type: &str,
	) -> Result<Option<Value>> {
		let index_key = serialize_account_data_index(room_id, user_id, event_type)?;
		let Some(data_key) = self.get_raw_cf("roomusertype_roomuserdataid", &index_key)? else {
			return Ok(None);
		};
		let Some(value) = self.get_raw_cf("roomuserdataid_accountdata", &data_key)? else {
			return Ok(None);
		};
		let value: Value = serde_json::from_slice(&value)?;

		Ok(value.get("content").cloned())
	}

	fn put_account_data_event(
		&mut self,
		room_id: Option<&str>,
		user_id: &str,
		event_type: &str,
		content: Value,
	) -> Result<()> {
		let count = self.next_count()?;
		let data_key = serialize_account_data_key(room_id, user_id, count, event_type)?;
		let index_key = serialize_account_data_index(room_id, user_id, event_type)?;
		let value = serde_json::to_vec(&json!({
			"type": event_type,
			"content": content,
		}))?;

		if let Some(previous_key) = self.get_raw_cf("roomusertype_roomuserdataid", &index_key)? {
			self.remove_raw("roomuserdataid_accountdata", &previous_key)?;
		}

		self.put_raw("roomuserdataid_accountdata", &data_key, &value)?;
		self.put_raw("roomusertype_roomuserdataid", &index_key, &data_key)
	}

	fn scan_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
		let handle = self
			.db
			.cf_handle(cf)
			.ok_or_else(|| Error::Message(format!("missing column family {cf}")))?;
		let mut values = Vec::new();
		for item in self.db.iterator_cf(&handle, rocksdb::IteratorMode::Start) {
			let (key, value) = item.map_err(|e| Error::rocksdb(&self.path, e))?;
			values.push((key.to_vec(), value.to_vec()));
		}

		Ok(values)
	}

	#[cfg(test)]
	pub fn get_raw(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
		self.get_raw_cf(cf, key)
	}

	#[cfg(test)]
	pub fn prefix_raw(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
		let handle = self
			.db
			.cf_handle(cf)
			.ok_or_else(|| Error::Message(format!("missing column family {cf}")))?;
		let mut values = Vec::new();
		for item in self.db.prefix_iterator_cf(&handle, prefix) {
			let (key, value) = item.map_err(|e| Error::rocksdb(&self.path, e))?;
			if !key.starts_with(prefix) {
				break;
			}
			values.push((key.to_vec(), value.to_vec()));
		}

		Ok(values)
	}

	fn get_raw_cf(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
		let handle = self
			.db
			.cf_handle(cf)
			.ok_or_else(|| Error::Message(format!("missing column family {cf}")))?;
		self.db
			.get_cf(&handle, key)
			.map_err(|e| Error::rocksdb(&self.path, e))
	}

	fn put_raw(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
		let handle = self
			.db
			.cf_handle(cf)
			.ok_or_else(|| Error::Message(format!("missing column family {cf}")))?;
		self.db
			.put_cf(&handle, key, value)
			.map_err(|e| Error::rocksdb(&self.path, e))
	}

	fn remove_raw(&self, cf: &str, key: &[u8]) -> Result<()> {
		let handle = self
			.db
			.cf_handle(cf)
			.ok_or_else(|| Error::Message(format!("missing column family {cf}")))?;
		self.db
			.delete_cf(&handle, key)
			.map_err(|e| Error::rocksdb(&self.path, e))
	}

	fn next_count(&mut self) -> Result<u64> {
		self.counter = self.counter.saturating_add(1);
		self.put_raw("global", b"c", &self.counter.to_be_bytes())?;
		Ok(self.counter)
	}

	fn reserve_count(&mut self, count: u64) -> Result<()> {
		if count > self.counter {
			self.counter = count;
			self.put_raw("global", b"c", &self.counter.to_be_bytes())?;
		}

		Ok(())
	}

	fn shortroomid_for(&mut self, room_id: &str) -> Result<u64> {
		if let Some(value) = self.get_raw_cf("roomid_shortroomid", room_id.as_bytes())? {
			if let Ok(bytes) = value.as_slice().try_into() {
				return Ok(u64::from_be_bytes(bytes));
			}
		}

		let shortroomid = self.next_count()?;
		self.put_raw("roomid_shortroomid", room_id.as_bytes(), &shortroomid.to_be_bytes())?;

		Ok(shortroomid)
	}

	fn shortstatekey_for(&mut self, event_type: &str, state_key: &str) -> Result<u64> {
		let key = serialize_to_vec((event_type, state_key))?;
		if let Some(value) = self.get_raw_cf("statekey_shortstatekey", &key)? {
			if let Ok(bytes) = value.as_slice().try_into() {
				return Ok(u64::from_be_bytes(bytes));
			}
		}

		let shortstatekey = self.next_count()?;
		self.put_raw("statekey_shortstatekey", &key, &shortstatekey.to_be_bytes())?;
		self.put_raw("shortstatekey_statekey", &shortstatekey.to_be_bytes(), &key)?;

		Ok(shortstatekey)
	}

	fn media_file_path(&self, key: &[u8]) -> PathBuf {
		let digest = Sha256::digest(key);
		self.path
			.join("media")
			.join(BASE64_URL_SAFE_NO_PAD.encode(digest))
	}

	fn mark_key_updates(&mut self, user_ids: BTreeSet<String>) -> Result<()> {
		for user_id in user_ids {
			let count = self.next_count()?;
			let key = serialize_to_vec((&user_id, count))?;
			self.put_raw("keychangeid_userid", &key, user_id.as_bytes())?;
		}

		Ok(())
	}
}

impl ImportReport {
	pub fn skip(&mut self, key: &str) {
		let entry = self.skipped.entry(key.to_owned()).or_default();
		*entry = entry.saturating_add(1);
	}

	pub fn warn(&mut self, warning: String) {
		self.warnings.push(warning);
	}

	pub fn to_text(&self) -> String {
		format!(
			"Imported users={} locked_users={} erased_users={} registration_tokens={} profiles={} threepids={} devices={} dehydrated_devices={} device_keys={} one_time_keys={} fallback_keys={} cross_signing_keys={} key_signatures={} room_key_backup_versions={} room_key_backups={} to_device_messages={} access_tokens={} open_id_tokens={} login_tokens={} account_data={} push_rules={} ignored_users={} room_tags={} filters={} presence={} media={} url_previews={} room_events={} event_edges={} redactions={} search_indexed_events={} event_relations={} thread_summaries={} room_state={} forward_extremities={} forgotten_rooms={} blocked_rooms={} room_aliases={} public_rooms={} receipts={} notification_counts={} pushers={} appservices={} signing_keys={} server_keys={} skipped={}",
			self.users,
			self.locked_users,
			self.erased_users,
			self.registration_tokens,
			self.profiles,
			self.threepids,
			self.devices,
			self.dehydrated_devices,
			self.device_keys,
			self.one_time_keys,
			self.fallback_keys,
			self.cross_signing_keys,
			self.key_signatures,
			self.room_key_backup_versions,
			self.room_key_backups,
			self.to_device_messages,
			self.access_tokens,
			self.open_id_tokens,
			self.login_tokens,
			self.account_data,
			self.push_rules,
			self.ignored_users,
			self.room_tags,
			self.filters,
			self.presence,
			self.media,
			self.url_previews,
			self.room_events,
			self.event_edges,
			self.redactions,
			self.search_indexed_events,
			self.event_relations,
			self.thread_summaries,
			self.room_state,
			self.forward_extremities,
			self.forgotten_rooms,
			self.blocked_rooms,
			self.room_aliases,
			self.public_rooms,
			self.receipts,
			self.notification_counts,
			self.pushers,
			self.appservices,
			self.signing_keys,
			self.server_keys,
			self.skipped.values().sum::<u64>(),
		)
	}
}

fn empty_push_rules_global() -> Map<String, Value> {
	let mut global = Map::new();
	for kind in ["override", "content", "room", "sender", "underride", "postcontent"] {
		global.insert(kind.to_owned(), Value::Array(Vec::new()));
	}
	global
}

fn push_rule_kind(priority_class: i64) -> Option<&'static str> {
	match priority_class {
		| 1 => Some("underride"),
		| 2 => Some("sender"),
		| 3 => Some("room"),
		| 4 => Some("content"),
		| 5 => Some("override"),
		| 6 => Some("postcontent"),
		| _ => None,
	}
}

fn push_rule_template(
	user_id: &str,
	rule: &SynapsePushRule,
	kind: &str,
	report: &mut ImportReport,
) -> Option<Value> {
	let Some(conditions) = rule.conditions.as_array() else {
		report.skip("push_rules.invalid_conditions");
		return None;
	};
	let Some(actions) = rule.actions.as_array() else {
		report.skip("push_rules.invalid_actions");
		return None;
	};

	let mut template = Map::new();
	let mut display_rule_id = push_rule_unscoped_id(&rule.rule_id);

	match kind {
		| "override" | "underride" | "postcontent" => {
			let conditions = conditions
				.iter()
				.cloned()
				.map(|mut condition| {
					convert_typed_push_rule_values(&mut condition, user_id);
					condition
				})
				.collect::<Vec<_>>();
			template.insert("conditions".to_owned(), Value::Array(conditions));
		},
		| "sender" | "room" => {
			let Some(pattern) = conditions
				.first()
				.and_then(|condition| condition.get("pattern"))
				.and_then(Value::as_str)
			else {
				report.skip("push_rules.invalid_conditions");
				return None;
			};
			display_rule_id = pattern.to_owned();
		},
		| "content" => {
			if conditions.len() != 1 {
				report.skip("push_rules.invalid_conditions");
				return None;
			}
			let condition = &conditions[0];
			if let Some(pattern) = condition.get("pattern").and_then(Value::as_str) {
				template.insert("pattern".to_owned(), Value::String(pattern.to_owned()));
			} else if let Some(pattern_type) = condition.get("pattern_type").and_then(Value::as_str) {
				template.insert("pattern_type".to_owned(), Value::String(pattern_type.to_owned()));
			} else {
				report.skip("push_rules.invalid_conditions");
				return None;
			}
		},
		| _ => return None,
	}

	template.insert("actions".to_owned(), Value::Array(actions.clone()));
	template.insert("rule_id".to_owned(), Value::String(display_rule_id));
	template.insert("default".to_owned(), Value::Bool(false));
	template.insert("enabled".to_owned(), Value::Bool(rule.enabled.unwrap_or(true)));

	let mut value = Value::Object(template);
	convert_typed_push_rule_values(&mut value, user_id);
	Some(value)
}

fn push_rule_unscoped_id(rule_id: &str) -> String {
	rule_id
		.rsplit('/')
		.next()
		.filter(|id| !id.is_empty())
		.unwrap_or(rule_id)
		.to_owned()
}

fn convert_typed_push_rule_values(value: &mut Value, user_id: &str) {
	let Some(object) = value.as_object_mut() else {
		return;
	};
	for field in ["pattern", "value"] {
		let typed_field = format!("{field}_type");
		let Some(Value::String(kind)) = object.remove(&typed_field) else {
			continue;
		};
		let replacement = match kind.as_str() {
			| "user_id" => Some(user_id.to_owned()),
			| "user_localpart" => user_localpart(user_id).map(ToOwned::to_owned),
			| _ => None,
		};
		if let Some(replacement) = replacement {
			object.insert(field.to_owned(), Value::String(replacement));
		}
	}
}

fn user_localpart(user_id: &str) -> Option<&str> {
	user_id
		.strip_prefix('@')
		.and_then(|rest| rest.split_once(':'))
		.map(|(localpart, _)| localpart)
}

#[derive(Debug, Deserialize)]
struct SynapseAppserviceRegistration {
	id: Option<String>,
}

#[derive(Debug)]
struct SynapseSigningKey {
	version: String,
	der: Vec<u8>,
}

const ED25519_PKCS8_V1_PREFIX: &[u8] = &[
	0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04,
	0x20,
];

fn migration_user_id(server_name: Option<&str>) -> String {
	format!("@synapse-migration:{}", server_name.unwrap_or("unknown.invalid"))
}

fn synapse_signing_keys(body: &[u8], report: &mut ImportReport) -> Vec<SynapseSigningKey> {
	let text = String::from_utf8_lossy(body);
	let mut keys = Vec::new();

	for line in text.lines().map(str::trim) {
		if line.is_empty() || line.starts_with('#') {
			continue;
		}

		let parts = line.split_whitespace().collect::<Vec<_>>();
		if parts.len() != 3 {
			report.skip("signing_key.invalid_line");
			continue;
		}
		if parts[0] != "ed25519" {
			report.skip("signing_key.unsupported_algorithm");
			continue;
		}

		let Ok(seed) = decode_synapse_signing_seed(parts[2]) else {
			report.skip("signing_key.invalid_base64");
			continue;
		};
		if seed.len() != 32 {
			report.skip("signing_key.invalid_seed_length");
			continue;
		}

		let mut der = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + seed.len());
		der.extend_from_slice(ED25519_PKCS8_V1_PREFIX);
		der.extend_from_slice(&seed);
		keys.push(SynapseSigningKey {
			version: parts[1].to_owned(),
			der,
		});
	}

	keys
}

fn decode_synapse_signing_seed(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
	BASE64_STANDARD_NO_PAD
		.decode(input)
		.or_else(|_| BASE64_STANDARD.decode(input))
}

fn signatures_by_target(
	signatures: Vec<SynapseKeySignature>,
) -> BTreeMap<(String, String), Vec<SynapseKeySignature>> {
	let mut by_target = BTreeMap::<(String, String), Vec<SynapseKeySignature>>::new();
	for signature in signatures {
		by_target
			.entry((
				signature.target_user_id.clone(),
				signature.target_device_id.clone(),
			))
			.or_default()
			.push(signature);
	}

	by_target
}

fn apply_key_signatures(
	key_json: &mut Value,
	signatures: Option<&Vec<SynapseKeySignature>>,
) -> u64 {
	let Some(signatures) = signatures else {
		return 0;
	};
	let Some(object) = key_json.as_object_mut() else {
		return 0;
	};
	let signatures_value = object
		.entry("signatures")
		.or_insert_with(|| Value::Object(Map::new()));
	let Some(signatures_object) = signatures_value.as_object_mut() else {
		return 0;
	};

	let mut applied = 0_u64;
	for signature in signatures {
		let signer_value = signatures_object
			.entry(signature.user_id.clone())
			.or_insert_with(|| Value::Object(Map::new()));
		if let Some(signer_object) = signer_value.as_object_mut() {
			signer_object.insert(
				signature.key_id.clone(),
				Value::String(signature.signature.clone()),
			);
			applied = applied.saturating_add(1);
		}
	}

	applied
}

fn cross_signing_index_cf(key_type: &str) -> Option<&'static str> {
	match key_type {
		| "master" => Some("userid_masterkeyid"),
		| "self_signing" => Some("userid_selfsigningkeyid"),
		| "user_signing" => Some("userid_usersigningkeyid"),
		| _ => None,
	}
}

fn cross_signing_public_key(key_data: &Value) -> Option<String> {
	let mut values = key_data.get("keys")?.as_object()?.values();
	let public_key = values.next()?.as_str()?.to_owned();
	if values.next().is_some() {
		return None;
	}

	Some(public_key)
}

fn serialize_account_data_key(
	room_id: Option<&str>,
	user_id: &str,
	count: u64,
	event_type: &str,
) -> Result<Vec<u8>> {
	match room_id {
		| Some(room_id) => Ok(serialize_to_vec((room_id, user_id, count, event_type))?),
		| None => Ok(serialize_to_vec((Option::<&str>::None, user_id, count, event_type))?),
	}
}

fn serialize_account_data_index(
	room_id: Option<&str>,
	user_id: &str,
	event_type: &str,
) -> Result<Vec<u8>> {
	match room_id {
		| Some(room_id) => Ok(serialize_to_vec((room_id, user_id, event_type))?),
		| None => Ok(serialize_to_vec((Option::<&str>::None, user_id, event_type))?),
	}
}

fn media_metadata_key(mxc: &str, content_type: Option<&str>) -> Result<Vec<u8>> {
	const SEP: u8 = 0xFF;

	let mut key = Vec::new();
	key.extend_from_slice(mxc.as_bytes());
	key.push(SEP);
	key.push(SEP);
	key.extend_from_slice(&0_u32.to_be_bytes());
	key.push(SEP);
	key.extend_from_slice(&0_u32.to_be_bytes());
	key.push(SEP);
	key.push(SEP);
	key.push(0x00);
	key.push(SEP);
	key.push(SEP);
	if let Some(content_type) = content_type {
		key.extend_from_slice(content_type.as_bytes());
	}

	Ok(key)
}

fn encode_url_preview(og: &Value, download_ts: Option<i64>) -> Option<Vec<u8>> {
	let object = og.as_object()?;
	let title = string_field(object, &["og:title"]);
	let description = string_field(object, &["og:description"]);
	let image = string_field(object, &["og:image"]);
	let image_size = usize_field(object, &["matrix:image:size"]);
	let image_width = u32_field(object, &["og:image:width"]);
	let image_height = u32_field(object, &["og:image:height"]);
	let video = string_field(object, &["og:video", "og:video:url"]);
	let video_size = usize_field(object, &["matrix:video:size"]);
	let video_width = u32_field(object, &["og:video:width"]);
	let video_height = u32_field(object, &["og:video:height"]);
	let audio = string_field(object, &["og:audio", "og:audio:url"]);
	let audio_size = usize_field(object, &["matrix:audio:size"]);
	let og_type = string_field(object, &["og:type"]);
	let site_name = string_field(object, &["og:site_name"]);
	let image_type = string_field(object, &["og:image:type"]);
	let video_type = string_field(object, &["og:video:type"]);
	let audio_type = string_field(object, &["og:audio:type"]);
	let additional = object
		.iter()
		.filter(|(key, _)| !modeled_url_preview_property(key))
		.filter_map(|(key, value)| string_value(value).map(|value| (key.clone(), value)))
		.collect::<BTreeMap<_, _>>();

	if title.is_none()
		&& description.is_none()
		&& image.is_none()
		&& image_size.is_none()
		&& image_width.is_none()
		&& image_height.is_none()
		&& video.is_none()
		&& video_size.is_none()
		&& video_width.is_none()
		&& video_height.is_none()
		&& audio.is_none()
		&& audio_size.is_none()
		&& og_type.is_none()
		&& site_name.is_none()
		&& image_type.is_none()
		&& video_type.is_none()
		&& audio_type.is_none()
		&& additional.is_empty()
	{
		return None;
	}

	let timestamp = download_ts
		.and_then(|ts| u64::try_from(ts).ok())
		.map(|ts| ts / 1000)
		.unwrap_or_default();
	let mut value = Vec::<u8>::new();
	value.extend_from_slice(&timestamp.to_be_bytes());
	value.push(0xFF);
	append_string(&mut value, title.as_deref());
	append_string(&mut value, description.as_deref());
	append_string(&mut value, image.as_deref());
	append_usize(&mut value, image_size);
	append_u32(&mut value, image_width);
	append_u32(&mut value, image_height);
	append_string(&mut value, video.as_deref());
	append_usize(&mut value, video_size);
	append_u32(&mut value, video_width);
	append_u32(&mut value, video_height);
	append_string(&mut value, audio.as_deref());
	append_usize(&mut value, audio_size);
	append_string(&mut value, og_type.as_deref());
	append_string(&mut value, site_name.as_deref());
	append_string(&mut value, image_type.as_deref());
	append_string(&mut value, video_type.as_deref());
	append_string(&mut value, audio_type.as_deref());
	if !additional.is_empty() {
		serde_json::to_writer(&mut value, &additional).ok()?;
	}

	Some(value)
}

fn append_string(value: &mut Vec<u8>, field: Option<&str>) {
	value.extend_from_slice(field.unwrap_or_default().as_bytes());
	value.push(0xFF);
}

fn append_usize(value: &mut Vec<u8>, field: Option<usize>) {
	value.extend_from_slice(&field.unwrap_or_default().to_be_bytes());
	value.push(0xFF);
}

fn append_u32(value: &mut Vec<u8>, field: Option<u32>) {
	value.extend_from_slice(&field.unwrap_or_default().to_be_bytes());
	value.push(0xFF);
}

fn string_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
	keys.iter()
		.find_map(|key| object.get(*key).and_then(string_value))
}

fn string_value(value: &Value) -> Option<String> {
	value
		.as_str()
		.filter(|value| !value.is_empty())
		.map(ToOwned::to_owned)
}

fn usize_field(object: &Map<String, Value>, keys: &[&str]) -> Option<usize> {
	keys.iter()
		.find_map(|key| object.get(*key).and_then(usize_value))
}

fn usize_value(value: &Value) -> Option<usize> {
	value
		.as_u64()
		.and_then(|value| usize::try_from(value).ok())
		.or_else(|| value.as_str()?.parse().ok())
}

fn u32_field(object: &Map<String, Value>, keys: &[&str]) -> Option<u32> {
	keys.iter()
		.find_map(|key| object.get(*key).and_then(u32_value))
}

fn u32_value(value: &Value) -> Option<u32> {
	value
		.as_u64()
		.and_then(|value| u32::try_from(value).ok())
		.or_else(|| value.as_str()?.parse().ok())
}

fn modeled_url_preview_property(key: &str) -> bool {
	matches!(
		key,
		"og:title"
			| "og:description"
			| "og:type"
			| "og:site_name"
			| "og:image"
			| "og:image:type"
			| "matrix:image:size"
			| "og:image:width"
			| "og:image:height"
			| "og:video"
			| "og:video:url"
			| "og:video:type"
			| "matrix:video:size"
			| "og:video:width"
			| "og:video:height"
			| "og:audio"
			| "og:audio:url"
			| "og:audio:type"
			| "matrix:audio:size"
	)
}

fn registration_token_expires(
	token: &SynapseRegistrationToken,
	report: &mut ImportReport,
) -> Option<Value> {
	let uses_allowed = match token.uses_allowed {
		| Some(value) if value < 0 => {
			report.skip("registration_tokens.invalid_uses_allowed");
			return None;
		},
		| Some(value) => Some(u64::try_from(value).ok()?),
		| None => None,
	};
	let expiry_time = match token.expiry_time {
		| Some(value) if value < 0 => {
			report.skip("registration_tokens.invalid_expiry_time");
			return None;
		},
		| Some(value) => Some(value),
		| None => None,
	};
	let completed = u64::try_from(token.completed).ok()?;

	match (uses_allowed, expiry_time) {
		| (Some(max_uses), Some(_)) if completed >= max_uses => {
			Some(json!({ "AfterUses": max_uses }))
		},
		| (Some(_), Some(expiry_ms)) if expiry_ms <= now_millis() => {
			Some(registration_token_time_expiry(expiry_ms))
		},
		| (Some(_), Some(_)) => {
			report.skip("registration_tokens.combined_active_limits");
			report.warn(
				"Skipped active Synapse registration token with both use and time limits because continuwuity can represent only one database-token expiry mode"
					.to_owned(),
			);
			None
		},
		| (Some(max_uses), None) => Some(json!({ "AfterUses": max_uses })),
		| (None, Some(expiry_ms)) => Some(registration_token_time_expiry(expiry_ms)),
		| (None, None) => Some(Value::Null),
	}
}

fn registration_token_time_expiry(expiry_ms: i64) -> Value {
	let secs = u64::try_from(expiry_ms / 1000).unwrap_or_default();
	let nanos = u32::try_from((expiry_ms % 1000) * 1_000_000).unwrap_or_default();
	json!({
		"AfterTime": {
			"secs_since_epoch": secs,
			"nanos_since_epoch": nanos,
		}
	})
}

fn now_millis() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
		.unwrap_or_default()
}

struct StoredEventJson {
	bytes: Vec<u8>,
}

fn event_json(event_id: &str, room_id: &str, json: Value) -> Result<StoredEventJson> {
	let mut json = json;
	let Some(object) = json.as_object_mut() else {
		return Err(Error::Message(format!("event_json for {event_id} is not a JSON object")));
	};

	object
		.entry("event_id")
		.or_insert_with(|| Value::String(event_id.to_owned()));
	object
		.entry("room_id")
		.or_insert_with(|| Value::String(room_id.to_owned()));

	Ok(StoredEventJson { bytes: serde_json::to_vec(object)? })
}

#[derive(Clone, Copy)]
struct StateEntry {
	shortstatekey: u64,
	shorteventid: u64,
}

#[derive(Default)]
struct MembershipSummary {
	joined_count: u64,
	invited_count: u64,
	knocked_count: u64,
	joined_servers: BTreeSet<String>,
}

struct ThreadSummary {
	root_pduid: Vec<u8>,
	reply_count: u64,
	latest_count: u64,
	latest_content: Value,
	participants: BTreeSet<String>,
}

fn positive_stream_ordering(stream_ordering: Option<i64>) -> Option<u64> {
	stream_ordering
		.and_then(|stream_ordering| u64::try_from(stream_ordering).ok())
		.filter(|stream_ordering| *stream_ordering != 0)
}

fn valid_presence_state(state: &str) -> bool {
	matches!(state, "online" | "offline" | "unavailable" | "org.matrix.msc3026.busy")
}

fn presenceid_key(count: u64, user_id: &str) -> Vec<u8> {
	let mut key = Vec::with_capacity(size_of::<u64>().saturating_add(user_id.len()));
	key.extend_from_slice(&count.to_be_bytes());
	key.extend_from_slice(user_id.as_bytes());
	key
}

fn relation_key(to: u64, from: u64) -> Vec<u8> {
	let mut key = Vec::with_capacity(size_of::<u64>() * 2);
	key.extend_from_slice(&to.to_be_bytes());
	key.extend_from_slice(&from.to_be_bytes());
	key
}

fn searchable_body(pdu: &[u8]) -> Result<Option<String>> {
	let json = serde_json::from_slice::<Value>(pdu)?;
	Ok(searchable_body_from_value(&json))
}

fn searchable_body_from_value(json: &Value) -> Option<String> {
	json
		.get("type")
		.and_then(Value::as_str)
		.filter(|event_type| *event_type == "m.room.message")
		.and_then(|_| json.get("content"))
		.and_then(|content| content.get("body"))
		.and_then(Value::as_str)
		.map(str::to_owned)
}

fn tokenize_search_body(body: &str) -> impl Iterator<Item = String> + Send + '_ {
	const WORD_MAX_LEN: usize = 50;

	body.split_terminator(|c: char| !c.is_alphanumeric())
		.filter(|s| !s.is_empty())
		.filter(|word| word.len() <= WORD_MAX_LEN)
		.map(str::to_lowercase)
}

fn object_field<'a>(object: &'a mut Map<String, Value>, field: &str) -> &'a mut Map<String, Value> {
	let value = object
		.entry(field.to_owned())
		.or_insert_with(|| Value::Object(Map::new()));
	if !value.is_object() {
		*value = Value::Object(Map::new());
	}
	value.as_object_mut().expect("object field was just initialized")
}

fn compressed_state_event(shortstatekey: u64, shorteventid: u64) -> [u8; 16] {
	let mut compressed = [0_u8; 16];
	compressed[..8].copy_from_slice(&shortstatekey.to_be_bytes());
	compressed[8..].copy_from_slice(&shorteventid.to_be_bytes());
	compressed
}

fn state_diff_value(compressed: &BTreeSet<[u8; 16]>) -> Vec<u8> {
	let mut value = Vec::with_capacity(8 + compressed.len().saturating_mul(16));
	value.extend_from_slice(&0_u64.to_be_bytes());
	for event in compressed {
		value.extend_from_slice(event);
	}
	value
}

fn event_sender(json: Option<&Value>) -> Option<&str> {
	json.and_then(|json| json.get("sender"))
		.and_then(Value::as_str)
}

fn server_name_from_user_id(user_id: &str) -> Option<&str> {
	user_id.rsplit_once(':').map(|(_, server)| server)
}

fn user_id_localpart(user_id: &str) -> Option<&str> {
	if !user_id.starts_with('@') {
		return None;
	}
	let (localpart, server_name) = user_id[1..].rsplit_once(':')?;
	if localpart.is_empty() || server_name.is_empty() {
		return None;
	}

	Some(localpart)
}

fn room_alias_localpart(room_alias: &str) -> Option<&str> {
	if !room_alias.starts_with('#') {
		return None;
	}
	let (localpart, server_name) = room_alias[1..].rsplit_once(':')?;
	if localpart.is_empty() || server_name.is_empty() {
		return None;
	}

	Some(localpart)
}

fn valid_email_address(email: &str) -> bool {
	let Some((local, domain)) = email.split_once('@') else {
		return false;
	};

	!local.is_empty() && !domain.is_empty() && !email.chars().any(char::is_whitespace)
}

fn valid_to_device_message(message: &Value) -> bool {
	let Some(object) = message.as_object() else {
		return false;
	};
	object
		.get("type")
		.and_then(Value::as_str)
		.is_some_and(|event_type| !event_type.is_empty())
		&& object
			.get("sender")
			.and_then(Value::as_str)
			.is_some_and(|sender| sender.starts_with('@'))
		&& object.get("content").is_some_and(Value::is_object)
}

fn keep_preferred_receipt(
	receipts: &mut BTreeMap<(String, String), SynapseReceipt>,
	receipt: SynapseReceipt,
) {
	let key = (receipt.room_id.clone(), receipt.user_id.clone());
	let replace = match receipts.get(&key) {
		| Some(existing) if existing.thread_id.is_none() && receipt.thread_id.is_some() => false,
		| Some(existing) if existing.thread_id.is_some() && receipt.thread_id.is_none() => true,
		| Some(existing) => receipt.stream_id >= existing.stream_id,
		| None => true,
	};
	if replace {
		receipts.insert(key, receipt);
	}
}

fn public_receipt_event(receipt: &SynapseReceipt) -> Value {
	let mut data = match receipt.data.clone() {
		| Value::Object(data) => Value::Object(data),
		| _ => json!({}),
	};
	if let (Some(thread_id), Some(data)) = (&receipt.thread_id, data.as_object_mut()) {
		data.insert("thread_id".to_owned(), Value::String(thread_id.clone()));
	}

	let mut users = Map::new();
	users.insert(receipt.user_id.clone(), data);

	let mut receipt_types = Map::new();
	receipt_types.insert("m.read".to_owned(), Value::Object(users));

	let mut content = Map::new();
	content.insert(receipt.event_id.clone(), Value::Object(receipt_types));

	json!({
		"type": "m.receipt",
		"room_id": receipt.room_id.clone(),
		"content": content,
	})
}

fn pusher_json(pusher: &SynapsePusher) -> Value {
	let data = match pusher.data.clone() {
		| Value::Object(data) => Value::Object(data),
		| _ => json!({}),
	};

	json!({
		"app_display_name": pusher.app_display_name.clone(),
		"app_id": pusher.app_id.clone(),
		"data": data,
		"device_display_name": pusher.device_display_name.clone(),
		"kind": pusher.kind.clone(),
		"lang": pusher.lang.as_deref().unwrap_or("en"),
		"profile_tag": pusher.profile_tag.clone(),
		"pushkey": pusher.pushkey.clone(),
	})
}

fn base_server_key_json(server_name: &str) -> Value {
	json!({
		"server_name": server_name,
		"valid_until_ts": 0,
		"verify_keys": {},
		"old_verify_keys": {},
		"signatures": {},
	})
}

fn normalize_server_key_json(key: &SynapseServerKey) -> Option<Value> {
	let mut json = key.key_json.clone();
	let object = json.as_object_mut()?;
	object
		.entry("server_name")
		.or_insert_with(|| Value::String(key.server_name.clone()));
	object
		.entry("valid_until_ts")
		.or_insert_with(|| Value::from(key.ts_valid_until_ms));
	object
		.entry("verify_keys")
		.or_insert_with(|| Value::Object(Map::new()));
	object
		.entry("old_verify_keys")
		.or_insert_with(|| Value::Object(Map::new()));
	Some(json)
}

fn merge_server_key_json(destination: &mut Value, source: Value) {
	let Some(destination) = destination.as_object_mut() else {
		return;
	};
	let Some(source) = source.as_object() else {
		return;
	};

	if let Some(valid_until_ts) = source.get("valid_until_ts").and_then(Value::as_i64) {
		let existing = destination
			.get("valid_until_ts")
			.and_then(Value::as_i64)
			.unwrap_or_default();
		if valid_until_ts > existing {
			destination.insert("valid_until_ts".to_owned(), Value::from(valid_until_ts));
		}
	}

	merge_json_object_field(destination, source, "verify_keys");
	merge_json_object_field(destination, source, "old_verify_keys");
	if let Some(signatures) = source.get("signatures").filter(|value| value.is_object()) {
		destination.insert("signatures".to_owned(), signatures.clone());
	}
}

fn merge_json_object_field(
	destination: &mut Map<String, Value>,
	source: &Map<String, Value>,
	field: &str,
) {
	let Some(source_values) = source.get(field).and_then(Value::as_object) else {
		return;
	};
	let destination_values = destination
		.entry(field.to_owned())
		.or_insert_with(|| Value::Object(Map::new()));
	let Some(destination_values) = destination_values.as_object_mut() else {
		return;
	};
	for (key, value) in source_values {
		destination_values.insert(key.clone(), value.clone());
	}
}

fn pdu_id(shortroomid: u64, shorteventid: u64) -> Vec<u8> {
	let mut pdu_id = Vec::with_capacity(16);
	pdu_id.extend_from_slice(&shortroomid.to_be_bytes());
	pdu_id.extend_from_slice(&shorteventid.to_be_bytes());
	pdu_id
}
