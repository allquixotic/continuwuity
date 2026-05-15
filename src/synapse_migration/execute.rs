use std::{fs, path::PathBuf};

use conduwuit_core::config::Config;

use crate::{
	Error, Result,
	config::{SynapseDatabase, SynapseInstall},
	plan::{DataKind, MigrationPlan},
	postgres::PostgresSource,
	sqlite::{
		SqliteSource, SynapseAccessToken, SynapseAccountData, SynapseCrossSigningKey,
		SynapseDevice, SynapseDeviceKey, SynapseFallbackKey, SynapseFilter, SynapseKeySignature,
		SynapseMedia, SynapseOneTimeKey, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapseReceipt, SynapseRoomAlias, SynapseRoomEvent, SynapseRoomKeyBackup,
		SynapseRoomKeyBackupVersion, SynapseRoomState, SynapseServerKey, SynapseThreepid,
		SynapseToDeviceMessage, SynapseUser,
	},
	store::{ContinuwuityStore, ImportReport},
};

const SUPPORTED_DATABASE_IMPORTS: &[DataKind] = &[
	DataKind::Users,
	DataKind::Profiles,
	DataKind::Threepids,
	DataKind::Devices,
	DataKind::DeviceKeys,
	DataKind::OneTimeKeys,
	DataKind::FallbackKeys,
	DataKind::CrossSigningKeys,
	DataKind::RoomKeyBackups,
	DataKind::ToDeviceMessages,
	DataKind::AccessTokens,
	DataKind::AccountData,
	DataKind::Filters,
	DataKind::Presence,
	DataKind::Media,
	DataKind::RoomEvents,
	DataKind::RoomState,
	DataKind::RoomAliases,
	DataKind::PublicRooms,
	DataKind::Receipts,
	DataKind::Pushers,
	DataKind::ServerKeys,
];
const FILE_IMPORTS: &[DataKind] = &[DataKind::Appservices, DataKind::SigningKey];

enum DatabaseSource {
	Sqlite(SqliteSource),
	Postgres(PostgresSource),
}

macro_rules! delegate_source {
	($source:expr, $method:ident($($arg:expr),* $(,)?)) => {
		match $source {
			| DatabaseSource::Sqlite(source) => source.$method($($arg),*),
			| DatabaseSource::Postgres(source) => source.$method($($arg),*),
		}
	};
}

impl DatabaseSource {
	fn open(database: &SynapseDatabase) -> Result<Self> {
		match database {
			| SynapseDatabase::Sqlite { path } => Ok(Self::Sqlite(SqliteSource::open(path)?)),
			| SynapseDatabase::Postgres { .. } => Ok(Self::Postgres(PostgresSource::open(database)?)),
			| SynapseDatabase::Other { name, .. } => Err(Error::Message(format!(
				"Synapse database backend {name} is not supported for row import"
			))),
		}
	}

	fn users(&self) -> Result<Vec<SynapseUser>> { delegate_source!(self, users()) }

	fn profiles(&self, server_name: Option<&str>) -> Result<Vec<SynapseProfile>> {
		delegate_source!(self, profiles(server_name))
	}

	fn threepids(&self) -> Result<Vec<SynapseThreepid>> {
		delegate_source!(self, threepids())
	}

	fn devices(&self) -> Result<Vec<SynapseDevice>> { delegate_source!(self, devices()) }

	fn device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		delegate_source!(self, device_keys())
	}

	fn one_time_keys(&self) -> Result<Vec<SynapseOneTimeKey>> {
		delegate_source!(self, one_time_keys())
	}

	fn fallback_keys(&self) -> Result<Vec<SynapseFallbackKey>> {
		delegate_source!(self, fallback_keys())
	}

	fn cross_signing_keys(&self) -> Result<Vec<SynapseCrossSigningKey>> {
		delegate_source!(self, cross_signing_keys())
	}

	fn cross_signing_signatures(&self) -> Result<Vec<SynapseKeySignature>> {
		delegate_source!(self, cross_signing_signatures())
	}

	fn room_key_backup_versions(&self) -> Result<Vec<SynapseRoomKeyBackupVersion>> {
		delegate_source!(self, room_key_backup_versions())
	}

	fn room_key_backups(&self) -> Result<Vec<SynapseRoomKeyBackup>> {
		delegate_source!(self, room_key_backups())
	}

	fn to_device_messages(&self) -> Result<Vec<SynapseToDeviceMessage>> {
		delegate_source!(self, to_device_messages())
	}

	fn access_tokens(&self) -> Result<Vec<SynapseAccessToken>> {
		delegate_source!(self, access_tokens())
	}

	fn account_data(&self) -> Result<Vec<SynapseAccountData>> {
		delegate_source!(self, account_data())
	}

	fn filters(&self, server_name: Option<&str>) -> Result<Vec<SynapseFilter>> {
		delegate_source!(self, filters(server_name))
	}

	fn presence(&self) -> Result<Vec<SynapsePresence>> {
		delegate_source!(self, presence())
	}

	fn media(
		&self,
		media_store: &std::path::Path,
		server_name: &str,
	) -> Result<Vec<SynapseMedia>> {
		delegate_source!(self, media(media_store, server_name))
	}

	fn room_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		delegate_source!(self, room_events())
	}

	fn room_state(&self) -> Result<Vec<SynapseRoomState>> {
		delegate_source!(self, room_state())
	}

	fn room_aliases(&self) -> Result<Vec<SynapseRoomAlias>> {
		delegate_source!(self, room_aliases())
	}

	fn public_rooms(&self) -> Result<Vec<SynapsePublicRoom>> {
		delegate_source!(self, public_rooms())
	}

	fn receipts(&self) -> Result<Vec<SynapseReceipt>> {
		delegate_source!(self, receipts())
	}

	fn pushers(&self) -> Result<Vec<SynapsePusher>> { delegate_source!(self, pushers()) }

	fn server_keys(&self) -> Result<Vec<SynapseServerKey>> {
		delegate_source!(self, server_keys())
	}
}

pub fn execute_plan(plan: &MigrationPlan) -> Result<ImportReport> {
	let unsupported = plan
		.selected_data
		.iter()
		.filter(|kind| !SUPPORTED_DATABASE_IMPORTS.contains(kind) && !FILE_IMPORTS.contains(kind))
		.collect::<Vec<_>>();
	if !unsupported.is_empty() {
		return Err(Error::Message(format!(
			"selected data kinds are not implemented for import yet: {unsupported:?}"
		)));
	}

	let destination = destination_database_path(plan)?;
	let mut store = ContinuwuityStore::open(destination)?;
	let mut report = ImportReport::default();
	let source = if needs_database_source(plan) {
		Some(DatabaseSource::open(&plan.synapse.database)?)
	} else {
		None
	};

	if selected(plan, DataKind::Users) {
		let source = database_source(&source);
		store.import_users(
			source.users()?,
			plan.synapse.password_pepper.as_deref(),
			&mut report,
		)?;
	}
	if selected(plan, DataKind::Profiles) {
		let source = database_source(&source);
		store.import_profiles(
			source.profiles(plan.synapse.server_name.as_deref())?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::Threepids) {
		let source = database_source(&source);
		store.import_threepids(source.threepids()?, &mut report)?;
	}
	if selected(plan, DataKind::Devices) {
		let source = database_source(&source);
		store.import_devices(source.devices()?, &mut report)?;
	}
	if selected(plan, DataKind::DeviceKeys) {
		let source = database_source(&source);
		store.import_device_keys(
			source.device_keys()?,
			source.cross_signing_signatures()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::OneTimeKeys) {
		let source = database_source(&source);
		store.import_one_time_keys(source.one_time_keys()?, &mut report)?;
	}
	if selected(plan, DataKind::FallbackKeys) {
		let source = database_source(&source);
		store.import_fallback_keys(source.fallback_keys()?, &mut report)?;
	}
	if selected(plan, DataKind::CrossSigningKeys) {
		let source = database_source(&source);
		store.import_cross_signing_keys(
			source.cross_signing_keys()?,
			source.cross_signing_signatures()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::RoomKeyBackups) {
		let source = database_source(&source);
		store.import_room_key_backups(
			source.room_key_backup_versions()?,
			source.room_key_backups()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::ToDeviceMessages) {
		let source = database_source(&source);
		store.import_to_device_messages(source.to_device_messages()?, &mut report)?;
	}
	if selected(plan, DataKind::AccessTokens) {
		let source = database_source(&source);
		store.import_access_tokens(source.access_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::Pushers) {
		let source = database_source(&source);
		store.import_pushers(source.pushers()?, &mut report)?;
	}
	if selected(plan, DataKind::AccountData) {
		let source = database_source(&source);
		store.import_account_data(source.account_data()?, &mut report)?;
	}
	if selected(plan, DataKind::Filters) {
		let source = database_source(&source);
		store.import_filters(source.filters(plan.synapse.server_name.as_deref())?, &mut report)?;
	}
	if selected(plan, DataKind::Presence) {
		let source = database_source(&source);
		store.import_presence(source.presence()?, &mut report)?;
	}
	if selected(plan, DataKind::Media) {
		let source = database_source(&source);
		import_media(&plan.synapse, source, &mut store, &mut report)?;
	}
	if selected(plan, DataKind::RoomEvents) {
		let source = database_source(&source);
		store.import_room_events(source.room_events()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomState) {
		let source = database_source(&source);
		store.import_room_state(source.room_state()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomAliases) {
		let source = database_source(&source);
		store.import_room_aliases(source.room_aliases()?, &mut report)?;
	}
	if selected(plan, DataKind::PublicRooms) {
		let source = database_source(&source);
		store.import_public_rooms(source.public_rooms()?, &mut report)?;
	}
	if selected(plan, DataKind::Receipts) {
		let source = database_source(&source);
		store.import_receipts(source.receipts()?, &mut report)?;
	}
	if selected(plan, DataKind::Appservices) {
		store.import_appservices(&plan.synapse.app_service_config_files, &mut report)?;
	}
	if selected(plan, DataKind::SigningKey) {
		import_signing_key(&plan.synapse, &store, &mut report)?;
	}
	if selected(plan, DataKind::ServerKeys) {
		let source = database_source(&source);
		store.import_server_keys(source.server_keys()?, &mut report)?;
	}

	Ok(report)
}

fn import_media(
	synapse: &SynapseInstall,
	source: &DatabaseSource,
	store: &mut ContinuwuityStore,
	report: &mut ImportReport,
) -> Result<()> {
	let Some(media_store) = &synapse.media_store_path else {
		return Err(Error::Message(
			"media import selected but Synapse media_store_path is unknown".to_owned(),
		));
	};
	let Some(server_name) = &synapse.server_name else {
		return Err(Error::Message(
			"media import selected but Synapse server_name is unknown".to_owned(),
		));
	};

	store.import_media(source.media(media_store, server_name)?, report)
}

fn import_signing_key(
	synapse: &SynapseInstall,
	store: &ContinuwuityStore,
	report: &mut ImportReport,
) -> Result<()> {
	if let Some(signing_key) = &synapse.signing_key {
		return store.import_signing_key(signing_key.as_bytes(), report);
	}

	let Some(path) = &synapse.signing_key_path else {
		return Err(Error::Message(
			"signing-key import selected but Synapse signing_key_path is unknown".to_owned(),
		));
	};
	let body = fs::read(path).map_err(|e| Error::io(path, e))?;

	store.import_signing_key(&body, report)
}

fn selected(plan: &MigrationPlan, kind: DataKind) -> bool {
	plan.selected_data.contains(&kind)
}

fn needs_database_source(plan: &MigrationPlan) -> bool {
	plan.selected_data
		.iter()
		.any(|kind| SUPPORTED_DATABASE_IMPORTS.contains(kind))
}

fn database_source(source: &Option<DatabaseSource>) -> &DatabaseSource {
	source
		.as_ref()
		.expect("database source is opened when database-backed data is selected")
}

fn destination_database_path(plan: &MigrationPlan) -> Result<PathBuf> {
	if let Some(path) = &plan.continuwuity_database_path {
		return Ok(path.clone());
	}

	let raw = Config::load(&plan.continuwuity_config_paths)?;
	let config = Config::new(&raw)?;

	Ok(config.database_path)
}

#[cfg(test)]
mod tests {
	use std::{collections::HashMap, fs, io::Write};

	use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
	use conduwuit_database::serialize_to_vec;
	use rusqlite::Connection;
	use tempfile::tempdir;

	use super::*;
	use crate::{
		config::ConfigOverrides,
		discover::DiscoveryInput,
		plan::PlanRequest,
	};

	#[test]
	fn imports_core_sqlite_rows_into_rocksdb() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		seed_core_sqlite(&sqlite_path);
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(
			config_path,
			dest_path.clone(),
			vec![
				DataKind::Users,
				DataKind::Profiles,
				DataKind::Threepids,
				DataKind::Devices,
				DataKind::DeviceKeys,
				DataKind::OneTimeKeys,
				DataKind::FallbackKeys,
				DataKind::CrossSigningKeys,
				DataKind::RoomKeyBackups,
				DataKind::ToDeviceMessages,
				DataKind::AccessTokens,
				DataKind::Pushers,
				DataKind::AccountData,
				DataKind::Filters,
				DataKind::Presence,
				DataKind::RoomEvents,
				DataKind::RoomState,
				DataKind::RoomAliases,
				DataKind::PublicRooms,
				DataKind::Receipts,
				DataKind::ServerKeys,
			],
		);
		let report = execute_plan(&plan).expect("execute import");

		assert_eq!(report.users, 1);
		assert_eq!(report.profiles, 1);
		assert_eq!(report.threepids, 1);
		assert_eq!(report.devices, 1);
		assert_eq!(report.device_keys, 1);
		assert_eq!(report.one_time_keys, 1);
		assert_eq!(report.fallback_keys, 1);
		assert_eq!(report.cross_signing_keys, 3);
		assert_eq!(report.key_signatures, 2);
		assert_eq!(report.room_key_backup_versions, 1);
		assert_eq!(report.room_key_backups, 1);
		assert_eq!(report.to_device_messages, 1);
		assert_eq!(report.access_tokens, 1);
		assert_eq!(report.pushers, 1);
		assert_eq!(report.account_data, 2);
		assert_eq!(report.filters, 1);
		assert_eq!(report.presence, 1);
		assert_eq!(report.room_events, 3);
		assert_eq!(report.room_state, 2);
		assert_eq!(report.room_aliases, 1);
		assert_eq!(report.public_rooms, 1);
		assert_eq!(report.receipts, 2);
		assert_eq!(report.server_keys, 1);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		let password = store
			.get_raw("userid_password", b"@alice:example.com")
			.expect("password query")
			.expect("password row");
		assert!(String::from_utf8_lossy(&password).starts_with("$synapse$bcrypt$"));
		assert_eq!(
			store
				.get_raw("userid_displayname", b"@alice:example.com")
				.expect("displayname query")
				.expect("displayname row"),
			b"Alice".to_vec()
		);
		assert_threepids_imported(&store);
		assert_filters_imported(&store);
		assert_presence_imported(&store);
		assert!(
			store
				.get_raw("token_userdeviceid", b"token")
				.expect("token query")
				.is_some()
		);
		assert!(
			store
				.get_raw("eventid_pduid", b"$event:example.com")
				.expect("event query")
				.is_some()
		);
		assert_room_state_imported(&store);
		assert_room_aliases_imported(&store);
		assert_public_rooms_imported(&store);
		assert_e2ee_imported(&store);
		assert_room_key_backups_imported(&store);
		assert_to_device_messages_imported(&store);
		assert_receipts_imported(&store);
		assert_pushers_imported(&store);
		assert_server_keys_imported(&store);
	}

	#[test]
	fn room_state_import_materializes_referenced_events() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		seed_core_sqlite(&sqlite_path);
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::RoomState]);
		let report = execute_plan(&plan).expect("execute state import");

		assert_eq!(report.room_events, 0);
		assert_eq!(report.room_state, 2);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		assert!(
			store
				.get_raw("eventid_pduid", b"$member:example.com")
				.expect("event query")
				.is_some()
		);
		assert_room_state_imported(&store);
	}

	#[test]
	fn imports_local_media_file() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let media_store = temp.path().join("media_store");
		let dest_path = temp.path().join("continuwuity-db");
		fs::create_dir_all(media_store.join("local_content/ab/cd")).expect("media dirs");
		fs::write(media_store.join("local_content/ab/cd/ef"), b"media").expect("media file");

		let conn = Connection::open(&sqlite_path).expect("sqlite");
		conn.execute_batch(
			"
			CREATE TABLE local_media_repository (
				media_id TEXT, media_type TEXT, upload_name TEXT, user_id TEXT, url_cache TEXT
			);
			INSERT INTO local_media_repository VALUES (
				'abcdef', 'text/plain', 'note.txt', '@alice:example.com', NULL
			);
			",
		)
		.expect("seed media sqlite");
		let config_path = write_synapse_config(temp.path(), &sqlite_path, Some(&media_store), &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::Media]);
		let report = execute_plan(&plan).expect("execute media import");

		assert_eq!(report.media, 1);
		assert_eq!(
			fs::read_dir(dest_path.join("media"))
				.expect("dest media dir")
				.count(),
			1
		);
	}

	#[test]
	fn imports_appservice_registration_file() {
		let temp = tempdir().expect("tempdir");
		let dest_path = temp.path().join("continuwuity-db");
		let appservice_path = temp.path().join("bridge.yaml");
		fs::write(
			&appservice_path,
			"
id: bridge
url: http://127.0.0.1:29317
as_token: as-token
hs_token: hs-token
sender_localpart: bridge
namespaces:
  users:
    - exclusive: true
      regex: '@bridge_.*:example.com'
  aliases: []
  rooms: []
rate_limited: false
",
		)
		.expect("appservice config");
		let config_path = write_synapse_postgres_config(temp.path(), &[appservice_path.clone()]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::Appservices]);
		let report = execute_plan(&plan).expect("execute appservice import");

		assert_eq!(report.appservices, 1);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		let registration = store
			.get_raw("id_appserviceregistrations", b"bridge")
			.expect("appservice query")
			.expect("appservice row");
		assert!(String::from_utf8_lossy(&registration).contains("as-token"));
	}

	#[test]
	fn imports_default_synapse_signing_key_file() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		let seed = [7_u8; 32];
		let seed_b64 = BASE64_STANDARD_NO_PAD.encode(seed);
		fs::write(
			temp.path().join("example.com.signing.key"),
			format!("ed25519 a_test {seed_b64}\n"),
		)
		.expect("signing key file");
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::SigningKey]);
		let report = execute_plan(&plan).expect("execute signing key import");

		assert_eq!(report.signing_keys, 1);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		let keypair = store
			.get_raw("global", b"keypair")
			.expect("keypair query")
			.expect("keypair row");
		assert!(keypair.starts_with(b"a_test\xFF"));
		assert!(keypair.ends_with(&seed));
	}

	fn seed_core_sqlite(path: &std::path::Path) {
		let conn = Connection::open(path).expect("sqlite");
		let password_hash = bcrypt::hash("secret", 4).expect("bcrypt hash");
		conn.execute_batch(&format!(
			"
			CREATE TABLE users (
				name TEXT, password_hash TEXT, deactivated INTEGER, admin INTEGER,
				appservice_id TEXT, user_type TEXT, shadow_banned INTEGER
			);
			INSERT INTO users VALUES (
				'@alice:example.com', '{password_hash}', 0, 1, NULL, NULL, 0
			);
			CREATE TABLE profiles (
				user_id TEXT, full_user_id TEXT, displayname TEXT, avatar_url TEXT
			);
			INSERT INTO profiles VALUES (
				'alice', '@alice:example.com', 'Alice', 'mxc://example.com/avatar'
			);
			CREATE TABLE user_threepids (
				user_id TEXT NOT NULL, medium TEXT NOT NULL, address TEXT NOT NULL,
				validated_at BIGINT, added_at BIGINT
			);
			INSERT INTO user_threepids VALUES (
				'@alice:example.com', 'email', 'Alice@Example.COM', 1000, 2000
			);
			CREATE TABLE devices (
				user_id TEXT, device_id TEXT, display_name TEXT, last_seen INTEGER, ip TEXT,
				hidden INTEGER
			);
			INSERT INTO devices VALUES (
				'@alice:example.com', 'DEVICE', 'Alice phone', 1234, '127.0.0.1', 0
			);
			CREATE TABLE e2e_device_keys_json (
				user_id TEXT NOT NULL, device_id TEXT NOT NULL, ts_added_ms BIGINT NOT NULL,
				key_json TEXT NOT NULL
			);
			INSERT INTO e2e_device_keys_json VALUES (
				'@alice:example.com', 'DEVICE', 1234,
				'{{
					\"user_id\":\"@alice:example.com\",
					\"device_id\":\"DEVICE\",
					\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\"],
					\"keys\":{{\"curve25519:DEVICE\":\"curve\",\"ed25519:DEVICE\":\"ed\"}},
					\"signatures\":{{}}
				}}'
			);
			CREATE TABLE e2e_one_time_keys_json (
				user_id TEXT NOT NULL, device_id TEXT NOT NULL, algorithm TEXT NOT NULL,
				key_id TEXT NOT NULL, ts_added_ms BIGINT NOT NULL, key_json TEXT NOT NULL
			);
			INSERT INTO e2e_one_time_keys_json VALUES (
				'@alice:example.com', 'DEVICE', 'signed_curve25519', 'AAAA', 1235,
				'{{\"key\":\"otk\"}}'
			);
			CREATE TABLE e2e_fallback_keys_json (
				user_id TEXT NOT NULL, device_id TEXT NOT NULL, algorithm TEXT NOT NULL,
				key_id TEXT NOT NULL, key_json TEXT NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE
			);
			INSERT INTO e2e_fallback_keys_json VALUES (
				'@alice:example.com', 'DEVICE', 'signed_curve25519', 'FALL',
				'{{\"key\":\"fallback\"}}', 0
			);
			CREATE TABLE e2e_cross_signing_keys (
				user_id TEXT NOT NULL, keytype TEXT NOT NULL, keydata TEXT NOT NULL,
				stream_id BIGINT NOT NULL
			);
			INSERT INTO e2e_cross_signing_keys VALUES (
				'@alice:example.com', 'master',
				'{{
					\"user_id\":\"@alice:example.com\",
					\"usage\":[\"master\"],
					\"keys\":{{\"ed25519:master\":\"master\"}}
				}}',
				10
			);
			INSERT INTO e2e_cross_signing_keys VALUES (
				'@alice:example.com', 'self_signing',
				'{{
					\"user_id\":\"@alice:example.com\",
					\"usage\":[\"self_signing\"],
					\"keys\":{{\"ed25519:self\":\"self\"}}
				}}',
				11
			);
			INSERT INTO e2e_cross_signing_keys VALUES (
				'@alice:example.com', 'user_signing',
				'{{
					\"user_id\":\"@alice:example.com\",
					\"usage\":[\"user_signing\"],
					\"keys\":{{\"ed25519:user\":\"user\"}}
				}}',
				12
			);
			CREATE TABLE e2e_cross_signing_signatures (
				user_id TEXT NOT NULL, key_id TEXT NOT NULL, target_user_id TEXT NOT NULL,
				target_device_id TEXT NOT NULL, signature TEXT NOT NULL
			);
			INSERT INTO e2e_cross_signing_signatures VALUES (
				'@alice:example.com', 'ed25519:master', '@alice:example.com',
				'DEVICE', 'device-sig'
			);
			INSERT INTO e2e_cross_signing_signatures VALUES (
				'@alice:example.com', 'ed25519:master', '@alice:example.com',
				'self', 'self-sig'
			);
			CREATE TABLE e2e_room_keys_versions (
				user_id TEXT NOT NULL, version BIGINT NOT NULL, algorithm TEXT NOT NULL,
				auth_data TEXT NOT NULL, deleted SMALLINT DEFAULT 0 NOT NULL, etag BIGINT
			);
			INSERT INTO e2e_room_keys_versions VALUES (
				'@alice:example.com', 1, 'm.megolm_backup.v1.curve25519-aes-sha2',
				'{{\"public_key\":\"backup-public-key\"}}', 0, 99
			);
			CREATE TABLE e2e_room_keys (
				user_id TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL,
				version BIGINT NOT NULL, first_message_index INT, forwarded_count INT,
				is_verified BOOLEAN, session_data TEXT NOT NULL
			);
			INSERT INTO e2e_room_keys VALUES (
				'@alice:example.com', '!room:example.com', 'SESSION', 1, 7, 2, 1,
				'{{\"ciphertext\":\"cipher\",\"mac\":\"mac\",\"ephemeral\":\"key\"}}'
			);
			CREATE TABLE device_inbox (
				user_id TEXT NOT NULL, device_id TEXT NOT NULL, stream_id BIGINT NOT NULL,
				message_json TEXT NOT NULL
			);
			INSERT INTO device_inbox VALUES (
				'@alice:example.com', 'DEVICE', 90,
				'{{
					\"type\":\"m.room_key_request\",
					\"sender\":\"@alice:example.com\",
					\"content\":{{\"action\":\"request\",\"request_id\":\"req\"}}
				}}'
			);
			CREATE TABLE access_tokens (
				user_id TEXT, device_id TEXT, token TEXT, valid_until_ms INTEGER
			);
			INSERT INTO access_tokens VALUES (
				'@alice:example.com', 'DEVICE', 'token', NULL
			);
			CREATE TABLE pushers (
				id BIGINT PRIMARY KEY, user_name TEXT NOT NULL, access_token BIGINT DEFAULT NULL,
				profile_tag TEXT NOT NULL, kind TEXT NOT NULL, app_id TEXT NOT NULL,
				app_display_name TEXT NOT NULL, device_display_name TEXT NOT NULL,
				pushkey TEXT NOT NULL, ts BIGINT NOT NULL, lang TEXT, data TEXT,
				last_stream_ordering INTEGER, last_success BIGINT, failing_since BIGINT,
				enabled INTEGER, device_id TEXT
			);
			INSERT INTO pushers VALUES (
				1, '@alice:example.com', NULL, '', 'http', 'com.example.app',
				'Example App', 'Alice phone', 'pushkey', 1234, 'en',
				'{{\"url\":\"https://push.example.com/_matrix/push/v1/notify\",\"format\":\"event_id_only\"}}',
				NULL, NULL, NULL, 1, 'DEVICE'
			);
			CREATE TABLE server_keys_json (
				server_name TEXT NOT NULL, key_id TEXT NOT NULL, from_server TEXT NOT NULL,
				ts_added_ms BIGINT NOT NULL, ts_valid_until_ms BIGINT NOT NULL,
				key_json BLOB NOT NULL
			);
			INSERT INTO server_keys_json VALUES (
				'remote.example', 'ed25519:1', 'remote.example', 1000, 9000,
				'{{
					\"server_name\":\"remote.example\",
					\"valid_until_ts\":9000,
					\"verify_keys\":{{\"ed25519:1\":{{\"key\":\"YWJj\"}}}},
					\"old_verify_keys\":{{}},
					\"signatures\":{{\"remote.example\":{{\"ed25519:1\":\"sig\"}}}}
				}}'
			);
			CREATE TABLE account_data (
				user_id TEXT, account_data_type TEXT, content TEXT
			);
			INSERT INTO account_data VALUES (
				'@alice:example.com', 'm.push_rules', '{{\"global\": {{}}}}'
			);
			CREATE TABLE room_account_data (
				user_id TEXT, room_id TEXT, account_data_type TEXT, content TEXT
			);
			INSERT INTO room_account_data VALUES (
				'@alice:example.com', '!room:example.com', 'm.tag', '{{\"tags\": {{}}}}'
			);
			CREATE TABLE user_filters (
				user_id TEXT NOT NULL, full_user_id TEXT, filter_id BIGINT NOT NULL,
				filter_json BLOB NOT NULL
			);
			INSERT INTO user_filters VALUES (
				'alice', '@alice:example.com', 1, '{{\"room\":{{\"timeline\":{{\"limit\":20}}}}}}'
			);
			CREATE TABLE presence_stream (
				stream_id BIGINT, user_id TEXT, state TEXT, last_active_ts BIGINT,
				last_federation_update_ts BIGINT, last_user_sync_ts BIGINT, status_msg TEXT,
				currently_active BOOLEAN
			);
			INSERT INTO presence_stream VALUES (
				91, '@alice:example.com', 'online', 123456, 123457, 123458, 'Ready', 1
			);
			INSERT INTO presence_stream VALUES (
				89, '@alice:example.com', 'unavailable', 100000, 100001, 100002, 'Older', 0
			);
			CREATE TABLE events (
				stream_ordering INTEGER, event_id TEXT, room_id TEXT, outlier INTEGER,
				rejection_reason TEXT
			);
			CREATE TABLE event_json (
				event_id TEXT, room_id TEXT, json TEXT
			);
			INSERT INTO events VALUES (
				1, '$create:example.com', '!room:example.com', 0, NULL
			);
			INSERT INTO events VALUES (
				2, '$member:example.com', '!room:example.com', 0, NULL
			);
			INSERT INTO events VALUES (
				42, '$event:example.com', '!room:example.com', 0, NULL
			);
			INSERT INTO event_json VALUES (
				'$create:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":1,
					\"type\":\"m.room.create\",
					\"state_key\":\"\",
					\"content\":{{\"creator\":\"@alice:example.com\",\"room_version\":\"11\"}},
					\"prev_events\":[],
					\"depth\":1,
					\"auth_events\":[],
					\"hashes\":{{\"sha256\":\"create\"}},
					\"signatures\":{{}}
				}}'
			);
			INSERT INTO event_json VALUES (
				'$member:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":2,
					\"type\":\"m.room.member\",
					\"state_key\":\"@alice:example.com\",
					\"content\":{{\"membership\":\"join\",\"displayname\":\"Alice\"}},
					\"prev_events\":[\"$create:example.com\"],
					\"depth\":2,
					\"auth_events\":[\"$create:example.com\"],
					\"hashes\":{{\"sha256\":\"member\"}},
					\"signatures\":{{}}
				}}'
			);
			INSERT INTO event_json VALUES (
				'$event:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":1,
					\"type\":\"m.room.message\",
					\"content\":{{\"body\":\"hi\",\"msgtype\":\"m.text\"}},
					\"prev_events\":[],
					\"depth\":1,
					\"auth_events\":[],
					\"hashes\":{{\"sha256\":\"abc\"}},
					\"signatures\":{{}}
				}}'
			);
			CREATE TABLE current_state_events (
				event_id TEXT NOT NULL, room_id TEXT NOT NULL, type TEXT NOT NULL,
				state_key TEXT NOT NULL, membership TEXT
			);
			INSERT INTO current_state_events VALUES (
				'$create:example.com', '!room:example.com', 'm.room.create', '', NULL
			);
			INSERT INTO current_state_events VALUES (
				'$member:example.com', '!room:example.com', 'm.room.member',
				'@alice:example.com', 'join'
			);
			CREATE TABLE room_aliases (
				room_alias TEXT NOT NULL, room_id TEXT NOT NULL, creator TEXT,
				UNIQUE(room_alias)
			);
			INSERT INTO room_aliases VALUES (
				'#test:example.com', '!room:example.com', '@alice:example.com'
			);
			CREATE TABLE room_alias_servers (
				room_alias TEXT NOT NULL, server TEXT NOT NULL
			);
			INSERT INTO room_alias_servers VALUES (
				'#test:example.com', 'example.com'
			);
			CREATE TABLE rooms (
				room_id TEXT NOT NULL, is_public BOOLEAN
			);
			INSERT INTO rooms VALUES (
				'!room:example.com', 1
			);
			CREATE TABLE receipts_linearized (
				stream_id BIGINT NOT NULL, room_id TEXT NOT NULL, receipt_type TEXT NOT NULL,
				user_id TEXT NOT NULL, event_id TEXT NOT NULL, thread_id TEXT,
				event_stream_ordering BIGINT, data TEXT NOT NULL
			);
			INSERT INTO receipts_linearized VALUES (
				77, '!room:example.com', 'm.read', '@alice:example.com',
				'$event:example.com', NULL, 42, '{{\"ts\":1234}}'
			);
			INSERT INTO receipts_linearized VALUES (
				78, '!room:example.com', 'm.read.private', '@alice:example.com',
				'$event:example.com', NULL, 42, '{{\"ts\":1235}}'
			);
			"
		))
		.expect("seed sqlite");
	}

	fn assert_threepids_imported(store: &ContinuwuityStore) {
		assert_eq!(
			store
				.get_raw("email_localpart", b"alice@example.com")
				.expect("email lookup query")
				.expect("email lookup row"),
			b"alice".to_vec()
		);
		assert_eq!(
			store
				.get_raw("localpart_email", b"alice")
				.expect("localpart email query")
				.expect("localpart email row"),
			b"alice@example.com".to_vec()
		);
	}

	fn assert_filters_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec(("@alice:example.com", "1")).expect("filter key");
		let filter = store
			.get_raw("userfilterid_filter", &key)
			.expect("filter query")
			.expect("filter row");
		let filter: serde_json::Value = serde_json::from_slice(&filter).expect("filter json");
		assert_eq!(filter["room"]["timeline"]["limit"], 20);
	}

	fn assert_presence_imported(store: &ContinuwuityStore) {
		assert_eq!(
			store
				.get_raw("userid_presenceid", b"@alice:example.com")
				.expect("presence index query")
				.expect("presence index row"),
			91_u64.to_be_bytes().to_vec()
		);

		let mut key = 91_u64.to_be_bytes().to_vec();
		key.extend_from_slice(b"@alice:example.com");
		let presence = store
			.get_raw("presenceid_presence", &key)
			.expect("presence query")
			.expect("presence row");
		let presence: serde_json::Value =
			serde_json::from_slice(&presence).expect("presence json");
		assert_eq!(presence["state"], "online");
		assert_eq!(presence["currently_active"], true);
		assert_eq!(presence["last_active_ts"], 123456);
		assert_eq!(presence["status_msg"], "Ready");
	}

	fn assert_room_state_imported(store: &ContinuwuityStore) {
		let state_hash = store
			.get_raw("roomid_shortstatehash", b"!room:example.com")
			.expect("state hash query")
			.expect("state hash row");
		assert_eq!(state_hash.len(), 8);

		let state_diff = store
			.get_raw("shortstatehash_statediff", &state_hash)
			.expect("state diff query")
			.expect("state diff row");
		assert_eq!(state_diff.len(), 40);

		let member_state_key =
			serialize_to_vec(("m.room.member", "@alice:example.com")).expect("member state key");
		assert!(
			store
				.get_raw("statekey_shortstatekey", &member_state_key)
				.expect("member state key query")
				.is_some()
		);

		let userroom =
			serialize_to_vec(("@alice:example.com", "!room:example.com")).expect("userroom key");
		let roomuser =
			serialize_to_vec(("!room:example.com", "@alice:example.com")).expect("roomuser key");
		assert!(
			store
				.get_raw("userroomid_joined", &userroom)
				.expect("user joined query")
				.is_some()
		);
		assert!(
			store
				.get_raw("roomuserid_joined", &roomuser)
				.expect("room joined query")
				.is_some()
		);
		assert!(
			store
				.get_raw("roomuseroncejoinedids", &userroom)
				.expect("once joined query")
				.is_some()
		);
		assert_eq!(
			store
				.get_raw("roomid_joinedcount", b"!room:example.com")
				.expect("joined count query")
				.expect("joined count row"),
			1_u64.to_be_bytes().to_vec()
		);
		assert!(
			store
				.get_raw(
					"roomserverids",
					&serialize_to_vec(("!room:example.com", "example.com"))
						.expect("room server key"),
				)
				.expect("room server query")
				.is_some()
		);
		assert!(
			store
				.get_raw(
					"serverroomids",
					&serialize_to_vec(("example.com", "!room:example.com"))
						.expect("server room key"),
			)
				.expect("server room query")
				.is_some()
		);
	}

	fn assert_room_aliases_imported(store: &ContinuwuityStore) {
		assert_eq!(
			store
				.get_raw("alias_roomid", b"test")
				.expect("alias room query")
				.expect("alias room row"),
			b"!room:example.com".to_vec()
		);
		assert_eq!(
			store
				.get_raw("alias_userid", b"test")
				.expect("alias creator query")
				.expect("alias creator row"),
			b"@alice:example.com".to_vec()
		);

		let mut prefix = b"!room:example.com".to_vec();
		prefix.push(0xFF);
		let aliases = store
			.prefix_raw("aliasid_alias", &prefix)
			.expect("alias index query");
		assert_eq!(aliases.len(), 1);
		assert_eq!(aliases[0].1, b"#test:example.com".to_vec());
	}

	fn assert_public_rooms_imported(store: &ContinuwuityStore) {
		assert!(
			store
				.get_raw("publicroomids", b"!room:example.com")
				.expect("public room query")
				.is_some()
		);
	}

	fn assert_e2ee_imported(store: &ContinuwuityStore) {
		let device_key =
			serialize_to_vec(("@alice:example.com", "DEVICE")).expect("device key id");
		let device = store
			.get_raw("keyid_key", &device_key)
			.expect("device key query")
			.expect("device key row");
		let device: serde_json::Value = serde_json::from_slice(&device).expect("device key json");
		assert_eq!(
			device["signatures"]["@alice:example.com"]["ed25519:master"],
			"device-sig"
		);

		let mut one_time_key = b"@alice:example.com".to_vec();
		one_time_key.push(0xFF);
		one_time_key.extend_from_slice(b"DEVICE");
		one_time_key.push(0xFF);
		one_time_key.extend_from_slice(
			serde_json::to_string("signed_curve25519:AAAA")
				.expect("one-time key id")
				.as_bytes(),
		);
		let one_time = store
			.get_raw("onetimekeyid_onetimekeys", &one_time_key)
			.expect("one-time key query")
			.expect("one-time key row");
		let one_time: serde_json::Value =
			serde_json::from_slice(&one_time).expect("one-time key json");
		assert_eq!(one_time["key"], "otk");

		let fallback_key = serialize_to_vec((
			"@alice:example.com",
			"DEVICE",
			"signed_curve25519",
		))
		.expect("fallback key id");
		assert!(
			store
				.get_raw("fallbackkeyid_fallbackkey", &fallback_key)
				.expect("fallback key query")
				.is_some()
		);

		let self_signing_key =
			serialize_to_vec(("@alice:example.com", "self")).expect("self-signing key id");
		let self_signing = store
			.get_raw("keyid_key", &self_signing_key)
			.expect("self-signing key query")
			.expect("self-signing key row");
		let self_signing: serde_json::Value =
			serde_json::from_slice(&self_signing).expect("self-signing key json");
		assert_eq!(
			self_signing["signatures"]["@alice:example.com"]["ed25519:master"],
			"self-sig"
		);
		assert_eq!(
			store
				.get_raw("userid_masterkeyid", b"@alice:example.com")
				.expect("master key query")
				.expect("master key row"),
			serialize_to_vec(("@alice:example.com", "master")).expect("master key id")
		);
		assert!(
			store
				.get_raw("userid_lastonetimekeyupdate", b"@alice:example.com")
				.expect("one-time update query")
				.is_some()
		);
	}

	fn assert_room_key_backups_imported(store: &ContinuwuityStore) {
		let version_key =
			serialize_to_vec(("@alice:example.com", "1")).expect("backup version key");
		let metadata = store
			.get_raw("backupid_algorithm", &version_key)
			.expect("backup metadata query")
			.expect("backup metadata row");
		let metadata: serde_json::Value =
			serde_json::from_slice(&metadata).expect("backup metadata json");
		assert_eq!(
			metadata["algorithm"],
			"m.megolm_backup.v1.curve25519-aes-sha2"
		);
		assert_eq!(metadata["auth_data"]["public_key"], "backup-public-key");
		assert_eq!(
			store
				.get_raw("backupid_etag", &version_key)
				.expect("backup etag query")
				.expect("backup etag row"),
			99_u64.to_be_bytes().to_vec()
		);

		let key = serialize_to_vec((
			"@alice:example.com",
			"1",
			"!room:example.com",
			"SESSION",
		))
		.expect("room key backup key");
		let backup = store
			.get_raw("backupkeyid_backup", &key)
			.expect("room key backup query")
			.expect("room key backup row");
		let backup: serde_json::Value =
			serde_json::from_slice(&backup).expect("room key backup json");
		assert_eq!(backup["first_message_index"], 7);
		assert_eq!(backup["forwarded_count"], 2);
		assert_eq!(backup["is_verified"], true);
		assert_eq!(backup["session_data"]["ciphertext"], "cipher");
	}

	fn assert_to_device_messages_imported(store: &ContinuwuityStore) {
		let key =
			serialize_to_vec(("@alice:example.com", "DEVICE", 90_u64)).expect("to-device key");
		let event = store
			.get_raw("todeviceid_events", &key)
			.expect("to-device query")
			.expect("to-device row");
		let event: serde_json::Value = serde_json::from_slice(&event).expect("to-device json");
		assert_eq!(event["type"], "m.room_key_request");
		assert_eq!(event["sender"], "@alice:example.com");
		assert_eq!(event["content"]["request_id"], "req");
	}

	fn assert_receipts_imported(store: &ContinuwuityStore) {
		let public_key = serialize_to_vec(("!room:example.com", 77_u64, "@alice:example.com"))
			.expect("public receipt key");
		let public = store
			.get_raw("readreceiptid_readreceipt", &public_key)
			.expect("public receipt query")
			.expect("public receipt row");
		let public: serde_json::Value =
			serde_json::from_slice(&public).expect("public receipt json");
		assert_eq!(
			public["content"]["$event:example.com"]["m.read"]["@alice:example.com"]["ts"],
			1234
		);

		let private_key =
			serialize_to_vec(("!room:example.com", "@alice:example.com")).expect("private key");
		assert_eq!(
			store
				.get_raw("roomuserid_privateread", &private_key)
				.expect("private receipt query")
				.expect("private receipt row"),
			42_u64.to_be_bytes().to_vec()
		);
		assert_eq!(
			store
				.get_raw("roomuserid_lastprivatereadupdate", &private_key)
				.expect("private receipt update query")
				.expect("private receipt update row"),
			78_u64.to_be_bytes().to_vec()
		);
	}

	fn assert_pushers_imported(store: &ContinuwuityStore) {
		let pusher_key =
			serialize_to_vec(("@alice:example.com", "pushkey")).expect("pusher key");
		let pusher = store
			.get_raw("senderkey_pusher", &pusher_key)
			.expect("pusher query")
			.expect("pusher row");
		let pusher: serde_json::Value = serde_json::from_slice(&pusher).expect("pusher json");
		assert_eq!(pusher["app_id"], "com.example.app");
		assert_eq!(pusher["kind"], "http");
		assert_eq!(
			pusher["data"]["url"],
			"https://push.example.com/_matrix/push/v1/notify"
		);

		assert_eq!(
			store
				.get_raw("pushkey_deviceid", b"pushkey")
				.expect("pusher device query")
				.expect("pusher device row"),
			b"DEVICE".to_vec()
		);
	}

	fn assert_server_keys_imported(store: &ContinuwuityStore) {
		let keys = store
			.get_raw("server_signingkeys", b"remote.example")
			.expect("server keys query")
			.expect("server keys row");
		let keys: serde_json::Value = serde_json::from_slice(&keys).expect("server keys json");
		assert_eq!(keys["server_name"], "remote.example");
		assert_eq!(keys["valid_until_ts"], 9000);
		assert_eq!(keys["verify_keys"]["ed25519:1"]["key"], "YWJj");
	}

	fn write_synapse_config(
		dir: &std::path::Path,
		sqlite_path: &std::path::Path,
		media_store: Option<&std::path::Path>,
		appservice_configs: &[PathBuf],
	) -> PathBuf {
		let path = dir.join("homeserver.yaml");
		let media = media_store.map_or(String::new(), |path| {
			format!("media_store_path: {}\n", path.display())
		});
		let appservices = appservice_config_yaml(appservice_configs);
		let mut file = fs::File::create(&path).expect("config file");
		write!(
			file,
			"
server_name: example.com
database:
  name: sqlite3
  args:
    database: {}
{media}{appservices}",
			sqlite_path.display()
		)
		.expect("write config");
		path
	}

	fn write_synapse_postgres_config(
		dir: &std::path::Path,
		appservice_configs: &[PathBuf],
	) -> PathBuf {
		let path = dir.join("homeserver.yaml");
		let appservices = appservice_config_yaml(appservice_configs);
		let mut file = fs::File::create(&path).expect("config file");
		write!(
			file,
			"
server_name: example.com
database:
  name: psycopg2
  args:
    database: synapse
{appservices}"
		)
		.expect("write config");
		path
	}

	fn appservice_config_yaml(appservice_configs: &[PathBuf]) -> String {
		if appservice_configs.is_empty() {
			return String::new();
		}

		let entries = appservice_configs
			.iter()
			.map(|path| format!("  - {}\n", path.display()))
			.collect::<String>();
		format!("app_service_config_files:\n{entries}")
	}

	fn test_plan(config_path: PathBuf, dest_path: PathBuf, only: Vec<DataKind>) -> MigrationPlan {
		let request = PlanRequest {
			explicit_synapse_configs: vec![config_path.clone()],
			config_overrides: ConfigOverrides::default(),
			continuwuity_database_path: Some(dest_path),
			only,
			..PlanRequest::default()
		};
		let input = DiscoveryInput {
			explicit_configs: vec![config_path],
			roots: Vec::new(),
			cwd: "/unused".into(),
			env: HashMap::new(),
		};

		MigrationPlan::build_with_discovery(request, &input).expect("plan")
	}
}
