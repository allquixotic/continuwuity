use std::path::PathBuf;

use conduwuit_core::config::Config;

use crate::{
	Error, Result,
	config::{SynapseDatabase, SynapseInstall},
	plan::{DataKind, MigrationPlan},
	sqlite::SqliteSource,
	store::{ContinuwuityStore, ImportReport},
};

const SUPPORTED_SQLITE_IMPORTS: &[DataKind] = &[
	DataKind::Users,
	DataKind::Profiles,
	DataKind::Devices,
	DataKind::AccessTokens,
	DataKind::AccountData,
	DataKind::Media,
	DataKind::RoomEvents,
	DataKind::RoomState,
	DataKind::Receipts,
];

pub fn execute_plan(plan: &MigrationPlan) -> Result<ImportReport> {
	let unsupported = plan
		.selected_data
		.iter()
		.filter(|kind| !SUPPORTED_SQLITE_IMPORTS.contains(kind))
		.collect::<Vec<_>>();
	if !unsupported.is_empty() {
		return Err(Error::Message(format!(
			"selected data kinds are not implemented for SQLite import yet: {unsupported:?}"
		)));
	}

	let SynapseDatabase::Sqlite { path } = &plan.synapse.database else {
		return Err(Error::Message(
			"only Synapse SQLite sources can be imported by this feature bundle".to_owned(),
		));
	};

	let source = SqliteSource::open(path)?;
	let destination = destination_database_path(plan)?;
	let mut store = ContinuwuityStore::open(destination)?;
	let mut report = ImportReport::default();

	if selected(plan, DataKind::Users) {
		store.import_users(
			source.users()?,
			plan.synapse.password_pepper.as_deref(),
			&mut report,
		)?;
	}
	if selected(plan, DataKind::Profiles) {
		store.import_profiles(
			source.profiles(plan.synapse.server_name.as_deref())?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::Devices) {
		store.import_devices(source.devices()?, &mut report)?;
	}
	if selected(plan, DataKind::AccessTokens) {
		store.import_access_tokens(source.access_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::AccountData) {
		store.import_account_data(source.account_data()?, &mut report)?;
	}
	if selected(plan, DataKind::Media) {
		import_media(&plan.synapse, &source, &mut store, &mut report)?;
	}
	if selected(plan, DataKind::RoomEvents) {
		store.import_room_events(source.room_events()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomState) {
		store.import_room_state(source.room_state()?, &mut report)?;
	}
	if selected(plan, DataKind::Receipts) {
		store.import_receipts(source.receipts()?, &mut report)?;
	}

	Ok(report)
}

fn import_media(
	synapse: &SynapseInstall,
	source: &SqliteSource,
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

fn selected(plan: &MigrationPlan, kind: DataKind) -> bool {
	plan.selected_data.contains(&kind)
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
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None);

		let plan = test_plan(
			config_path,
			dest_path.clone(),
			vec![
				DataKind::Users,
				DataKind::Profiles,
				DataKind::Devices,
				DataKind::AccessTokens,
				DataKind::AccountData,
				DataKind::RoomEvents,
				DataKind::RoomState,
				DataKind::Receipts,
			],
		);
		let report = execute_plan(&plan).expect("execute import");

		assert_eq!(report.users, 1);
		assert_eq!(report.profiles, 1);
		assert_eq!(report.devices, 1);
		assert_eq!(report.access_tokens, 1);
		assert_eq!(report.account_data, 2);
		assert_eq!(report.room_events, 3);
		assert_eq!(report.room_state, 2);
		assert_eq!(report.receipts, 2);

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
		assert_receipts_imported(&store);
	}

	#[test]
	fn room_state_import_materializes_referenced_events() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		seed_core_sqlite(&sqlite_path);
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None);

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
		let config_path = write_synapse_config(temp.path(), &sqlite_path, Some(&media_store));

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
			CREATE TABLE devices (
				user_id TEXT, device_id TEXT, display_name TEXT, last_seen INTEGER, ip TEXT,
				hidden INTEGER
			);
			INSERT INTO devices VALUES (
				'@alice:example.com', 'DEVICE', 'Alice phone', 1234, '127.0.0.1', 0
			);
			CREATE TABLE access_tokens (
				user_id TEXT, device_id TEXT, token TEXT, valid_until_ms INTEGER
			);
			INSERT INTO access_tokens VALUES (
				'@alice:example.com', 'DEVICE', 'token', NULL
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

	fn write_synapse_config(
		dir: &std::path::Path,
		sqlite_path: &std::path::Path,
		media_store: Option<&std::path::Path>,
	) -> PathBuf {
		let path = dir.join("homeserver.yaml");
		let media = media_store.map_or(String::new(), |path| {
			format!("media_store_path: {}\n", path.display())
		});
		let mut file = fs::File::create(&path).expect("config file");
		write!(
			file,
			"
server_name: example.com
database:
  name: sqlite3
  args:
    database: {}
{media}",
			sqlite_path.display()
		)
		.expect("write config");
		path
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
