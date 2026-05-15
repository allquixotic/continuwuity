use std::{fs, path::PathBuf};

use conduwuit_core::config::Config;

use crate::{
	Error, Result,
	config::{SynapseDatabase, SynapseInstall},
	plan::{DataKind, MigrationPlan},
	postgres::PostgresSource,
	sqlite::{
		SqliteSource, SynapseAccessToken, SynapseAccountData, SynapseBlockedRoom, SynapseCrossSigningKey,
		SynapseDehydratedDevice, SynapseDevice, SynapseDeviceKey, SynapseErasedUser,
		SynapseEventRelation, SynapseFallbackKey, SynapseFilter, SynapseForgottenRoom,
		SynapseForwardExtremity, SynapseIgnoredUser, SynapseKeySignature, SynapseMedia, SynapseNotificationCount,
		SynapseOneTimeKey, SynapseOpenIdToken, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapseReceipt, SynapseRedaction, SynapseRoomAlias, SynapseRoomEvent,
		SynapseRegistrationToken, SynapseRoomKeyBackup, SynapseRoomKeyBackupVersion, SynapseRoomState,
		SynapseRoomTag, SynapseServerKey, SynapseThreepid, SynapseToDeviceMessage, SynapseUrlPreview,
		SynapseUser,
	},
	store::{ContinuwuityStore, ImportReport},
};

const SUPPORTED_DATABASE_IMPORTS: &[DataKind] = &[
	DataKind::Users,
	DataKind::ErasedUsers,
	DataKind::RegistrationTokens,
	DataKind::Profiles,
	DataKind::Threepids,
	DataKind::Devices,
	DataKind::DehydratedDevices,
	DataKind::DeviceKeys,
	DataKind::OneTimeKeys,
	DataKind::FallbackKeys,
	DataKind::CrossSigningKeys,
	DataKind::RoomKeyBackups,
	DataKind::ToDeviceMessages,
	DataKind::AccessTokens,
	DataKind::OpenIdTokens,
	DataKind::AccountData,
	DataKind::IgnoredUsers,
	DataKind::RoomTags,
	DataKind::Filters,
	DataKind::Presence,
	DataKind::Media,
	DataKind::UrlPreviews,
	DataKind::RoomEvents,
	DataKind::Redactions,
	DataKind::RoomState,
	DataKind::EventRelations,
	DataKind::ForwardExtremities,
	DataKind::ForgottenRooms,
	DataKind::BlockedRooms,
	DataKind::RoomAliases,
	DataKind::PublicRooms,
	DataKind::Receipts,
	DataKind::NotificationCounts,
	DataKind::Pushers,
	DataKind::ServerKeys,
];
const FILE_IMPORTS: &[DataKind] = &[DataKind::Appservices, DataKind::SigningKey];
const LOCAL_IMPORTS: &[DataKind] = &[DataKind::SearchIndex];

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

	fn erased_users(&self) -> Result<Vec<SynapseErasedUser>> {
		delegate_source!(self, erased_users())
	}

	fn registration_tokens(&self) -> Result<Vec<SynapseRegistrationToken>> {
		delegate_source!(self, registration_tokens())
	}

	fn profiles(&self, server_name: Option<&str>) -> Result<Vec<SynapseProfile>> {
		delegate_source!(self, profiles(server_name))
	}

	fn threepids(&self) -> Result<Vec<SynapseThreepid>> {
		delegate_source!(self, threepids())
	}

	fn devices(&self) -> Result<Vec<SynapseDevice>> { delegate_source!(self, devices()) }

	fn dehydrated_devices(&self) -> Result<Vec<SynapseDehydratedDevice>> {
		delegate_source!(self, dehydrated_devices())
	}

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

	fn open_id_tokens(&self) -> Result<Vec<SynapseOpenIdToken>> {
		delegate_source!(self, open_id_tokens())
	}

	fn account_data(&self) -> Result<Vec<SynapseAccountData>> {
		delegate_source!(self, account_data())
	}

	fn ignored_users(&self) -> Result<Vec<SynapseIgnoredUser>> {
		delegate_source!(self, ignored_users())
	}

	fn room_tags(&self) -> Result<Vec<SynapseRoomTag>> {
		delegate_source!(self, room_tags())
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

	fn url_previews(&self) -> Result<Vec<SynapseUrlPreview>> {
		delegate_source!(self, url_previews())
	}

	fn room_events(&self) -> Result<Vec<SynapseRoomEvent>> {
		delegate_source!(self, room_events())
	}

	fn forward_extremities(&self) -> Result<Vec<SynapseForwardExtremity>> {
		delegate_source!(self, forward_extremities())
	}

	fn redactions(&self) -> Result<Vec<SynapseRedaction>> {
		delegate_source!(self, redactions())
	}

	fn event_relations(&self) -> Result<Vec<SynapseEventRelation>> {
		delegate_source!(self, event_relations())
	}

	fn room_state(&self) -> Result<Vec<SynapseRoomState>> {
		delegate_source!(self, room_state())
	}

	fn forgotten_rooms(&self) -> Result<Vec<SynapseForgottenRoom>> {
		delegate_source!(self, forgotten_rooms())
	}

	fn blocked_rooms(&self) -> Result<Vec<SynapseBlockedRoom>> {
		delegate_source!(self, blocked_rooms())
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

	fn notification_counts(&self) -> Result<Vec<SynapseNotificationCount>> {
		delegate_source!(self, notification_counts())
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
		.filter(|kind| {
			!SUPPORTED_DATABASE_IMPORTS.contains(kind)
				&& !FILE_IMPORTS.contains(kind)
				&& !LOCAL_IMPORTS.contains(kind)
		})
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
			plan.synapse.server_name.as_deref(),
			plan.synapse.password_pepper.as_deref(),
			&mut report,
		)?;
	}
	if selected(plan, DataKind::ErasedUsers) {
		let source = database_source(&source);
		store.import_erased_users(source.erased_users()?, &mut report)?;
	}
	if selected(plan, DataKind::RegistrationTokens) {
		let source = database_source(&source);
		store.import_registration_tokens(
			source.registration_tokens()?,
			plan.synapse.server_name.as_deref(),
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
	if selected(plan, DataKind::DehydratedDevices) {
		let source = database_source(&source);
		store.import_dehydrated_devices(source.dehydrated_devices()?, &mut report)?;
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
	if selected(plan, DataKind::OpenIdTokens) {
		let source = database_source(&source);
		store.import_open_id_tokens(source.open_id_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::Pushers) {
		let source = database_source(&source);
		store.import_pushers(source.pushers()?, &mut report)?;
	}
	if selected(plan, DataKind::AccountData) {
		let source = database_source(&source);
		store.import_account_data(source.account_data()?, &mut report)?;
	}
	if selected(plan, DataKind::IgnoredUsers) {
		let source = database_source(&source);
		store.import_ignored_users(source.ignored_users()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomTags) {
		let source = database_source(&source);
		store.import_room_tags(source.room_tags()?, &mut report)?;
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
	if selected(plan, DataKind::UrlPreviews) {
		let source = database_source(&source);
		store.import_url_previews(source.url_previews()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomEvents) {
		let source = database_source(&source);
		store.import_room_events(source.room_events()?, &mut report)?;
	}
	if selected(plan, DataKind::Redactions) {
		let source = database_source(&source);
		store.import_redactions(source.redactions()?, &mut report)?;
	}
	if selected(plan, DataKind::SearchIndex) {
		store.rebuild_search_index(&mut report)?;
	}
	if selected(plan, DataKind::EventRelations) {
		let source = database_source(&source);
		store.import_event_relations(source.event_relations()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomState) {
		let source = database_source(&source);
		store.import_room_state(source.room_state()?, &mut report)?;
	}
	if selected(plan, DataKind::ForwardExtremities) {
		let source = database_source(&source);
		store.import_forward_extremities(source.forward_extremities()?, &mut report)?;
	}
	if selected(plan, DataKind::ForgottenRooms) {
		let source = database_source(&source);
		store.import_forgotten_rooms(source.forgotten_rooms()?, &mut report)?;
	}
	if selected(plan, DataKind::BlockedRooms) {
		let source = database_source(&source);
		store.import_blocked_rooms(source.blocked_rooms()?, &mut report)?;
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
	if selected(plan, DataKind::NotificationCounts) {
		let source = database_source(&source);
		store.import_notification_counts(source.notification_counts()?, &mut report)?;
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
	use std::{
		collections::{BTreeMap, HashMap},
		fs,
		io::Write,
		mem::size_of,
	};

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
				DataKind::ErasedUsers,
				DataKind::RegistrationTokens,
				DataKind::Profiles,
				DataKind::Threepids,
				DataKind::Devices,
				DataKind::DehydratedDevices,
				DataKind::DeviceKeys,
				DataKind::OneTimeKeys,
				DataKind::FallbackKeys,
				DataKind::CrossSigningKeys,
				DataKind::RoomKeyBackups,
				DataKind::ToDeviceMessages,
				DataKind::AccessTokens,
				DataKind::OpenIdTokens,
				DataKind::Pushers,
				DataKind::AccountData,
				DataKind::IgnoredUsers,
				DataKind::RoomTags,
				DataKind::Filters,
				DataKind::Presence,
				DataKind::UrlPreviews,
				DataKind::RoomEvents,
				DataKind::Redactions,
				DataKind::SearchIndex,
				DataKind::EventRelations,
				DataKind::RoomState,
				DataKind::ForwardExtremities,
				DataKind::BlockedRooms,
				DataKind::RoomAliases,
				DataKind::PublicRooms,
				DataKind::Receipts,
				DataKind::NotificationCounts,
				DataKind::ServerKeys,
			],
		);
		let report = execute_plan(&plan).expect("execute import");

		assert_eq!(report.users, 1);
		assert_eq!(report.locked_users, 1);
		assert_eq!(report.erased_users, 1);
		assert_eq!(report.registration_tokens, 1);
		assert_eq!(report.profiles, 1);
		assert_eq!(report.threepids, 1);
		assert_eq!(report.devices, 1);
		assert_eq!(report.dehydrated_devices, 1);
		assert_eq!(report.device_keys, 1);
		assert_eq!(report.one_time_keys, 1);
		assert_eq!(report.fallback_keys, 1);
		assert_eq!(report.cross_signing_keys, 3);
		assert_eq!(report.key_signatures, 2);
		assert_eq!(report.room_key_backup_versions, 1);
		assert_eq!(report.room_key_backups, 1);
		assert_eq!(report.to_device_messages, 1);
		assert_eq!(report.access_tokens, 1);
		assert_eq!(report.open_id_tokens, 1);
		assert_eq!(report.pushers, 1);
		assert_eq!(report.account_data, 2);
		assert_eq!(report.ignored_users, 1);
		assert_eq!(report.room_tags, 1);
		assert_eq!(report.filters, 1);
		assert_eq!(report.presence, 1);
		assert_eq!(report.url_previews, 1);
		assert_eq!(report.room_events, 5);
		assert_eq!(report.redactions, 1);
		assert_eq!(report.search_indexed_events, 1);
		assert_eq!(report.event_relations, 1);
		assert_eq!(report.thread_summaries, 1);
		assert_eq!(report.room_state, 2);
		assert_eq!(report.forward_extremities, 1);
		assert_eq!(report.skipped.get("forward_extremities.missing_event"), Some(&1));
		assert_eq!(report.blocked_rooms, 1);
		assert_eq!(report.room_aliases, 1);
		assert_eq!(report.public_rooms, 1);
		assert_eq!(report.receipts, 2);
		assert_eq!(report.notification_counts, 1);
		assert_eq!(report.server_keys, 1);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		let password = store
			.get_raw("userid_password", b"@alice:example.com")
			.expect("password query")
			.expect("password row");
		assert!(String::from_utf8_lossy(&password).starts_with("$synapse$bcrypt$"));
		assert_locked_user_imported(&store);
		assert_eq!(
			store
				.get_raw("userid_displayname", b"@alice:example.com")
				.expect("displayname query")
				.expect("displayname row"),
			b"Alice".to_vec()
		);
		assert_erased_users_imported(&store);
		assert_registration_tokens_imported(&store);
		assert_threepids_imported(&store);
		assert_dehydrated_devices_imported(&store);
		assert_ignored_users_imported(&store);
		assert_room_tags_imported(&store);
		assert_filters_imported(&store);
		assert_presence_imported(&store);
		assert_url_previews_imported(&store);
		assert_open_id_tokens_imported(&store);
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
		assert_redactions_imported(&store);
		assert_search_index_imported(&store);
		assert_event_relations_imported(&store);
		assert_room_state_imported(&store);
		assert_forward_extremities_imported(&store);
		assert_blocked_rooms_imported(&store);
		assert_room_aliases_imported(&store);
		assert_public_rooms_imported(&store);
		assert_e2ee_imported(&store);
		assert_room_key_backups_imported(&store);
		assert_to_device_messages_imported(&store);
		assert_receipts_imported(&store);
		assert_notification_counts_imported(&store);
		assert_pushers_imported(&store);
		assert_server_keys_imported(&store);
	}

	#[test]
	fn imports_users_from_legacy_sqlite_schema() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		seed_legacy_user_sqlite(&sqlite_path);
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::Users]);
		let report = execute_plan(&plan).expect("execute legacy user import");

		assert_eq!(report.users, 1);
		assert_eq!(report.locked_users, 0);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		assert!(
			store
				.get_raw("userid_password", b"@legacy:example.com")
				.expect("legacy password query")
				.is_some()
		);
		assert!(
			store
				.get_raw("userid_lock", b"@legacy:example.com")
				.expect("legacy lock query")
				.is_none()
		);
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
	fn forgotten_room_import_removes_left_membership_indexes() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		seed_forgotten_room_sqlite(&sqlite_path);
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(
			config_path,
			dest_path.clone(),
			vec![DataKind::RoomState, DataKind::ForgottenRooms],
		);
		let report = execute_plan(&plan).expect("execute forgotten room import");

		assert_eq!(report.room_state, 1);
		assert_eq!(report.forgotten_rooms, 1);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		let userroom =
			serialize_to_vec(("@alice:example.com", "!room:example.com")).expect("userroom key");
		let roomuser =
			serialize_to_vec(("!room:example.com", "@alice:example.com")).expect("roomuser key");
		assert!(
			store
				.get_raw("userroomid_leftstate", &userroom)
				.expect("left state query")
				.is_none()
		);
		assert!(
			store
				.get_raw("roomuserid_leftcount", &roomuser)
				.expect("left count query")
				.is_none()
		);
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
				appservice_id TEXT, user_type TEXT, shadow_banned INTEGER, locked INTEGER
			);
			INSERT INTO users VALUES (
				'@alice:example.com', '{password_hash}', 0, 1, NULL, NULL, 0, 1
			);
			CREATE TABLE erased_users (
				user_id TEXT NOT NULL
			);
			INSERT INTO erased_users VALUES (
				'@alice:example.com'
			);
			CREATE TABLE registration_tokens (
				token TEXT NOT NULL, uses_allowed INT, pending INT NOT NULL,
				completed INT NOT NULL, expiry_time BIGINT, UNIQUE(token)
			);
			INSERT INTO registration_tokens VALUES (
				'regtoken', 3, 0, 1, NULL
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
			CREATE TABLE dehydrated_devices (
				user_id TEXT NOT NULL PRIMARY KEY,
				device_id TEXT NOT NULL,
				device_data TEXT NOT NULL
			);
			INSERT INTO dehydrated_devices VALUES (
				'@alice:example.com', 'DEHY',
				'{{\"algorithm\":\"m.dehydration.v1.olm\",\"account\":\"cipher\"}}'
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
			CREATE TABLE open_id_tokens (
				token TEXT NOT NULL PRIMARY KEY,
				ts_valid_until_ms BIGINT NOT NULL,
				user_id TEXT NOT NULL
			);
			INSERT INTO open_id_tokens VALUES (
				'openid-token', 4102444800000, '@alice:example.com'
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
			CREATE TABLE ignored_users (
				ignorer_user_id TEXT NOT NULL, ignored_user_id TEXT NOT NULL
			);
			INSERT INTO ignored_users VALUES (
				'@alice:example.com', '@mallory:example.com'
			);
			CREATE TABLE room_account_data (
				user_id TEXT, room_id TEXT, account_data_type TEXT, content TEXT
			);
			INSERT INTO room_account_data VALUES (
				'@alice:example.com', '!room:example.com', 'm.tag', '{{\"tags\": {{}}}}'
			);
			CREATE TABLE room_tags (
				user_id TEXT NOT NULL, room_id TEXT NOT NULL, tag TEXT NOT NULL,
				content TEXT NOT NULL
			);
			INSERT INTO room_tags VALUES (
				'@alice:example.com', '!room:example.com', 'm.favourite',
				'{{\"order\":0.5}}'
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
			CREATE TABLE local_media_repository_url_cache (
				url TEXT, response_code INTEGER, etag TEXT, expires_ts BIGINT,
				og TEXT, media_id TEXT, download_ts BIGINT
			);
			INSERT INTO local_media_repository_url_cache VALUES (
				'https://example.com/post', 200, NULL, 999999,
				'{{
					\"og:title\":\"Example Post\",
					\"og:description\":\"Preview text\",
					\"og:image\":\"mxc://example.com/preview\",
					\"og:image:type\":\"image/png\",
					\"matrix:image:size\":512,
					\"og:image:width\":\"64\",
					\"og:image:height\":32,
					\"og:site_name\":\"Example\",
					\"article:author\":\"Alice\"
				}}',
				'preview-media', 123000
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
			INSERT INTO events VALUES (
				43, '$thread:example.com', '!room:example.com', 0, NULL
			);
			INSERT INTO events VALUES (
				44, '$redaction:example.com', '!room:example.com', 0, NULL
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
			INSERT INTO event_json VALUES (
				'$thread:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":3,
					\"type\":\"m.room.message\",
					\"content\":{{
						\"body\":\"thread reply\",
						\"msgtype\":\"m.text\",
						\"m.relates_to\":{{
							\"rel_type\":\"m.thread\",
							\"event_id\":\"$event:example.com\"
						}}
					}},
					\"prev_events\":[\"$event:example.com\"],
					\"depth\":2,
					\"auth_events\":[\"$create:example.com\"],
					\"hashes\":{{\"sha256\":\"thread\"}},
					\"signatures\":{{}}
				}}'
			);
			INSERT INTO event_json VALUES (
				'$redaction:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":4,
					\"type\":\"m.room.redaction\",
					\"content\":{{\"reason\":\"cleanup\"}},
					\"redacts\":\"$event:example.com\",
					\"prev_events\":[\"$thread:example.com\"],
					\"depth\":3,
					\"auth_events\":[\"$create:example.com\"],
					\"hashes\":{{\"sha256\":\"redaction\"}},
					\"signatures\":{{}}
				}}'
			);
			CREATE TABLE redactions (
				event_id TEXT NOT NULL, redacts TEXT NOT NULL,
				have_censored BOOL NOT NULL DEFAULT false, received_ts BIGINT
			);
			INSERT INTO redactions VALUES (
				'$redaction:example.com', '$event:example.com', 0, 4
			);
			CREATE TABLE event_relations (
				event_id TEXT NOT NULL, relates_to_id TEXT NOT NULL,
				relation_type TEXT NOT NULL, aggregation_key TEXT
			);
			INSERT INTO event_relations VALUES (
				'$thread:example.com', '$event:example.com', 'm.thread', NULL
			);
			CREATE TABLE event_forward_extremities (
				event_id TEXT NOT NULL, room_id TEXT NOT NULL
			);
			INSERT INTO event_forward_extremities VALUES (
				'$event:example.com', '!room:example.com'
			);
			INSERT INTO event_forward_extremities VALUES (
				'$missing:example.com', '!room:example.com'
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
			CREATE TABLE blocked_rooms (
				room_id TEXT NOT NULL, user_id TEXT NOT NULL
			);
			INSERT INTO blocked_rooms VALUES (
				'!blocked:example.com', '@alice:example.com'
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
			CREATE TABLE event_push_summary (
				user_id TEXT NOT NULL, room_id TEXT NOT NULL, notif_count BIGINT NOT NULL,
				stream_ordering BIGINT NOT NULL, unread_count BIGINT,
				last_receipt_stream_ordering BIGINT, thread_id TEXT
			);
			INSERT INTO event_push_summary VALUES (
				'@alice:example.com', '!room:example.com', 4, 50, 7, NULL, 'main'
			);
			CREATE TABLE event_push_actions (
				room_id TEXT NOT NULL, event_id TEXT NOT NULL, user_id TEXT NOT NULL,
				profile_tag VARCHAR(32), actions TEXT NOT NULL, topological_ordering BIGINT,
				stream_ordering BIGINT, notif SMALLINT, highlight SMALLINT, unread SMALLINT,
				thread_id TEXT
			);
			INSERT INTO event_push_actions VALUES (
				'!room:example.com', '$event:example.com', '@alice:example.com',
				'', '[]', 1, 42, 1, 1, 1, 'main'
			);
			"
		))
		.expect("seed sqlite");
	}

	fn seed_legacy_user_sqlite(path: &std::path::Path) {
		let conn = Connection::open(path).expect("sqlite");
		let password_hash = bcrypt::hash("secret", 4).expect("bcrypt hash");
		conn.execute_batch(&format!(
			"
			CREATE TABLE users (
				name TEXT, password_hash TEXT, deactivated INTEGER, admin INTEGER,
				appservice_id TEXT, user_type TEXT
			);
			INSERT INTO users VALUES (
				'@legacy:example.com', '{password_hash}', 0, 0, NULL, NULL
			);
			"
		))
		.expect("seed legacy user sqlite");
	}

	fn seed_forgotten_room_sqlite(path: &std::path::Path) {
		let conn = Connection::open(path).expect("sqlite");
		conn.execute_batch(
			"
			CREATE TABLE events (
				stream_ordering INTEGER, event_id TEXT, room_id TEXT, outlier INTEGER,
				rejection_reason TEXT
			);
			CREATE TABLE event_json (
				event_id TEXT, room_id TEXT, json TEXT
			);
			INSERT INTO events VALUES (
				1, '$leave:example.com', '!room:example.com', 0, NULL
			);
			INSERT INTO event_json VALUES (
				'$leave:example.com',
				'!room:example.com',
				'{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":1,
					\"type\":\"m.room.member\",
					\"state_key\":\"@alice:example.com\",
					\"content\":{\"membership\":\"leave\"},
					\"prev_events\":[],
					\"depth\":1,
					\"auth_events\":[],
					\"hashes\":{\"sha256\":\"leave\"},
					\"signatures\":{}
				}'
			);
			CREATE TABLE current_state_events (
				event_id TEXT NOT NULL, room_id TEXT NOT NULL, type TEXT NOT NULL,
				state_key TEXT NOT NULL, membership TEXT
			);
			INSERT INTO current_state_events VALUES (
				'$leave:example.com', '!room:example.com', 'm.room.member',
				'@alice:example.com', 'leave'
			);
			CREATE TABLE room_memberships (
				event_id TEXT NOT NULL, user_id TEXT NOT NULL, sender TEXT NOT NULL,
				room_id TEXT NOT NULL, membership TEXT NOT NULL, forgotten INTEGER DEFAULT 0
			);
			INSERT INTO room_memberships VALUES (
				'$leave:example.com', '@alice:example.com', '@alice:example.com',
				'!room:example.com', 'leave', 1
			);
			INSERT INTO room_memberships VALUES (
				'$old:example.com', '@bob:example.com', '@bob:example.com',
				'!room:example.com', 'leave', 1
			);
			INSERT INTO room_memberships VALUES (
				'$new:example.com', '@bob:example.com', '@bob:example.com',
				'!room:example.com', 'join', 0
			);
			",
		)
		.expect("seed forgotten room sqlite");
	}

	fn assert_erased_users_imported(store: &ContinuwuityStore) {
		assert!(
			store
				.get_raw("userid_erased", b"@alice:example.com")
				.expect("erased user query")
				.is_some()
		);
	}

	fn assert_locked_user_imported(store: &ContinuwuityStore) {
		let lock = store
			.get_raw("userid_lock", b"@alice:example.com")
			.expect("locked user query")
			.expect("locked user row");
		let lock: serde_json::Value = serde_json::from_slice(&lock).expect("locked user json");
		assert_eq!(lock["suspended"], true);
		assert_eq!(lock["suspended_at"], 0);
		assert_eq!(lock["suspended_by"], "@synapse-migration:example.com");
	}

	fn assert_registration_tokens_imported(store: &ContinuwuityStore) {
		let token = store
			.get_raw("registrationtoken_info", b"regtoken")
			.expect("registration token query")
			.expect("registration token row");
		let token: serde_json::Value =
			serde_json::from_slice(&token).expect("registration token json");
		assert_eq!(token["creator"], "@synapse-migration:example.com");
		assert_eq!(token["uses"], 1);
		assert_eq!(token["expires"]["AfterUses"], 3);
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

	fn assert_dehydrated_devices_imported(store: &ContinuwuityStore) {
		let device = store
			.get_raw("userid_dehydrateddevice", b"@alice:example.com")
			.expect("dehydrated device query")
			.expect("dehydrated device row");
		let device: serde_json::Value =
			serde_json::from_slice(&device).expect("dehydrated device json");
		assert_eq!(device["device_id"], "DEHY");
		assert_eq!(device["device_data"]["account"], "cipher");
	}

	fn assert_ignored_users_imported(store: &ContinuwuityStore) {
		let index_key = serialize_to_vec((
			Option::<&str>::None,
			"@alice:example.com",
			"m.ignored_user_list",
		))
		.expect("ignored users index key");
		let data_key = store
			.get_raw("roomusertype_roomuserdataid", &index_key)
			.expect("ignored users index query")
			.expect("ignored users index row");
		let event = store
			.get_raw("roomuserdataid_accountdata", &data_key)
			.expect("ignored users event query")
			.expect("ignored users event row");
		let event: serde_json::Value =
			serde_json::from_slice(&event).expect("ignored users event json");

		assert_eq!(event["type"], "m.ignored_user_list");
		assert!(event["content"]["ignored_users"]["@mallory:example.com"].is_object());
	}

	fn assert_room_tags_imported(store: &ContinuwuityStore) {
		let index_key =
			serialize_to_vec(("!room:example.com", "@alice:example.com", "m.tag")).expect("tag index key");
		let data_key = store
			.get_raw("roomusertype_roomuserdataid", &index_key)
			.expect("room tag index query")
			.expect("room tag index row");
		let event = store
			.get_raw("roomuserdataid_accountdata", &data_key)
			.expect("room tag event query")
			.expect("room tag event row");
		let event: serde_json::Value = serde_json::from_slice(&event).expect("room tag event json");

		assert_eq!(event["type"], "m.tag");
		assert_eq!(event["content"]["tags"]["m.favourite"]["order"], 0.5);
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

	fn assert_url_previews_imported(store: &ContinuwuityStore) {
		let preview = store
			.get_raw("url_previews", b"https://example.com/post")
			.expect("url preview query")
			.expect("url preview row");
		let fields = preview.split(|&byte| byte == 0xFF).collect::<Vec<_>>();

		assert_eq!(fields[1], b"Example Post");
		assert_eq!(fields[2], b"Preview text");
		assert_eq!(fields[3], b"mxc://example.com/preview");
		assert_eq!(
			usize::from_be_bytes(fields[4].try_into().expect("image size bytes")),
			512
		);
		assert_eq!(
			u32::from_be_bytes(fields[5].try_into().expect("image width bytes")),
			64
		);
		assert_eq!(
			u32::from_be_bytes(fields[6].try_into().expect("image height bytes")),
			32
		);
		assert_eq!(fields[14], b"Example");
		assert_eq!(fields[15], b"image/png");
		let additional: BTreeMap<String, String> =
			serde_json::from_slice(fields[18]).expect("url preview additional json");
		assert_eq!(additional.get("article:author").map(String::as_str), Some("Alice"));
	}

	fn assert_open_id_tokens_imported(store: &ContinuwuityStore) {
		let token = store
			.get_raw("openidtoken_expiresatuserid", b"openid-token")
			.expect("openid token query")
			.expect("openid token row");
		let (expires_at, user_id) = token.split_at(size_of::<u64>());

		assert_eq!(
			u64::from_be_bytes(expires_at.try_into().expect("openid expiry bytes")),
			4102444800000
		);
		assert_eq!(user_id, b"@alice:example.com");
	}

	fn assert_redactions_imported(store: &ContinuwuityStore) {
		let root_pduid = store
			.get_raw("eventid_pduid", b"$event:example.com")
			.expect("root pduid query")
			.expect("root pduid row");
		let root = store
			.get_raw("pduid_pdu", &root_pduid)
			.expect("root pdu query")
			.expect("root pdu row");
		let root: serde_json::Value = serde_json::from_slice(&root).expect("root pdu json");
		assert!(root["content"]["body"].is_null());
		assert!(root["content"]["msgtype"].is_null());
		assert_eq!(
			root["unsigned"]["redacted_because"]["event_id"],
			"$redaction:example.com"
		);
	}

	fn assert_event_relations_imported(store: &ContinuwuityStore) {
		let mut relation_key = 42_u64.to_be_bytes().to_vec();
		relation_key.extend_from_slice(&43_u64.to_be_bytes());
		assert!(
			store
				.get_raw("tofrom_relation", &relation_key)
				.expect("relation query")
				.is_some()
		);

		let root_pduid = store
			.get_raw("eventid_pduid", b"$event:example.com")
			.expect("root pduid query")
			.expect("root pduid row");
		let participants = store
			.get_raw("threadid_userids", &root_pduid)
			.expect("thread participants query")
			.expect("thread participants row");
		assert_eq!(participants, b"@alice:example.com".to_vec());

		let root = store
			.get_raw("pduid_pdu", &root_pduid)
			.expect("root pdu query")
			.expect("root pdu row");
		let root: serde_json::Value = serde_json::from_slice(&root).expect("root pdu json");
		let thread = &root["unsigned"]["m.relations"]["m.thread"];
		assert_eq!(thread["count"], 1);
		assert_eq!(thread["current_user_participated"], true);
		assert_eq!(thread["latest_event"]["body"], "thread reply");
	}

	fn assert_search_index_imported(store: &ContinuwuityStore) {
		let root_pduid = store
			.get_raw("eventid_pduid", b"$event:example.com")
			.expect("root pduid query")
			.expect("root pduid row");
		let mut root_key = root_pduid[..8].to_vec();
		root_key.extend_from_slice(b"hi");
		root_key.push(0xFF);
		root_key.extend_from_slice(&root_pduid);
		assert!(
			store
				.get_raw("tokenids", &root_key)
				.expect("search token query")
				.is_none()
		);

		let thread_pduid = store
			.get_raw("eventid_pduid", b"$thread:example.com")
			.expect("thread pduid query")
			.expect("thread pduid row");
		let mut thread_key = thread_pduid[..8].to_vec();
		thread_key.extend_from_slice(b"thread");
		thread_key.push(0xFF);
		thread_key.extend_from_slice(&thread_pduid);
		assert!(
			store
				.get_raw("tokenids", &thread_key)
				.expect("search token query")
				.is_some()
		);
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

	fn assert_forward_extremities_imported(store: &ContinuwuityStore) {
		let key =
			serialize_to_vec(("!room:example.com", "$event:example.com")).expect("leaf key");
		assert_eq!(
			store
				.get_raw("roomid_pduleaves", &key)
				.expect("forward extremity query")
				.expect("forward extremity row"),
			b"$event:example.com".to_vec()
		);
	}

	fn assert_blocked_rooms_imported(store: &ContinuwuityStore) {
		assert!(
			store
				.get_raw("bannedroomids", b"!blocked:example.com")
				.expect("blocked room query")
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

	fn assert_notification_counts_imported(store: &ContinuwuityStore) {
		let userroom =
			serialize_to_vec(("@alice:example.com", "!room:example.com")).expect("userroom key");
		assert_eq!(
			store
				.get_raw("userroomid_notificationcount", &userroom)
				.expect("notification count query")
				.expect("notification count row"),
			4_u64.to_be_bytes().to_vec()
		);
		assert_eq!(
			store
				.get_raw("userroomid_highlightcount", &userroom)
				.expect("highlight count query")
				.expect("highlight count row"),
			1_u64.to_be_bytes().to_vec()
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
