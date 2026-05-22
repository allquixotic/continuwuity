use std::{fs, path::PathBuf};

use conduwuit_core::config::Config;

use crate::{
	Error, Result,
	config::{SynapseDatabase, SynapseInstall},
	plan::{DataKind, MigrationPlan},
	postgres::PostgresSource,
	sqlite::{
		SqliteSource, SynapseAccessToken, SynapseAccountData, SynapseAccountValidity,
		SynapseApplicationServiceRoom, SynapseApplicationServiceState,
		SynapseApplicationServiceStreamPosition, SynapseApplicationServiceTxn,
		SynapseBlockedRoom, SynapseCrossSigningKey, SynapseDehydratedDevice, SynapseDeletedPusher, SynapseDevice,
		SynapseDeviceAuthProvider, SynapseDeviceFederationInbox, SynapseDeviceFederationOutbox,
		SynapseDeviceKey, SynapseDeviceListRemoteExtremity, SynapseDeviceListRemoteResync,
		SynapseErasedUser, SynapseEventExpiry,
		SynapseEventRelation, SynapseEventReport, SynapseEventTransaction, SynapseFallbackKey,
		SynapseFilter,
		SynapseForgottenRoom, SynapseForwardExtremity, SynapseIgnoredUser, SynapseKeySignature,
		SynapseLoginToken, SynapseMedia, SynapseMediaThumbnail, SynapseMonthlyActiveUser, SynapseNotificationCount,
		SynapseOneTimeKey, SynapseOpenIdToken, SynapsePresence, SynapseProfile, SynapsePublicRoom,
		SynapsePusher, SynapsePushRule, SynapseRatelimitOverride, SynapseReceipt, SynapseRedaction, SynapseRegistrationToken,
		SynapseRoomAlias, SynapseRoomKeyBackup, SynapseRoomKeyBackupVersion, SynapseRoomRetention,
		SynapseRoomState, SynapseRoomTag, SynapseServerKey, SynapseThreepid, SynapseToDeviceMessage,
		SynapseUiAuthSession, SynapseUiAuthSessionCredential, SynapseUiAuthSessionIp, SynapseUrlPreview,
		SynapseUser, SynapseUserExternalId, SynapseUserSignatureStream,
	},
	store::{ContinuwuityStore, ImportReport},
};

const SUPPORTED_DATABASE_IMPORTS: &[DataKind] = &[
	DataKind::Users,
	DataKind::ErasedUsers,
	DataKind::AccountValidity,
	DataKind::RatelimitOverrides,
	DataKind::MonthlyActiveUsers,
	DataKind::RegistrationTokens,
	DataKind::Profiles,
	DataKind::Threepids,
	DataKind::UserExternalIds,
	DataKind::Devices,
	DataKind::DeviceAuthProviders,
	DataKind::DehydratedDevices,
	DataKind::DeviceKeys,
	DataKind::RemoteDeviceKeys,
	DataKind::OneTimeKeys,
	DataKind::FallbackKeys,
	DataKind::CrossSigningKeys,
	DataKind::RoomKeyBackups,
	DataKind::ToDeviceMessages,
	DataKind::DeviceFederationQueues,
	DataKind::AccessTokens,
	DataKind::OpenIdTokens,
	DataKind::LoginTokens,
	DataKind::UiAuthSessions,
	DataKind::AccountData,
	DataKind::PushRules,
	DataKind::IgnoredUsers,
	DataKind::RoomTags,
	DataKind::Filters,
	DataKind::Presence,
	DataKind::Media,
	DataKind::MediaThumbnails,
	DataKind::UrlPreviews,
	DataKind::RoomEvents,
	DataKind::OutlierEvents,
	DataKind::BackfilledEvents,
	DataKind::EventEdges,
	DataKind::SoftFailedEvents,
	DataKind::Redactions,
	DataKind::EventReports,
	DataKind::RoomState,
	DataKind::RoomRetention,
	DataKind::EventExpiry,
	DataKind::EventRelations,
	DataKind::EventTransactions,
	DataKind::ForwardExtremities,
	DataKind::ForgottenRooms,
	DataKind::BlockedRooms,
	DataKind::RoomAliases,
	DataKind::PublicRooms,
	DataKind::Receipts,
	DataKind::NotificationCounts,
	DataKind::Pushers,
	DataKind::DeletedPushers,
	DataKind::AppserviceDelivery,
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

	fn account_validity(&self) -> Result<Vec<SynapseAccountValidity>> {
		delegate_source!(self, account_validity())
	}

	fn ratelimit_overrides(&self) -> Result<Vec<SynapseRatelimitOverride>> {
		delegate_source!(self, ratelimit_overrides())
	}

	fn monthly_active_users(&self) -> Result<Vec<SynapseMonthlyActiveUser>> {
		delegate_source!(self, monthly_active_users())
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

	fn user_external_ids(&self) -> Result<Vec<SynapseUserExternalId>> {
		delegate_source!(self, user_external_ids())
	}

	fn devices(&self) -> Result<Vec<SynapseDevice>> { delegate_source!(self, devices()) }

	fn device_auth_providers(&self) -> Result<Vec<SynapseDeviceAuthProvider>> {
		delegate_source!(self, device_auth_providers())
	}

	fn dehydrated_devices(&self) -> Result<Vec<SynapseDehydratedDevice>> {
		delegate_source!(self, dehydrated_devices())
	}

	fn device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		delegate_source!(self, device_keys())
	}

	fn remote_device_keys(&self) -> Result<Vec<SynapseDeviceKey>> {
		delegate_source!(self, remote_device_keys())
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

	fn device_federation_inbox(&self) -> Result<Vec<SynapseDeviceFederationInbox>> {
		delegate_source!(self, device_federation_inbox())
	}

	fn device_federation_outbox(&self) -> Result<Vec<SynapseDeviceFederationOutbox>> {
		delegate_source!(self, device_federation_outbox())
	}

	fn device_list_remote_extremities(&self) -> Result<Vec<SynapseDeviceListRemoteExtremity>> {
		delegate_source!(self, device_list_remote_extremities())
	}

	fn device_list_remote_resync(&self) -> Result<Vec<SynapseDeviceListRemoteResync>> {
		delegate_source!(self, device_list_remote_resync())
	}

	fn user_signature_stream(&self) -> Result<Vec<SynapseUserSignatureStream>> {
		delegate_source!(self, user_signature_stream())
	}

	fn access_tokens(&self) -> Result<Vec<SynapseAccessToken>> {
		delegate_source!(self, access_tokens())
	}

	fn open_id_tokens(&self) -> Result<Vec<SynapseOpenIdToken>> {
		delegate_source!(self, open_id_tokens())
	}

	fn login_tokens(&self) -> Result<Vec<SynapseLoginToken>> {
		delegate_source!(self, login_tokens())
	}

	fn ui_auth_sessions(&self) -> Result<Vec<SynapseUiAuthSession>> {
		delegate_source!(self, ui_auth_sessions())
	}

	fn ui_auth_session_credentials(&self) -> Result<Vec<SynapseUiAuthSessionCredential>> {
		delegate_source!(self, ui_auth_session_credentials())
	}

	fn ui_auth_session_ips(&self) -> Result<Vec<SynapseUiAuthSessionIp>> {
		delegate_source!(self, ui_auth_session_ips())
	}

	fn account_data(&self) -> Result<Vec<SynapseAccountData>> {
		delegate_source!(self, account_data())
	}

	fn push_rules(&self) -> Result<Vec<SynapsePushRule>> {
		delegate_source!(self, push_rules())
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
		backup_media_store: Option<&std::path::Path>,
		server_name: &str,
	) -> Result<Vec<SynapseMedia>> {
		delegate_source!(self, media(media_store, backup_media_store, server_name))
	}

	fn media_thumbnails(
		&self,
		media_store: &std::path::Path,
		backup_media_store: Option<&std::path::Path>,
		server_name: &str,
	) -> Result<Vec<SynapseMediaThumbnail>> {
		delegate_source!(self, media_thumbnails(media_store, backup_media_store, server_name))
	}

	fn url_previews(&self) -> Result<Vec<SynapseUrlPreview>> {
		delegate_source!(self, url_previews())
	}

	fn forward_extremities(&self) -> Result<Vec<SynapseForwardExtremity>> {
		delegate_source!(self, forward_extremities())
	}

	fn redactions(&self) -> Result<Vec<SynapseRedaction>> {
		delegate_source!(self, redactions())
	}

	fn event_reports(&self) -> Result<Vec<SynapseEventReport>> {
		delegate_source!(self, event_reports())
	}

	fn event_relations(&self) -> Result<Vec<SynapseEventRelation>> {
		delegate_source!(self, event_relations())
	}

	fn event_transactions(&self) -> Result<Vec<SynapseEventTransaction>> {
		delegate_source!(self, event_transactions())
	}

	fn room_state(&self) -> Result<Vec<SynapseRoomState>> {
		delegate_source!(self, room_state())
	}

	fn room_retention(&self) -> Result<Vec<SynapseRoomRetention>> {
		delegate_source!(self, room_retention())
	}

	fn event_expiry(&self) -> Result<Vec<SynapseEventExpiry>> {
		delegate_source!(self, event_expiry())
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

	fn deleted_pushers(&self) -> Result<Vec<SynapseDeletedPusher>> {
		delegate_source!(self, deleted_pushers())
	}

	fn application_service_txns(&self) -> Result<Vec<SynapseApplicationServiceTxn>> {
		delegate_source!(self, application_service_txns())
	}

	fn application_service_state(&self) -> Result<Vec<SynapseApplicationServiceState>> {
		delegate_source!(self, application_service_state())
	}

	fn appservice_stream_position(
		&self,
	) -> Result<Vec<SynapseApplicationServiceStreamPosition>> {
		delegate_source!(self, appservice_stream_position())
	}

	fn appservice_room_list(&self) -> Result<Vec<SynapseApplicationServiceRoom>> {
		delegate_source!(self, appservice_room_list())
	}

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
	store.initialize_global_metadata()?;
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
	if selected(plan, DataKind::AccountValidity) {
		let source = database_source(&source);
		store.import_account_validity(source.account_validity()?, &mut report)?;
	}
	if selected(plan, DataKind::RatelimitOverrides) {
		let source = database_source(&source);
		store.import_ratelimit_overrides(source.ratelimit_overrides()?, &mut report)?;
	}
	if selected(plan, DataKind::MonthlyActiveUsers) {
		let source = database_source(&source);
		store.import_monthly_active_users(source.monthly_active_users()?, &mut report)?;
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
	if selected(plan, DataKind::UserExternalIds) {
		let source = database_source(&source);
		store.import_user_external_ids(source.user_external_ids()?, &mut report)?;
	}
	if selected(plan, DataKind::Devices) {
		let source = database_source(&source);
		store.import_devices(source.devices()?, &mut report)?;
	}
	if selected(plan, DataKind::DeviceAuthProviders) {
		let source = database_source(&source);
		store.import_device_auth_providers(source.device_auth_providers()?, &mut report)?;
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
	if selected(plan, DataKind::RemoteDeviceKeys) {
		let source = database_source(&source);
		store.import_remote_device_keys(source.remote_device_keys()?, &mut report)?;
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
	if selected(plan, DataKind::DeviceFederationQueues) {
		let source = database_source(&source);
		store.import_device_federation_queues(
			source.device_federation_inbox()?,
			source.device_federation_outbox()?,
			source.device_list_remote_extremities()?,
			source.device_list_remote_resync()?,
			source.user_signature_stream()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::AccessTokens) {
		let source = database_source(&source);
		store.import_access_tokens(source.access_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::OpenIdTokens) {
		let source = database_source(&source);
		store.import_open_id_tokens(source.open_id_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::LoginTokens) {
		let source = database_source(&source);
		store.import_login_tokens(source.login_tokens()?, &mut report)?;
	}
	if selected(plan, DataKind::UiAuthSessions) {
		let source = database_source(&source);
		store.import_ui_auth_sessions(
			source.ui_auth_sessions()?,
			source.ui_auth_session_credentials()?,
			source.ui_auth_session_ips()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::Pushers) {
		let source = database_source(&source);
		store.import_pushers(source.pushers()?, &mut report)?;
	}
	if selected(plan, DataKind::DeletedPushers) {
		let source = database_source(&source);
		store.import_deleted_pushers(source.deleted_pushers()?, &mut report)?;
	}
	if selected(plan, DataKind::AppserviceDelivery) {
		let source = database_source(&source);
		store.import_appservice_delivery(
			source.application_service_txns()?,
			source.application_service_state()?,
			source.appservice_stream_position()?,
			source.appservice_room_list()?,
			&mut report,
		)?;
	}
	if selected(plan, DataKind::AccountData) {
		let source = database_source(&source);
		store.import_account_data(source.account_data()?, &mut report)?;
	}
	if selected(plan, DataKind::PushRules) {
		let source = database_source(&source);
		store.import_push_rules(source.push_rules()?, &mut report)?;
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
	if selected(plan, DataKind::MediaThumbnails) {
		let source = database_source(&source);
		import_media_thumbnails(&plan.synapse, source, &store, &mut report)?;
	}
	if selected(plan, DataKind::UrlPreviews) {
		let source = database_source(&source);
		store.import_url_previews(source.url_previews()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomEvents) {
		let source = database_source(&source);
		source.import_room_events(&mut store, &mut report)?;
	}
	if selected(plan, DataKind::OutlierEvents) {
		let source = database_source(&source);
		source.import_outlier_events(&store, &mut report)?;
	}
	if selected(plan, DataKind::BackfilledEvents) {
		let source = database_source(&source);
		source.import_backfilled_events(&mut store, &mut report)?;
	}
	if selected(plan, DataKind::EventEdges) {
		let source = database_source(&source);
		source.import_event_edges(&store, &mut report)?;
	}
	if selected(plan, DataKind::SoftFailedEvents) {
		let source = database_source(&source);
		source.import_soft_failed_events(&store, &mut report)?;
	}
	if selected(plan, DataKind::Redactions) {
		let source = database_source(&source);
		store.import_redactions(source.redactions()?, &mut report)?;
	}
	if selected(plan, DataKind::EventReports) {
		let source = database_source(&source);
		store.import_event_reports(source.event_reports()?, &mut report)?;
	}
	if selected(plan, DataKind::SearchIndex) {
		store.rebuild_search_index(&mut report)?;
	}
	if selected(plan, DataKind::EventRelations) {
		let source = database_source(&source);
		store.import_event_relations(source.event_relations()?, &mut report)?;
	}
	if selected(plan, DataKind::EventTransactions) {
		let source = database_source(&source);
		store.import_event_transactions(source.event_transactions()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomState) {
		let source = database_source(&source);
		store.import_room_state(source.room_state()?, &mut report)?;
	}
	if selected(plan, DataKind::RoomRetention) {
		let source = database_source(&source);
		store.import_room_retention(source.room_retention()?, &mut report)?;
	}
	if selected(plan, DataKind::EventExpiry) {
		let source = database_source(&source);
		store.import_event_expiry(source.event_expiry()?, &mut report)?;
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

	store.import_media(
		source.media(media_store, synapse.backup_media_store_path.as_deref(), server_name)?,
		report,
	)
}

fn import_media_thumbnails(
	synapse: &SynapseInstall,
	source: &DatabaseSource,
	store: &ContinuwuityStore,
	report: &mut ImportReport,
) -> Result<()> {
	let Some(media_store) = &synapse.media_store_path else {
		return Err(Error::Message(
			"media-thumbnails import selected but Synapse media_store_path is unknown".to_owned(),
		));
	};
	let Some(server_name) = &synapse.server_name else {
		return Err(Error::Message(
			"media-thumbnails import selected but Synapse server_name is unknown".to_owned(),
		));
	};

	store.import_media_thumbnails(
		source.media_thumbnails(
			media_store,
			synapse.backup_media_store_path.as_deref(),
			server_name,
		)?,
		report,
	)
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

impl DatabaseSource {
	fn import_room_events(
		&self,
		store: &mut ContinuwuityStore,
		report: &mut ImportReport,
	) -> Result<()> {
		match self {
			| Self::Sqlite(source) => store.import_room_events(source.room_events()?, report),
			| Self::Postgres(source) =>
				source.for_each_room_events_batch(|events| store.import_room_events(events, report)),
		}
	}

	fn import_outlier_events(
		&self,
		store: &ContinuwuityStore,
		report: &mut ImportReport,
	) -> Result<()> {
		match self {
			| Self::Sqlite(source) => store.import_outlier_events(source.outlier_events()?, report),
			| Self::Postgres(source) => source
				.for_each_outlier_events_batch(|events| store.import_outlier_events(events, report)),
		}
	}

	fn import_backfilled_events(
		&self,
		store: &mut ContinuwuityStore,
		report: &mut ImportReport,
	) -> Result<()> {
		match self {
			| Self::Sqlite(source) => store.import_backfilled_events(source.backfilled_events()?, report),
			| Self::Postgres(source) => source
				.for_each_backfilled_events_batch(|events| store.import_backfilled_events(events, report)),
		}
	}

	fn import_event_edges(
		&self,
		store: &ContinuwuityStore,
		report: &mut ImportReport,
	) -> Result<()> {
		match self {
			| Self::Sqlite(source) => store.import_event_edges(source.event_edges()?, report),
			| Self::Postgres(source) =>
				source.for_each_event_edges_batch(|edges| store.import_event_edges(edges, report)),
		}
	}

	fn import_soft_failed_events(
		&self,
		store: &ContinuwuityStore,
		report: &mut ImportReport,
	) -> Result<()> {
		match self {
			| Self::Sqlite(source) =>
				store.import_soft_failed_events(source.soft_failed_events()?, report),
			| Self::Postgres(source) => source.for_each_soft_failed_events_batch(|events| {
				store.import_soft_failed_events(events, report)
			}),
		}
	}
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
				DataKind::AccountValidity,
				DataKind::RatelimitOverrides,
				DataKind::MonthlyActiveUsers,
				DataKind::RegistrationTokens,
				DataKind::Profiles,
				DataKind::Threepids,
				DataKind::UserExternalIds,
				DataKind::Devices,
				DataKind::DeviceAuthProviders,
				DataKind::DehydratedDevices,
				DataKind::DeviceKeys,
				DataKind::RemoteDeviceKeys,
				DataKind::OneTimeKeys,
				DataKind::FallbackKeys,
				DataKind::CrossSigningKeys,
				DataKind::RoomKeyBackups,
				DataKind::ToDeviceMessages,
				DataKind::DeviceFederationQueues,
				DataKind::AccessTokens,
				DataKind::OpenIdTokens,
				DataKind::LoginTokens,
				DataKind::UiAuthSessions,
				DataKind::Pushers,
				DataKind::DeletedPushers,
				DataKind::AppserviceDelivery,
				DataKind::AccountData,
				DataKind::PushRules,
				DataKind::IgnoredUsers,
				DataKind::RoomTags,
				DataKind::Filters,
				DataKind::Presence,
				DataKind::UrlPreviews,
				DataKind::RoomEvents,
				DataKind::OutlierEvents,
				DataKind::BackfilledEvents,
				DataKind::EventEdges,
				DataKind::Redactions,
				DataKind::EventReports,
				DataKind::SearchIndex,
				DataKind::EventRelations,
				DataKind::EventTransactions,
				DataKind::RoomState,
				DataKind::RoomRetention,
				DataKind::EventExpiry,
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
		assert_eq!(report.suspended_users, 1);
		assert_eq!(report.erased_users, 1);
		assert_eq!(report.account_validity, 2);
		assert_eq!(report.skipped.get("account_validity.invalid_user_id"), Some(&1));
		assert_eq!(
			report.skipped.get("account_validity.invalid_expiration"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("account_validity.invalid_token_used"),
			Some(&1)
		);
		assert_eq!(report.ratelimit_overrides, 2);
		assert_eq!(
			report.skipped.get("ratelimit_overrides.invalid_user_id"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("ratelimit_overrides.invalid_limit"),
			Some(&1)
		);
		assert_eq!(report.monthly_active_users, 1);
		assert_eq!(
			report.skipped.get("monthly_active_users.invalid_user_id"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("monthly_active_users.invalid_timestamp"),
			Some(&1)
		);
		assert_eq!(report.registration_tokens, 1);
		assert_eq!(report.profiles, 1);
		assert_eq!(report.threepids, 1);
		assert_eq!(report.user_external_ids, 1);
		assert_eq!(report.skipped.get("user_external_ids.invalid"), Some(&2));
		assert_eq!(report.devices, 2);
		assert_eq!(report.device_auth_providers, 1);
		assert_eq!(
			report.skipped.get("device_auth_providers.invalid"),
			Some(&1)
		);
		assert_eq!(report.dehydrated_devices, 1);
		assert_eq!(report.device_keys, 1);
		assert_eq!(report.remote_device_keys, 1);
		assert_eq!(report.one_time_keys, 1);
		assert_eq!(report.fallback_keys, 1);
		assert_eq!(report.cross_signing_keys, 3);
		assert_eq!(report.key_signatures, 2);
		assert_eq!(report.room_key_backup_versions, 1);
		assert_eq!(report.room_key_backups, 1);
		assert_eq!(report.to_device_messages, 1);
		assert_eq!(report.device_federation_inbox, 1);
		assert_eq!(report.device_federation_outbox, 1);
		assert_eq!(report.device_list_remote_extremities, 1);
		assert_eq!(report.device_list_remote_resync, 1);
		assert_eq!(report.user_signature_stream, 1);
		assert_eq!(
			report.skipped.get("device_federation_inbox.invalid"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("device_federation_outbox.invalid_stream_id"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("device_list_remote_extremities.invalid"),
			Some(&1)
		);
		assert_eq!(
			report.skipped.get("device_list_remote_resync.invalid"),
			Some(&1)
		);
		assert_eq!(report.skipped.get("user_signature_stream.invalid"), Some(&1));
		assert_eq!(report.access_tokens, 1);
		assert_eq!(report.open_id_tokens, 1);
		assert_eq!(report.login_tokens, 1);
		assert_eq!(report.skipped.get("login_tokens.expired"), Some(&1));
		assert_eq!(report.skipped.get("login_tokens.used"), Some(&1));
		assert_eq!(report.ui_auth_sessions, 1);
		assert_eq!(report.ui_auth_session_credentials, 1);
		assert_eq!(report.ui_auth_session_ips, 1);
		assert_eq!(report.skipped.get("ui_auth_sessions.invalid"), Some(&1));
		assert_eq!(
			report.skipped.get("ui_auth_session_credentials.invalid"),
			Some(&1)
		);
		assert_eq!(report.skipped.get("ui_auth_session_ips.invalid"), Some(&1));
		assert_eq!(report.pushers, 1);
		assert_eq!(report.deleted_pushers, 1);
		assert_eq!(
			report.skipped.get("deleted_pushers.invalid_stream_id"),
			Some(&1)
		);
		assert_eq!(report.skipped.get("deleted_pushers.invalid"), Some(&1));
		assert_eq!(report.appservice_txns, 1);
		assert_eq!(report.appservice_state, 1);
		assert_eq!(report.appservice_stream_positions, 1);
		assert_eq!(report.appservice_room_list, 1);
		assert_eq!(report.skipped.get("appservice_txns.invalid_txn_id"), Some(&1));
		assert_eq!(report.skipped.get("appservice_txns.invalid"), Some(&1));
		assert_eq!(report.skipped.get("appservice_state.invalid"), Some(&1));
		assert_eq!(
			report.skipped.get("appservice_stream_position.invalid"),
			Some(&1)
		);
		assert_eq!(report.skipped.get("appservice_room_list.invalid"), Some(&1));
		assert_eq!(report.account_data, 2);
		assert_eq!(report.push_rules, 3);
		assert_eq!(report.skipped.get("push_rules.invalid_actions"), Some(&1));
		assert_eq!(report.ignored_users, 1);
		assert_eq!(report.room_tags, 1);
		assert_eq!(report.filters, 1);
		assert_eq!(report.presence, 1);
		assert_eq!(report.url_previews, 1);
		assert_eq!(report.room_events, 5);
		assert_eq!(report.outlier_events, 1);
		assert_eq!(report.backfilled_events, 1);
		assert_eq!(report.event_edges, 2);
		assert_eq!(report.skipped.get("event_edges.missing_event"), Some(&1));
		assert_eq!(report.redactions, 1);
		assert_eq!(report.search_indexed_events, 2);
		assert_eq!(report.event_relations, 1);
		assert_eq!(report.event_transactions, 2);
		assert_eq!(report.skipped.get("event_transactions.invalid_id"), Some(&1));
		assert_eq!(report.skipped.get("event_transactions.missing_event"), Some(&1));
		assert_eq!(report.thread_summaries, 1);
		assert_eq!(report.room_state, 2);
		assert_eq!(report.room_retention, 1);
		assert_eq!(report.event_expiry, 1);
		assert_eq!(report.skipped.get("room_retention.invalid_id"), Some(&1));
		assert_eq!(report.skipped.get("room_retention.invalid_lifetime"), Some(&1));
		assert_eq!(report.skipped.get("event_expiry.invalid_event_id"), Some(&1));
		assert_eq!(report.skipped.get("event_expiry.invalid_expiry_ts"), Some(&1));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("room_retention metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("account_validity metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("ratelimit_override metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("monthly_active_users metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("deleted_pushers tombstones were preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("appservice delivery metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("UI-auth session metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("expired account")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("user_external_ids SSO metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("device_auth_providers SSO metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("device-list federation queue metadata was preserved")));
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("event_expiry metadata was preserved")));
		assert_eq!(report.event_reports, 1);
		assert_eq!(report.skipped.get("event_reports.invalid_id"), Some(&1));
		assert_eq!(
			report.skipped.get("event_reports.invalid_reference"),
			Some(&1)
		);
		assert!(report
			.warnings
			.iter()
			.any(|warning| warning.contains("event_reports were preserved")));
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
		assert_account_validity_imported(&store);
		assert_admin_metadata_imported(&store);
		assert_registration_tokens_imported(&store);
		assert_threepids_imported(&store);
		assert_user_external_ids_imported(&store);
		assert_devices_imported(&store);
		assert_device_auth_providers_imported(&store);
		assert_dehydrated_devices_imported(&store);
		assert_remote_device_keys_imported(&store);
		assert_ignored_users_imported(&store);
		assert_room_tags_imported(&store);
		assert_filters_imported(&store);
		assert_presence_imported(&store);
		assert_url_previews_imported(&store);
		assert_open_id_tokens_imported(&store);
		assert_login_tokens_imported(&store);
		assert_ui_auth_sessions_imported(&store);
		assert_push_rules_imported(&store);
		assert_outlier_events_imported(&store);
		assert_backfilled_events_imported(&store);
		assert_event_edges_imported(&store);
		assert!(
			store
				.get_raw("token_userdeviceid", b"token")
				.expect("token query")
				.is_some()
		);
		assert!(
			store
				.get_raw("userid_password", b"@conduit:example.com")
				.expect("server user query")
				.is_some()
		);
		assert!(
			store
				.get_raw("global", b"version")
				.expect("database version query")
				.is_some()
		);
		assert!(
			store
				.get_raw("global", b"feat_sha256_media")
				.expect("fresh marker query")
				.is_some()
		);
		assert!(
			store
				.get_raw("eventid_pduid", b"$event:example.com")
				.expect("event query")
				.is_some()
		);
		assert_room_event_references_normalized(&store);
		assert_redactions_imported(&store);
		assert_event_reports_imported(&store);
		assert_search_index_imported(&store);
		assert_event_relations_imported(&store);
		assert_event_transactions_imported(&store);
		assert_room_state_imported(&store);
		assert_room_retention_imported(&store);
		assert_event_expiry_imported(&store);
		assert_event_state_hash_repaired(&store);
		assert_forward_extremities_imported(&store);
		assert_blocked_rooms_imported(&store);
		assert_room_aliases_imported(&store);
		assert_public_rooms_imported(&store);
		assert_e2ee_imported(&store);
		assert_room_key_backups_imported(&store);
		assert_to_device_messages_imported(&store);
		assert_device_federation_queues_imported(&store);
		assert_receipts_imported(&store);
		assert_notification_counts_imported(&store);
		assert_pushers_imported(&store);
		assert_deleted_pushers_imported(&store);
		assert_appservice_delivery_imported(&store);
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
		assert_eq!(report.suspended_users, 0);

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
		assert!(
			store
				.get_raw("userid_suspension", b"@legacy:example.com")
				.expect("legacy suspension query")
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
	fn imports_soft_failed_event_metadata() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let dest_path = temp.path().join("continuwuity-db");
		let conn = Connection::open(&sqlite_path).expect("sqlite");
		conn.execute_batch(
			"
			CREATE TABLE event_json (
				event_id TEXT NOT NULL, room_id TEXT NOT NULL,
				internal_metadata TEXT NOT NULL, json TEXT NOT NULL
			);
			INSERT INTO event_json VALUES (
				'$soft:example.com', '!room:example.com',
				'{\"soft_failed\":true}', '{}'
			);
			INSERT INTO event_json VALUES (
				'$hard:example.com', '!room:example.com',
				'{\"soft_failed\":false}', '{}'
			);
			",
		)
		.expect("seed soft failed sqlite");
		let config_path = write_synapse_config(temp.path(), &sqlite_path, None, &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::SoftFailedEvents]);
		let report = execute_plan(&plan).expect("execute soft failed import");

		assert_eq!(report.soft_failed_events, 1);
		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		assert!(
			store
				.get_raw("softfailedeventids", b"$soft:example.com")
				.expect("soft failed query")
				.is_some()
		);
		assert!(
			store
				.get_raw("softfailedeventids", b"$hard:example.com")
				.expect("hard event query")
				.is_none()
		);
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
	fn imports_media_from_backup_store_when_primary_missing() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let media_store = temp.path().join("media_store");
		let backup_media_store = temp.path().join("backup_media_store");
		let dest_path = temp.path().join("continuwuity-db");
		fs::create_dir_all(backup_media_store.join("local_content/ab/cd"))
			.expect("backup media dirs");
		fs::write(backup_media_store.join("local_content/ab/cd/ef"), b"backup media")
			.expect("backup media file");

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
		.expect("seed backup media sqlite");
		let config_path = write_synapse_config_with_backup(
			temp.path(),
			&sqlite_path,
			Some(&media_store),
			Some(&backup_media_store),
			&[],
		);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::Media]);
		let report = execute_plan(&plan).expect("execute backup media import");

		assert_eq!(report.media, 1);
		assert_eq!(
			fs::read_dir(dest_path.join("media"))
				.expect("dest media dir")
				.count(),
			1
		);
	}

	#[test]
	fn imports_media_thumbnails() {
		let temp = tempdir().expect("tempdir");
		let sqlite_path = temp.path().join("homeserver.db");
		let media_store = temp.path().join("media_store");
		let dest_path = temp.path().join("continuwuity-db");
		fs::create_dir_all(media_store.join("local_thumbnails/ab/cd/ef"))
			.expect("local thumbnail dirs");
		fs::write(
			media_store.join("local_thumbnails/ab/cd/ef/32-32-image-png-crop"),
			b"local-thumb",
		)
		.expect("local thumbnail file");
		fs::create_dir_all(media_store.join("remote_thumbnail/remote.example/xy/za/bc"))
			.expect("remote thumbnail dirs");
		fs::write(
			media_store.join("remote_thumbnail/remote.example/xy/za/bc/64-64-image-jpeg"),
			b"remote-thumb",
		)
		.expect("legacy remote thumbnail file");

		let conn = Connection::open(&sqlite_path).expect("sqlite");
		conn.execute_batch(
			"
			CREATE TABLE local_media_repository_thumbnails (
				media_id TEXT, thumbnail_width INTEGER, thumbnail_height INTEGER,
				thumbnail_type TEXT, thumbnail_method TEXT, thumbnail_length INTEGER
			);
			INSERT INTO local_media_repository_thumbnails VALUES (
				'abcdef', 32, 32, 'image/png', 'crop', 11
			);
			INSERT INTO local_media_repository_thumbnails VALUES (
				'badmethod', 32, 32, 'image/png', 'stretch', 0
			);
			CREATE TABLE remote_media_cache_thumbnails (
				media_origin TEXT, media_id TEXT, thumbnail_width INTEGER,
				thumbnail_height INTEGER, thumbnail_method TEXT, thumbnail_type TEXT,
				thumbnail_length INTEGER, filesystem_id TEXT
			);
			INSERT INTO remote_media_cache_thumbnails VALUES (
				'remote.example', 'remoteid', 64, 64, 'scale', 'image/jpeg', 12, 'xyzabc'
			);
			INSERT INTO remote_media_cache_thumbnails VALUES (
				'remote.example', 'badtype', 64, 64, 'scale', 'image', 0, 'badtype'
			);
			",
		)
		.expect("seed thumbnail sqlite");
		let config_path = write_synapse_config(temp.path(), &sqlite_path, Some(&media_store), &[]);

		let plan = test_plan(config_path, dest_path.clone(), vec![DataKind::MediaThumbnails]);
		let report = execute_plan(&plan).expect("execute thumbnail import");

		assert_eq!(report.media_thumbnails, 2);
		assert_eq!(report.skipped.get("media_thumbnails.invalid_method"), Some(&1));
		assert_eq!(
			report.skipped.get("media_thumbnails.invalid_content_type"),
			Some(&1)
		);
		assert_eq!(
			fs::read_dir(dest_path.join("media"))
				.expect("dest media dir")
				.count(),
			2
		);

		let store = ContinuwuityStore::open(&dest_path).expect("open destination");
		assert_eq!(
			store
				.prefix_raw("mediaid_file", b"mxc://example.com/abcdef")
				.expect("local thumbnail key")
				.len(),
			1
		);
		assert_eq!(
			store
				.prefix_raw("mediaid_file", b"mxc://remote.example/remoteid")
				.expect("remote thumbnail key")
				.len(),
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
				appservice_id TEXT, user_type TEXT, shadow_banned INTEGER, locked INTEGER,
				suspended INTEGER
			);
			INSERT INTO users VALUES (
				'@alice:example.com', '{password_hash}', 0, 1, NULL, NULL, 0, 1, 1
			);
			CREATE TABLE erased_users (
				user_id TEXT NOT NULL
			);
			INSERT INTO erased_users VALUES (
				'@alice:example.com'
			);
			CREATE TABLE account_validity (
				user_id TEXT PRIMARY KEY,
				expiration_ts_ms BIGINT NOT NULL,
				email_sent BOOLEAN NOT NULL,
				renewal_token TEXT,
				token_used_ts_ms BIGINT
			);
			INSERT INTO account_validity VALUES (
				'@alice:example.com', 4102444800000, 1, 'renew-token', NULL
			);
			INSERT INTO account_validity VALUES (
				'@expired:example.com', 1, 0, NULL, NULL
			);
			INSERT INTO account_validity VALUES (
				'alice', 4102444800000, 0, NULL, NULL
			);
			INSERT INTO account_validity VALUES (
				'@badexpiry:example.com', -1, 0, NULL, NULL
			);
			INSERT INTO account_validity VALUES (
				'@badtoken:example.com', 4102444800000, 0, NULL, -1
			);
			CREATE TABLE ratelimit_override (
				user_id TEXT NOT NULL,
				messages_per_second BIGINT,
				burst_count BIGINT
			);
			INSERT INTO ratelimit_override VALUES (
				'@alice:example.com', 0, 0
			);
			INSERT INTO ratelimit_override VALUES (
				'@bob:example.com', 5, 20
			);
			INSERT INTO ratelimit_override VALUES (
				'alice', 1, 1
			);
			INSERT INTO ratelimit_override VALUES (
				'@badlimit:example.com', -1, 1
			);
			CREATE TABLE monthly_active_users (
				user_id TEXT NOT NULL,
				timestamp BIGINT NOT NULL
			);
			INSERT INTO monthly_active_users VALUES (
				'@alice:example.com', 123456
			);
			INSERT INTO monthly_active_users VALUES (
				'alice', 123456
			);
			INSERT INTO monthly_active_users VALUES (
				'@badmau:example.com', -1
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
			CREATE TABLE user_external_ids (
				auth_provider TEXT NOT NULL,
				external_id TEXT NOT NULL,
				user_id TEXT NOT NULL
			);
			INSERT INTO user_external_ids VALUES (
				'oidc', 'alice-oidc', '@alice:example.com'
			);
			INSERT INTO user_external_ids VALUES (
				'', 'bad', '@alice:example.com'
			);
			INSERT INTO user_external_ids VALUES (
				'oidc', 'bad-user', 'alice'
			);
			CREATE TABLE devices (
				user_id TEXT, device_id TEXT, display_name TEXT, last_seen INTEGER, ip TEXT,
				hidden INTEGER
			);
			INSERT INTO devices VALUES (
				'@alice:example.com', 'DEVICE', 'Alice phone', 1234, '127.0.0.1', 0
			);
			INSERT INTO devices VALUES (
				'@alice:example.com', 'IPDEVICE', 'Synced phone', NULL, NULL, 0
			);
			CREATE TABLE user_ips (
				user_id TEXT, access_token TEXT, ip TEXT, user_agent TEXT,
				device_id TEXT, last_seen INTEGER
			);
			INSERT INTO user_ips VALUES (
				'@alice:example.com', 'fallback-token', '192.0.2.10', 'older-agent',
				'IPDEVICE', 2000
			);
			INSERT INTO user_ips VALUES (
				'@alice:example.com', 'fallback-token', '192.0.2.20', 'newer-agent',
				'IPDEVICE', 5678
			);
			CREATE TABLE device_auth_providers (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				auth_provider_id TEXT NOT NULL,
				auth_provider_session_id TEXT NOT NULL
			);
			INSERT INTO device_auth_providers VALUES (
				'@alice:example.com', 'DEVICE', 'oidc', 'session'
			);
			INSERT INTO device_auth_providers VALUES (
				'@alice:example.com', '', 'oidc', 'session'
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
			CREATE TABLE device_lists_remote_cache (
				user_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				content TEXT NOT NULL
			);
			INSERT INTO device_lists_remote_cache VALUES (
				'@bob:remote.example', 'REMOTE',
				'{{
					\"user_id\":\"@bob:remote.example\",
					\"device_id\":\"REMOTE\",
					\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\"],
					\"keys\":{{\"curve25519:REMOTE\":\"remote-curve\",\"ed25519:REMOTE\":\"remote-ed\"}},
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
			CREATE TABLE device_federation_inbox (
				origin TEXT NOT NULL,
				message_id TEXT NOT NULL,
				received_ts BIGINT NOT NULL,
				instance_name TEXT
			);
			INSERT INTO device_federation_inbox VALUES (
				'remote.example', 'msg1', 100, 'main'
			);
			INSERT INTO device_federation_inbox VALUES (
				'', 'msg2', 101, NULL
			);
			CREATE TABLE device_federation_outbox (
				destination TEXT NOT NULL,
				stream_id BIGINT NOT NULL,
				queued_ts BIGINT NOT NULL,
				messages_json TEXT NOT NULL,
				instance_name TEXT
			);
			INSERT INTO device_federation_outbox VALUES (
				'remote.example', 101, 123456,
				'{{\"messages\":[{{\"type\":\"m.device_list_update\"}}]}}',
				'main'
			);
			INSERT INTO device_federation_outbox VALUES (
				'remote.example', -1, 123456, '{{}}', NULL
			);
			CREATE TABLE device_lists_remote_extremeties (
				user_id TEXT NOT NULL,
				stream_id TEXT NOT NULL
			);
			INSERT INTO device_lists_remote_extremeties VALUES (
				'@bob:remote.example', 'opaque-stream'
			);
			INSERT INTO device_lists_remote_extremeties VALUES (
				'bob', 'opaque-stream'
			);
			CREATE TABLE device_lists_remote_resync (
				user_id TEXT NOT NULL,
				added_ts BIGINT NOT NULL
			);
			INSERT INTO device_lists_remote_resync VALUES (
				'@bob:remote.example', 123457
			);
			INSERT INTO device_lists_remote_resync VALUES (
				'bob', 123457
			);
			CREATE TABLE user_signature_stream (
				stream_id BIGINT NOT NULL,
				from_user_id TEXT NOT NULL,
				user_ids TEXT NOT NULL,
				instance_name TEXT
			);
			INSERT INTO user_signature_stream VALUES (
				102, '@alice:example.com',
				'[\"@alice:example.com\",\"@bob:remote.example\"]',
				'main'
			);
			INSERT INTO user_signature_stream VALUES (
				103, '@alice:example.com', '{{}}', NULL
			);
			CREATE TABLE access_tokens (
				id BIGINT PRIMARY KEY, user_id TEXT, device_id TEXT, token TEXT,
				valid_until_ms INTEGER
			);
			INSERT INTO access_tokens VALUES (
				1, '@alice:example.com', 'DEVICE', 'token', NULL
			);
			CREATE TABLE open_id_tokens (
				token TEXT NOT NULL PRIMARY KEY,
				ts_valid_until_ms BIGINT NOT NULL,
				user_id TEXT NOT NULL
			);
			INSERT INTO open_id_tokens VALUES (
				'openid-token', 4102444800000, '@alice:example.com'
			);
			CREATE TABLE login_tokens (
				token TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				expiry_ts BIGINT NOT NULL,
				used_ts BIGINT,
				auth_provider_id TEXT,
				auth_provider_session_id TEXT
			);
			INSERT INTO login_tokens VALUES (
				'login-token', '@alice:example.com', 4102444800000, NULL, NULL, NULL
			);
			INSERT INTO login_tokens VALUES (
				'expired-login-token', '@alice:example.com', 1, NULL, NULL, NULL
			);
			INSERT INTO login_tokens VALUES (
				'used-login-token', '@alice:example.com', 4102444800000, 2, NULL, NULL
			);
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
				'uiaa-session', 123456,
				'{{\"user_id\":\"@alice:example.com\"}}',
				'{{\"auth\":{{\"type\":\"m.login.password\"}}}}',
				'/_matrix/client/v3/account/password',
				'POST',
				'Change password'
			);
			INSERT INTO ui_auth_sessions VALUES (
				'bad-uiaa-session', -1, '{{}}', '{{}}',
				'/_matrix/client/v3/account/password', 'POST', 'Bad'
			);
			CREATE TABLE ui_auth_sessions_credentials (
				session_id TEXT NOT NULL,
				stage_type TEXT NOT NULL,
				result TEXT NOT NULL
			);
			INSERT INTO ui_auth_sessions_credentials VALUES (
				'uiaa-session', 'm.login.password',
				'{{\"user_id\":\"@alice:example.com\"}}'
			);
			INSERT INTO ui_auth_sessions_credentials VALUES (
				'uiaa-session', '', '{{}}'
			);
			CREATE TABLE ui_auth_sessions_ips (
				session_id TEXT NOT NULL,
				ip TEXT NOT NULL,
				user_agent TEXT NOT NULL
			);
			INSERT INTO ui_auth_sessions_ips VALUES (
				'uiaa-session', '127.0.0.1', 'Element'
			);
			INSERT INTO ui_auth_sessions_ips VALUES (
				'uiaa-session', '', 'Element'
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
			CREATE TABLE deleted_pushers (
				stream_id BIGINT NOT NULL,
				app_id TEXT NOT NULL,
				pushkey TEXT NOT NULL,
				user_id TEXT NOT NULL
			);
			INSERT INTO deleted_pushers VALUES (
				7, 'com.example.app', 'old-pushkey', '@alice:example.com'
			);
			INSERT INTO deleted_pushers VALUES (
				-1, 'com.example.app', 'old-pushkey', '@alice:example.com'
			);
			INSERT INTO deleted_pushers VALUES (
				8, '', 'old-pushkey', '@alice:example.com'
			);
			CREATE TABLE application_services_txns (
				as_id TEXT NOT NULL,
				txn_id BIGINT NOT NULL,
				event_ids TEXT NOT NULL
			);
			INSERT INTO application_services_txns VALUES (
				'bridge', 11, '[\"$event:example.com\"]'
			);
			INSERT INTO application_services_txns VALUES (
				'bridge', -1, '[\"$event:example.com\"]'
			);
			INSERT INTO application_services_txns VALUES (
				'bridge', 12, '{{}}'
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
				'bridge', 'up', 77, 88, 99, 101
			);
			INSERT INTO application_services_state VALUES (
				'badbridge', 'up', -1, 88, 99, 101
			);
			CREATE TABLE appservice_stream_position (
				Lock CHAR(1) NOT NULL,
				stream_ordering BIGINT
			);
			INSERT INTO appservice_stream_position VALUES (
				'X', 42
			);
			INSERT INTO appservice_stream_position VALUES (
				'', 42
			);
			CREATE TABLE appservice_room_list (
				appservice_id TEXT NOT NULL,
				network_id TEXT NOT NULL,
				room_id TEXT NOT NULL
			);
			INSERT INTO appservice_room_list VALUES (
				'bridge', 'irc', '!room:example.com'
			);
			INSERT INTO appservice_room_list VALUES (
				'bridge', 'irc', 'room'
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
			CREATE TABLE push_rules (
				id BIGINT PRIMARY KEY,
				user_name TEXT NOT NULL,
				rule_id TEXT NOT NULL,
				priority_class SMALLINT NOT NULL,
				priority INTEGER NOT NULL DEFAULT 0,
				conditions TEXT NOT NULL,
				actions TEXT NOT NULL
			);
			CREATE TABLE push_rules_enable (
				id BIGINT PRIMARY KEY,
				user_name TEXT NOT NULL,
				rule_id TEXT NOT NULL,
				enabled SMALLINT
			);
			INSERT INTO push_rules VALUES (
				1, '@alice:example.com', 'global/override/custom-override', 5, 20,
				'[{{\"kind\":\"event_match\",\"key\":\"type\",\"pattern\":\"m.room.message\"}}]',
				'[\"notify\", {{\"set_tweak\":\"highlight\",\"value\":true}}]'
			);
			INSERT INTO push_rules_enable VALUES (
				1, '@alice:example.com', 'global/override/custom-override', 0
			);
			INSERT INTO push_rules VALUES (
				2, '@alice:example.com', 'global/content/contains-tea', 4, 10,
				'[{{\"kind\":\"event_match\",\"key\":\"content.body\",\"pattern\":\"tea\"}}]',
				'[\"notify\"]'
			);
			INSERT INTO push_rules VALUES (
				3, '@alice:example.com', 'global/room/!room:example.com', 3, 5,
				'[{{\"kind\":\"event_match\",\"key\":\"room_id\",\"pattern\":\"!room:example.com\"}}]',
				'[\"dont_notify\"]'
			);
			INSERT INTO push_rules VALUES (
				4, '@alice:example.com', 'global/content/broken', 4, 1,
				'[{{\"kind\":\"event_match\",\"key\":\"content.body\",\"pattern\":\"broken\"}}]',
				'{{\"not\":\"an array\"}}'
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
			INSERT INTO events VALUES (
				45, '$outlier:remote.example', '!room:example.com', 1, NULL
			);
			INSERT INTO events VALUES (
				-1, '$backfilled:example.com', '!room:example.com', 0, NULL
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
					\"prev_events\":[[\"$event:example.com\",{{\"sha256\":\"prev\"}}]],
					\"depth\":2,
					\"auth_events\":[[\"$create:example.com\",{{\"sha256\":\"auth\"}}]],
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
					\"prev_events\":[[\"$thread:example.com\",{{\"sha256\":\"thread\"}}]],
					\"depth\":3,
					\"auth_events\":[[\"$create:example.com\",{{\"sha256\":\"auth\"}}]],
					\"hashes\":{{\"sha256\":\"redaction\"}},
					\"signatures\":{{}}
				}}'
			);
			INSERT INTO event_json VALUES (
				'$outlier:remote.example',
				'!room:example.com',
				'{{
					\"sender\":\"@bob:remote.example\",
					\"origin_server_ts\":5,
					\"type\":\"m.room.message\",
					\"content\":{{\"body\":\"remote auth\",\"msgtype\":\"m.text\"}},
					\"prev_events\":[[\"$redaction:example.com\",{{\"sha256\":\"redaction\"}}]],
					\"depth\":4,
					\"auth_events\":[[\"$create:example.com\",{{\"sha256\":\"auth\"}}]],
					\"hashes\":{{\"sha256\":\"outlier\"}},
					\"signatures\":{{}}
				}}'
			);
			INSERT INTO event_json VALUES (
				'$backfilled:example.com',
				'!room:example.com',
				'{{
					\"sender\":\"@alice:example.com\",
					\"origin_server_ts\":0,
					\"type\":\"m.room.message\",
					\"content\":{{\"body\":\"older\",\"msgtype\":\"m.text\"}},
					\"prev_events\":[],
					\"depth\":0,
					\"auth_events\":[[\"$create:example.com\",{{\"sha256\":\"auth\"}}]],
					\"hashes\":{{\"sha256\":\"backfilled\"}},
					\"signatures\":{{}}
				}}'
			);
			CREATE TABLE event_edges (
				event_id TEXT NOT NULL,
				prev_event_id TEXT NOT NULL,
				room_id TEXT NULL,
				is_state BOOL NOT NULL DEFAULT 0
			);
			INSERT INTO event_edges VALUES (
				'$thread:example.com', '$event:example.com', NULL, 0
			);
			INSERT INTO event_edges VALUES (
				'$redaction:example.com', '$thread:example.com', '!room:example.com', 0
			);
			INSERT INTO event_edges VALUES (
				'$member:example.com', '$create:example.com', '!room:example.com', 1
			);
			INSERT INTO event_edges VALUES (
				'$missing:example.com', '$event:example.com', '!room:example.com', 0
			);
			CREATE TABLE redactions (
				event_id TEXT NOT NULL, redacts TEXT NOT NULL,
				have_censored BOOL NOT NULL DEFAULT false, received_ts BIGINT
			);
			INSERT INTO redactions VALUES (
				'$redaction:example.com', '$event:example.com', 0, 4
			);
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
				1, 123456, '!room:example.com', '$event:example.com',
				'@alice:example.com', 'bad event',
				'{{\"score\":-100,\"reason\":\"bad event\"}}'
			);
			INSERT INTO event_reports VALUES (
				-1, 123456, '!room:example.com', '$event:example.com',
				'@alice:example.com', 'bad id', '{{}}'
			);
			INSERT INTO event_reports VALUES (
				2, 123456, '!room:example.com', 'event',
				'@alice:example.com', 'bad event id', '{{}}'
			);
			CREATE TABLE event_relations (
				event_id TEXT NOT NULL, relates_to_id TEXT NOT NULL,
				relation_type TEXT NOT NULL, aggregation_key TEXT
			);
			INSERT INTO event_relations VALUES (
				'$thread:example.com', '$event:example.com', 'm.thread', NULL
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
				'$event:example.com', '!room:example.com', '@alice:example.com',
				'DEVICE', 'txn-device', 100
			);
			INSERT INTO event_txn_id_device_id VALUES (
				'$missing:example.com', '!room:example.com', '@alice:example.com',
				'DEVICE', 'txn-missing', 101
			);
			INSERT INTO event_txn_id_device_id VALUES (
				'$event:example.com', 'room:example.com', '@alice:example.com',
				'DEVICE', 'txn-invalid', 102
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
				'$thread:example.com', '!room:example.com', '@alice:example.com',
				1, 'txn-token', 103
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
			CREATE TABLE room_retention (
				room_id TEXT,
				event_id TEXT,
				min_lifetime BIGINT,
				max_lifetime BIGINT,
				PRIMARY KEY(room_id, event_id)
			);
			INSERT INTO room_retention VALUES (
				'!room:example.com', '$retention:example.com', 1000, 2000
			);
			INSERT INTO room_retention VALUES (
				'room:example.com', '$retention:example.com', 1000, 2000
			);
			INSERT INTO room_retention VALUES (
				'!room:example.com', '$badretention:example.com', -1, 2000
			);
			CREATE TABLE event_expiry (
				event_id TEXT PRIMARY KEY,
				expiry_ts BIGINT NOT NULL
			);
			INSERT INTO event_expiry VALUES (
				'$event:example.com', 4102444800000
			);
			INSERT INTO event_expiry VALUES (
				'event:example.com', 4102444800000
			);
			INSERT INTO event_expiry VALUES (
				'$badexpiry:example.com', -1
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

	fn assert_account_validity_imported(store: &ContinuwuityStore) {
		let row = store
			.get_raw("synapse_account_validity", b"@alice:example.com")
			.expect("account validity query")
			.expect("account validity row");
		let row: serde_json::Value =
			serde_json::from_slice(&row).expect("account validity json");
		assert_eq!(row["user_id"], "@alice:example.com");
		assert_eq!(row["expiration_ts_ms"], 4102444800000_i64);
		assert_eq!(row["email_sent"], true);
		assert_eq!(row["renewal_token"], "renew-token");
		assert!(row["token_used_ts_ms"].is_null());

		let expired = store
			.get_raw("synapse_account_validity", b"@expired:example.com")
			.expect("expired account validity query")
			.expect("expired account validity row");
		let expired: serde_json::Value =
			serde_json::from_slice(&expired).expect("expired account validity json");
		assert_eq!(expired["expiration_ts_ms"], 1);
	}

	fn assert_admin_metadata_imported(store: &ContinuwuityStore) {
		let rate_limit = store
			.get_raw("synapse_ratelimit_overrides", b"@alice:example.com")
			.expect("ratelimit override query")
			.expect("ratelimit override row");
		let rate_limit: serde_json::Value =
			serde_json::from_slice(&rate_limit).expect("ratelimit override json");
		assert_eq!(rate_limit["user_id"], "@alice:example.com");
		assert_eq!(rate_limit["messages_per_second"], 0);
		assert_eq!(rate_limit["burst_count"], 0);

		let bob_rate_limit = store
			.get_raw("synapse_ratelimit_overrides", b"@bob:example.com")
			.expect("bob ratelimit override query")
			.expect("bob ratelimit override row");
		let bob_rate_limit: serde_json::Value =
			serde_json::from_slice(&bob_rate_limit).expect("bob ratelimit override json");
		assert_eq!(bob_rate_limit["messages_per_second"], 5);
		assert_eq!(bob_rate_limit["burst_count"], 20);

		let monthly_active = store
			.get_raw("synapse_monthly_active_users", b"@alice:example.com")
			.expect("monthly active user query")
			.expect("monthly active user row");
		let monthly_active: serde_json::Value =
			serde_json::from_slice(&monthly_active).expect("monthly active user json");
		assert_eq!(monthly_active["user_id"], "@alice:example.com");
		assert_eq!(monthly_active["timestamp"], 123456);
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

		let suspension = store
			.get_raw("userid_suspension", b"@alice:example.com")
			.expect("suspended user query")
			.expect("suspended user row");
		let suspension: serde_json::Value =
			serde_json::from_slice(&suspension).expect("suspended user json");
		assert_eq!(suspension["suspended"], true);
		assert_eq!(suspension["suspended_at"], 0);
		assert_eq!(suspension["suspended_by"], "@synapse-migration:example.com");
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

	fn assert_user_external_ids_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec(("oidc", "alice-oidc")).expect("external id key");
		let row = store
			.get_raw("synapse_user_external_ids", &key)
			.expect("external id query")
			.expect("external id row");
		let row: serde_json::Value = serde_json::from_slice(&row).expect("external id json");
		assert_eq!(row["auth_provider"], "oidc");
		assert_eq!(row["external_id"], "alice-oidc");
		assert_eq!(row["user_id"], "@alice:example.com");
	}

	fn assert_devices_imported(store: &ContinuwuityStore) {
		let device_key =
			serialize_to_vec(("@alice:example.com", "DEVICE")).expect("device metadata key");
		let device = store
			.get_raw("userdeviceid_metadata", &device_key)
			.expect("device metadata query")
			.expect("device metadata row");
		let device: serde_json::Value =
			serde_json::from_slice(&device).expect("device metadata json");
		assert_eq!(device["display_name"], "Alice phone");
		assert_eq!(device["last_seen_ip"], "127.0.0.1");
		assert_eq!(device["last_seen_ts"], 1234);

		let fallback_key =
			serialize_to_vec(("@alice:example.com", "IPDEVICE")).expect("fallback metadata key");
		let fallback = store
			.get_raw("userdeviceid_metadata", &fallback_key)
			.expect("fallback metadata query")
			.expect("fallback metadata row");
		let fallback: serde_json::Value =
			serde_json::from_slice(&fallback).expect("fallback metadata json");
		assert_eq!(fallback["display_name"], "Synced phone");
		assert_eq!(fallback["last_seen_ip"], "192.0.2.20");
		assert_eq!(fallback["last_seen_ts"], 5678);
	}

	fn assert_device_auth_providers_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec(("@alice:example.com", "DEVICE", "oidc", "session"))
			.expect("device auth provider key");
		let row = store
			.get_raw("synapse_device_auth_providers", &key)
			.expect("device auth provider query")
			.expect("device auth provider row");
		let row: serde_json::Value =
			serde_json::from_slice(&row).expect("device auth provider json");
		assert_eq!(row["user_id"], "@alice:example.com");
		assert_eq!(row["device_id"], "DEVICE");
		assert_eq!(row["auth_provider_id"], "oidc");
		assert_eq!(row["auth_provider_session_id"], "session");
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

	fn assert_remote_device_keys_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec(("@bob:remote.example", "REMOTE")).expect("remote device key id");
		let key_json = store
			.get_raw("keyid_key", &key)
			.expect("remote device key query")
			.expect("remote device key row");
		let key_json: serde_json::Value =
			serde_json::from_slice(&key_json).expect("remote device key json");

		assert_eq!(key_json["user_id"], "@bob:remote.example");
		assert_eq!(key_json["keys"]["ed25519:REMOTE"], "remote-ed");
	}

	fn assert_push_rules_imported(store: &ContinuwuityStore) {
		let index_key = serialize_to_vec((
			Option::<&str>::None,
			"@alice:example.com",
			"m.push_rules",
		))
		.expect("push rules index key");
		let data_key = store
			.get_raw("roomusertype_roomuserdataid", &index_key)
			.expect("push rules index query")
			.expect("push rules index row");
		let event = store
			.get_raw("roomuserdataid_accountdata", &data_key)
			.expect("push rules event query")
			.expect("push rules event row");
		let event: serde_json::Value = serde_json::from_slice(&event).expect("push rules event json");

		assert_eq!(event["type"], "m.push_rules");
		assert_eq!(event["content"]["global"]["override"][0]["rule_id"], "custom-override");
		assert_eq!(event["content"]["global"]["override"][0]["enabled"], false);
		assert_eq!(
			event["content"]["global"]["override"][0]["conditions"][0]["pattern"],
			"m.room.message"
		);
		assert_eq!(event["content"]["global"]["content"][0]["rule_id"], "contains-tea");
		assert_eq!(event["content"]["global"]["content"][0]["pattern"], "tea");
		assert_eq!(event["content"]["global"]["room"][0]["rule_id"], "!room:example.com");
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

	fn assert_login_tokens_imported(store: &ContinuwuityStore) {
		let token = store
			.get_raw("logintoken_expiresatuserid", b"login-token")
			.expect("login token query")
			.expect("login token row");
		assert_eq!(
			token,
			serialize_to_vec((4102444800000_u64, "@alice:example.com")).expect("login token value")
		);
		assert!(
			store
				.get_raw("logintoken_expiresatuserid", b"expired-login-token")
				.expect("expired login token query")
				.is_none()
		);
		assert!(
			store
				.get_raw("logintoken_expiresatuserid", b"used-login-token")
				.expect("used login token query")
				.is_none()
		);
	}

	fn assert_ui_auth_sessions_imported(store: &ContinuwuityStore) {
		let session = store
			.get_raw("synapse_ui_auth_sessions", b"uiaa-session")
			.expect("ui auth session query")
			.expect("ui auth session row");
		let session: serde_json::Value =
			serde_json::from_slice(&session).expect("ui auth session json");
		assert_eq!(session["session_id"], "uiaa-session");
		assert_eq!(session["creation_time"], 123456);
		assert_eq!(session["serverdict"]["user_id"], "@alice:example.com");
		assert_eq!(
			session["clientdict"]["auth"]["type"],
			"m.login.password"
		);
		assert_eq!(session["uri"], "/_matrix/client/v3/account/password");
		assert_eq!(session["method"], "POST");
		assert_eq!(session["description"], "Change password");

		let credential_key =
			serialize_to_vec(("uiaa-session", "m.login.password")).expect("ui auth credential key");
		let credential = store
			.get_raw("synapse_ui_auth_session_credentials", &credential_key)
			.expect("ui auth credential query")
			.expect("ui auth credential row");
		let credential: serde_json::Value =
			serde_json::from_slice(&credential).expect("ui auth credential json");
		assert_eq!(credential["session_id"], "uiaa-session");
		assert_eq!(credential["stage_type"], "m.login.password");
		assert_eq!(credential["result"]["user_id"], "@alice:example.com");

		let ip_key =
			serialize_to_vec(("uiaa-session", "127.0.0.1", "Element")).expect("ui auth ip key");
		let ip = store
			.get_raw("synapse_ui_auth_session_ips", &ip_key)
			.expect("ui auth ip query")
			.expect("ui auth ip row");
		let ip: serde_json::Value = serde_json::from_slice(&ip).expect("ui auth ip json");
		assert_eq!(ip["session_id"], "uiaa-session");
		assert_eq!(ip["ip"], "127.0.0.1");
		assert_eq!(ip["user_agent"], "Element");
	}

	fn assert_room_event_references_normalized(store: &ContinuwuityStore) {
		let pdu_id = store
			.get_raw("eventid_pduid", b"$thread:example.com")
			.expect("thread pdu id query")
			.expect("thread pdu id row");
		let thread = store
			.get_raw("pduid_pdu", &pdu_id)
			.expect("thread pdu query")
			.expect("thread pdu row");
		let thread: serde_json::Value = serde_json::from_slice(&thread).expect("thread pdu json");
		assert_eq!(thread["prev_events"], serde_json::json!(["$event:example.com"]));
		assert_eq!(thread["auth_events"], serde_json::json!(["$create:example.com"]));
	}

	fn assert_outlier_events_imported(store: &ContinuwuityStore) {
		let outlier = store
			.get_raw("eventid_outlierpdu", b"$outlier:remote.example")
			.expect("outlier event query")
			.expect("outlier event row");
		let outlier: serde_json::Value =
			serde_json::from_slice(&outlier).expect("outlier event json");
		assert_eq!(outlier["event_id"], "$outlier:remote.example");
		assert_eq!(outlier["room_id"], "!room:example.com");
		assert_eq!(outlier["sender"], "@bob:remote.example");
		assert_eq!(
			outlier["prev_events"],
			serde_json::json!(["$redaction:example.com"])
		);
		assert_eq!(outlier["auth_events"], serde_json::json!(["$create:example.com"]));
		assert!(
			store
				.get_raw("eventid_pduid", b"$outlier:remote.example")
				.expect("outlier timeline query")
				.is_none()
		);
	}

	fn assert_backfilled_events_imported(store: &ContinuwuityStore) {
		let pdu_id = store
			.get_raw("eventid_pduid", b"$backfilled:example.com")
			.expect("backfilled pdu id query")
			.expect("backfilled pdu id row");
		assert_eq!(pdu_id.len(), 24);
		assert_eq!(&pdu_id[8..16], &0_u64.to_be_bytes());
		assert_eq!(&pdu_id[16..24], &(-1_i64).to_be_bytes());

		let pdu = store
			.get_raw("pduid_pdu", &pdu_id)
			.expect("backfilled pdu query")
			.expect("backfilled pdu row");
		let pdu: serde_json::Value = serde_json::from_slice(&pdu).expect("backfilled pdu json");
		assert_eq!(pdu["event_id"], "$backfilled:example.com");
		assert_eq!(pdu["content"]["body"], "older");
		assert_eq!(pdu["auth_events"], serde_json::json!(["$create:example.com"]));
		let shorteventid = store
			.get_raw("eventid_shorteventid", b"$backfilled:example.com")
			.expect("backfilled shorteventid query")
			.expect("backfilled shorteventid row");
		assert_eq!(shorteventid, ((-1_i64) as u64).to_be_bytes());
		assert!(
			store
				.get_raw("shorteventid_eventid", &shorteventid)
				.expect("backfilled reverse shorteventid query")
				.is_some()
		);
	}

	fn assert_event_edges_imported(store: &ContinuwuityStore) {
		let event_key =
			serialize_to_vec(("!room:example.com", "$event:example.com")).expect("referenced event key");
		assert!(
			store
				.get_raw("referencedevents", &event_key)
				.expect("referenced event query")
				.is_some()
		);
		let thread_key =
			serialize_to_vec(("!room:example.com", "$thread:example.com")).expect("referenced thread key");
		assert!(
			store
				.get_raw("referencedevents", &thread_key)
				.expect("referenced thread query")
				.is_some()
		);
		let create_key =
			serialize_to_vec(("!room:example.com", "$create:example.com")).expect("state edge key");
		assert!(
			store
				.get_raw("referencedevents", &create_key)
				.expect("state edge query")
				.is_none()
		);
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

	fn assert_event_reports_imported(store: &ContinuwuityStore) {
		let report = store
			.get_raw("synapse_event_reports", &1_u64.to_be_bytes())
			.expect("event report query")
			.expect("event report row");
		let report: serde_json::Value =
			serde_json::from_slice(&report).expect("event report json");
		assert_eq!(report["id"], 1);
		assert_eq!(report["received_ts"], 123456);
		assert_eq!(report["room_id"], "!room:example.com");
		assert_eq!(report["event_id"], "$event:example.com");
		assert_eq!(report["user_id"], "@alice:example.com");
		assert_eq!(report["reason"], "bad event");
		assert_eq!(report["content"]["score"], -100);
		assert_eq!(report["content"]["reason"], "bad event");
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

	fn assert_event_transactions_imported(store: &ContinuwuityStore) {
		assert_eq!(
			store
				.get_raw(
					"userdevicetxnid_response",
					&client_txn_key("@alice:example.com", Some("DEVICE"), "txn-device"),
				)
				.expect("device transaction query")
				.expect("device transaction row"),
			b"$event:example.com".to_vec()
		);
		assert_eq!(
			store
				.get_raw(
					"userdevicetxnid_response",
					&client_txn_key("@alice:example.com", Some("DEVICE"), "txn-token"),
				)
				.expect("token transaction query")
				.expect("token transaction row"),
			b"$thread:example.com".to_vec()
		);
	}

	fn client_txn_key(user_id: &str, device_id: Option<&str>, txn_id: &str) -> Vec<u8> {
		let mut key = user_id.as_bytes().to_vec();
		key.push(0xFF);
		key.extend_from_slice(device_id.unwrap_or_default().as_bytes());
		key.push(0xFF);
		key.extend_from_slice(txn_id.as_bytes());
		key
	}

	fn assert_room_retention_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec(("!room:example.com", "$retention:example.com"))
			.expect("room retention key");
		let row = store
			.get_raw("synapse_room_retention", &key)
			.expect("room retention query")
			.expect("room retention row");
		let row: serde_json::Value =
			serde_json::from_slice(&row).expect("room retention json");

		assert_eq!(row["room_id"], "!room:example.com");
		assert_eq!(row["event_id"], "$retention:example.com");
		assert_eq!(row["min_lifetime"], 1000);
		assert_eq!(row["max_lifetime"], 2000);
	}

	fn assert_event_expiry_imported(store: &ContinuwuityStore) {
		let mut key = 4102444800000_i64.to_be_bytes().to_vec();
		key.extend_from_slice(b"$event:example.com");
		let row = store
			.get_raw("synapse_event_expiry", &key)
			.expect("event expiry query")
			.expect("event expiry row");
		let row: serde_json::Value = serde_json::from_slice(&row).expect("event expiry json");

		assert_eq!(row["event_id"], "$event:example.com");
		assert_eq!(row["expiry_ts"], 4102444800000_i64);
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

		let backfilled_pduid = store
			.get_raw("eventid_pduid", b"$backfilled:example.com")
			.expect("backfilled pduid query")
			.expect("backfilled pduid row");
		let mut backfilled_key = backfilled_pduid[..8].to_vec();
		backfilled_key.extend_from_slice(b"older");
		backfilled_key.push(0xFF);
		backfilled_key.extend_from_slice(&backfilled_pduid);
		assert!(
			store
				.get_raw("tokenids", &backfilled_key)
				.expect("backfilled search token query")
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

	fn assert_event_state_hash_repaired(store: &ContinuwuityStore) {
		let state_hash = store
			.get_raw("roomid_shortstatehash", b"!room:example.com")
			.expect("state hash query")
			.expect("state hash row");
		let event_shorteventid = store
			.get_raw("eventid_shorteventid", b"$event:example.com")
			.expect("event shorteventid query")
			.expect("event shorteventid row");
		let event_state_hash = store
			.get_raw("shorteventid_shortstatehash", &event_shorteventid)
			.expect("event state hash query")
			.expect("event state hash row");
		assert_eq!(event_state_hash, state_hash);
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

	fn assert_device_federation_queues_imported(store: &ContinuwuityStore) {
		let inbox_key =
			serialize_to_vec(("remote.example", "msg1")).expect("device federation inbox key");
		let inbox = store
			.get_raw("synapse_device_federation_inbox", &inbox_key)
			.expect("device federation inbox query")
			.expect("device federation inbox row");
		let inbox: serde_json::Value =
			serde_json::from_slice(&inbox).expect("device federation inbox json");
		assert_eq!(inbox["origin"], "remote.example");
		assert_eq!(inbox["message_id"], "msg1");
		assert_eq!(inbox["received_ts"], 100);
		assert_eq!(inbox["instance_name"], "main");

		let outbox_key =
			serialize_to_vec((101_u64, "remote.example")).expect("device federation outbox key");
		let outbox = store
			.get_raw("synapse_device_federation_outbox", &outbox_key)
			.expect("device federation outbox query")
			.expect("device federation outbox row");
		let outbox: serde_json::Value =
			serde_json::from_slice(&outbox).expect("device federation outbox json");
		assert_eq!(outbox["destination"], "remote.example");
		assert_eq!(outbox["stream_id"], 101);
		assert_eq!(outbox["queued_ts"], 123456);
		assert_eq!(outbox["messages_json"]["messages"][0]["type"], "m.device_list_update");
		assert_eq!(outbox["instance_name"], "main");

		let extremity = store
			.get_raw("synapse_device_list_remote_extremities", b"@bob:remote.example")
			.expect("remote device list extremity query")
			.expect("remote device list extremity row");
		let extremity: serde_json::Value =
			serde_json::from_slice(&extremity).expect("remote device list extremity json");
		assert_eq!(extremity["stream_id"], "opaque-stream");

		let resync = store
			.get_raw("synapse_device_list_remote_resync", b"@bob:remote.example")
			.expect("remote device list resync query")
			.expect("remote device list resync row");
		let resync: serde_json::Value =
			serde_json::from_slice(&resync).expect("remote device list resync json");
		assert_eq!(resync["added_ts"], 123457);

		let signature = store
			.get_raw("synapse_user_signature_stream", &102_u64.to_be_bytes())
			.expect("user signature stream query")
			.expect("user signature stream row");
		let signature: serde_json::Value =
			serde_json::from_slice(&signature).expect("user signature stream json");
		assert_eq!(signature["from_user_id"], "@alice:example.com");
		assert_eq!(signature["user_ids"][0], "@alice:example.com");
		assert_eq!(signature["user_ids"][1], "@bob:remote.example");
		assert_eq!(signature["instance_name"], "main");
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

	fn assert_deleted_pushers_imported(store: &ContinuwuityStore) {
		let key = serialize_to_vec((
			7_u64,
			"@alice:example.com",
			"com.example.app",
			"old-pushkey",
		))
		.expect("deleted pusher key");
		let pusher = store
			.get_raw("synapse_deleted_pushers", &key)
			.expect("deleted pusher query")
			.expect("deleted pusher row");
		let pusher: serde_json::Value =
			serde_json::from_slice(&pusher).expect("deleted pusher json");
		assert_eq!(pusher["stream_id"], 7);
		assert_eq!(pusher["app_id"], "com.example.app");
		assert_eq!(pusher["pushkey"], "old-pushkey");
		assert_eq!(pusher["user_id"], "@alice:example.com");
	}

	fn assert_appservice_delivery_imported(store: &ContinuwuityStore) {
		let txn_key = serialize_to_vec(("bridge", 11_u64)).expect("appservice txn key");
		let txn = store
			.get_raw("synapse_application_services_txns", &txn_key)
			.expect("appservice txn query")
			.expect("appservice txn row");
		let txn: serde_json::Value = serde_json::from_slice(&txn).expect("appservice txn json");
		assert_eq!(txn["as_id"], "bridge");
		assert_eq!(txn["txn_id"], 11);
		assert_eq!(txn["event_ids"][0], "$event:example.com");

		let state = store
			.get_raw("synapse_application_services_state", b"bridge")
			.expect("appservice state query")
			.expect("appservice state row");
		let state: serde_json::Value =
			serde_json::from_slice(&state).expect("appservice state json");
		assert_eq!(state["as_id"], "bridge");
		assert_eq!(state["state"], "up");
		assert_eq!(state["read_receipt_stream_id"], 77);
		assert_eq!(state["presence_stream_id"], 88);
		assert_eq!(state["to_device_stream_id"], 99);
		assert_eq!(state["device_list_stream_id"], 101);

		let position = store
			.get_raw("synapse_appservice_stream_position", b"X")
			.expect("appservice stream position query")
			.expect("appservice stream position row");
		let position: serde_json::Value =
			serde_json::from_slice(&position).expect("appservice stream position json");
		assert_eq!(position["lock"], "X");
		assert_eq!(position["stream_ordering"], 42);

		let room_key =
			serialize_to_vec(("bridge", "irc", "!room:example.com")).expect("appservice room key");
		let room = store
			.get_raw("synapse_appservice_room_list", &room_key)
			.expect("appservice room query")
			.expect("appservice room row");
		let room: serde_json::Value =
			serde_json::from_slice(&room).expect("appservice room json");
		assert_eq!(room["appservice_id"], "bridge");
		assert_eq!(room["network_id"], "irc");
		assert_eq!(room["room_id"], "!room:example.com");
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
		write_synapse_config_with_backup(dir, sqlite_path, media_store, None, appservice_configs)
	}

	fn write_synapse_config_with_backup(
		dir: &std::path::Path,
		sqlite_path: &std::path::Path,
		media_store: Option<&std::path::Path>,
		backup_media_store: Option<&std::path::Path>,
		appservice_configs: &[PathBuf],
	) -> PathBuf {
		let path = dir.join("homeserver.yaml");
		let media = media_store.map_or(String::new(), |path| {
			format!("media_store_path: {}\n", path.display())
		});
		let backup_media = backup_media_store.map_or(String::new(), |path| {
			format!("backup_media_store_path: {}\n", path.display())
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
{media}{backup_media}{appservices}",
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
