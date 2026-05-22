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
pub struct SynapseUserDailyVisit {
	pub user_id: String,
	pub device_id: Option<String>,
	pub timestamp: i64,
	pub user_agent: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseUserIp {
	pub user_id: String,
	pub access_token: String,
	pub device_id: Option<String>,
	pub ip: String,
	pub user_agent: String,
	pub last_seen: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseUserStatsCurrent {
	pub user_id: String,
	pub joined_rooms: i64,
	pub completed_delta_stream_id: i64,
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
pub struct SynapseThreepidValidationSession {
	pub session_id: String,
	pub medium: String,
	pub address: String,
	pub client_secret: String,
	pub last_send_attempt: i64,
	pub validated_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseThreepidIdServer {
	pub user_id: String,
	pub medium: String,
	pub address: String,
	pub id_server: String,
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
pub struct SynapseReceivedTransaction {
	pub transaction_id: Option<String>,
	pub origin: Option<String>,
	pub ts: Option<i64>,
	pub response_code: Option<i64>,
	pub response_json: Option<Vec<u8>>,
	pub has_been_referenced: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseDestination {
	pub destination: String,
	pub retry_last_ts: Option<i64>,
	pub retry_interval: Option<i64>,
	pub failure_ts: Option<i64>,
	pub last_successful_stream_ordering: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseDestinationRoom {
	pub destination: String,
	pub room_id: String,
	pub stream_ordering: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventFailedPullAttempt {
	pub room_id: String,
	pub event_id: String,
	pub num_attempts: i64,
	pub last_attempt_ts: i64,
	pub last_cause: String,
}

#[derive(Clone, Debug)]
pub struct SynapseCacheInvalidation {
	pub stream_id: i64,
	pub instance_name: String,
	pub cache_func: String,
	pub keys: Option<Vec<String>>,
	pub invalidation_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseFederationStreamPosition {
	pub stream_type: String,
	pub stream_id: i64,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseFederationInboundEvent {
	pub origin: String,
	pub room_id: String,
	pub event_id: String,
	pub received_ts: i64,
	pub event_json: Value,
	pub internal_metadata: Value,
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
pub struct SynapseDeviceListStreamUpdate {
	pub stream_id: i64,
	pub user_id: String,
	pub device_id: String,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListOutboundPoke {
	pub destination: String,
	pub stream_id: i64,
	pub user_id: String,
	pub device_id: String,
	pub sent: bool,
	pub ts: i64,
	pub opentracing_context: Option<String>,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListOutboundLastSuccess {
	pub destination: String,
	pub user_id: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListRemotePending {
	pub stream_id: i64,
	pub user_id: String,
	pub device_id: String,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListChangeInRoom {
	pub user_id: String,
	pub device_id: String,
	pub room_id: String,
	pub stream_id: i64,
	pub converted_to_destinations: bool,
	pub opentracing_context: Option<String>,
	pub instance_name: Option<String>,
	pub inserted_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListChangesConvertedPosition {
	pub stream_id: i64,
	pub room_id: String,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseDeviceListChangesMaxPruned {
	pub stream_id: i64,
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
pub struct SynapseRoomTagRevision {
	pub user_id: String,
	pub room_id: String,
	pub stream_id: i64,
	pub instance_name: Option<String>,
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
pub struct SynapseEventAuth {
	pub event_id: String,
	pub auth_id: String,
	pub room_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventAuthChain {
	pub event_id: String,
	pub chain_id: i64,
	pub sequence_number: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventAuthChainLink {
	pub origin_chain_id: i64,
	pub origin_sequence_number: i64,
	pub target_chain_id: i64,
	pub target_sequence_number: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventAuthChainToCalculate {
	pub event_id: String,
	pub room_id: String,
	pub event_type: String,
	pub state_key: String,
}

#[derive(Clone, Debug)]
pub struct SynapseRejectedEvent {
	pub event_id: String,
	pub reason: String,
	pub last_check: String,
}

#[derive(Clone, Debug)]
pub struct SynapseBackwardExtremity {
	pub event_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseTimelineGap {
	pub room_id: String,
	pub instance_name: String,
	pub stream_ordering: i64,
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
pub struct SynapseCurrentStateDelta {
	pub stream_id: i64,
	pub room_id: String,
	pub event_type: String,
	pub state_key: String,
	pub event_id: Option<String>,
	pub prev_event_id: Option<String>,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseStreamOrderingExtremity {
	pub stream_ordering: i64,
	pub room_id: String,
	pub event_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseExOutlierStream {
	pub event_stream_ordering: i64,
	pub event_id: String,
	pub state_group: i64,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseStateGroup {
	pub id: i64,
	pub room_id: String,
	pub event_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseStateGroupEdge {
	pub state_group: i64,
	pub prev_state_group: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventToStateGroup {
	pub event_id: String,
	pub state_group: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseStateGroupState {
	pub state_group: i64,
	pub room_id: String,
	pub event_type: String,
	pub state_key: String,
	pub event_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseLocalCurrentMembership {
	pub room_id: String,
	pub user_id: String,
	pub event_id: String,
	pub membership: String,
	pub event_stream_ordering: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapsePartialStateRoom {
	pub room_id: String,
	pub device_lists_stream_id: Option<i64>,
	pub join_event_id: Option<String>,
	pub joined_via: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapsePartialStateRoomServer {
	pub room_id: String,
	pub server_name: String,
}

#[derive(Clone, Debug)]
pub struct SynapsePartialStateEvent {
	pub room_id: String,
	pub event_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseUnPartialStatedRoom {
	pub stream_id: i64,
	pub instance_name: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseUnPartialStatedEvent {
	pub stream_id: i64,
	pub instance_name: String,
	pub event_id: String,
	pub rejection_status_changed: bool,
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
pub struct SynapseRoomMetadata {
	pub room_id: String,
	pub is_public: Option<bool>,
	pub creator: Option<String>,
	pub room_version: Option<String>,
	pub has_auth_chain_index: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomDepth {
	pub room_id: String,
	pub min_depth: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseUsersInPublicRoom {
	pub user_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseUsersWhoSharePrivateRoom {
	pub user_id: String,
	pub other_user_id: String,
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseUserDirectoryEntry {
	pub user_id: String,
	pub room_id: Option<String>,
	pub display_name: Option<String>,
	pub avatar_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseUserDirectorySearch {
	pub user_id: String,
	pub vector: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseUserDirectoryStaleRemoteUser {
	pub user_id: String,
	pub user_server_name: String,
	pub next_try_at_ts: i64,
	pub retry_counter: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseUserDirectoryStreamPosition {
	pub lock: String,
	pub stream_id: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomStatsCurrent {
	pub room_id: String,
	pub current_state_events: i64,
	pub joined_members: i64,
	pub invited_members: i64,
	pub left_members: i64,
	pub banned_members: i64,
	pub local_users_in_room: i64,
	pub completed_delta_stream_id: i64,
	pub knocked_members: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomStatsState {
	pub room_id: String,
	pub name: Option<String>,
	pub canonical_alias: Option<String>,
	pub join_rules: Option<String>,
	pub history_visibility: Option<String>,
	pub encryption: Option<String>,
	pub avatar: Option<String>,
	pub guest_access: Option<String>,
	pub is_federatable: Option<bool>,
	pub topic: Option<String>,
	pub room_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomStatsEarliestToken {
	pub room_id: String,
	pub token: i64,
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
pub struct SynapseReceiptGraph {
	pub room_id: String,
	pub receipt_type: String,
	pub user_id: String,
	pub event_ids: Vec<String>,
	pub data: Value,
	pub thread_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseNotificationCount {
	pub user_id: String,
	pub room_id: String,
	pub notification_count: i64,
	pub highlight_count: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventPushSummary {
	pub user_id: String,
	pub room_id: String,
	pub notif_count: i64,
	pub stream_ordering: i64,
	pub unread_count: Option<i64>,
	pub last_receipt_stream_ordering: Option<i64>,
	pub thread_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventPushAction {
	pub room_id: String,
	pub event_id: String,
	pub user_id: String,
	pub profile_tag: Option<String>,
	pub actions: Value,
	pub topological_ordering: Option<i64>,
	pub stream_ordering: Option<i64>,
	pub notif: Option<bool>,
	pub highlight: Option<bool>,
	pub unread: Option<bool>,
	pub thread_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventPushActionStaging {
	pub event_id: String,
	pub user_id: String,
	pub actions: Value,
	pub notif: bool,
	pub highlight: bool,
	pub unread: Option<bool>,
	pub thread_id: Option<String>,
	pub inserted_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseEventPushSummaryStreamPosition {
	pub lock: String,
	pub stream_ordering: i64,
}

#[derive(Clone, Debug)]
pub struct SynapsePushRulesStream {
	pub stream_id: i64,
	pub event_stream_ordering: i64,
	pub user_id: String,
	pub rule_id: String,
	pub op: String,
	pub priority_class: Option<i64>,
	pub priority: Option<i64>,
	pub conditions: Option<Value>,
	pub actions: Option<Value>,
	pub instance_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnection {
	pub connection_key: i64,
	pub user_id: String,
	pub effective_device_id: String,
	pub conn_id: String,
	pub created_ts: i64,
	pub last_used_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnectionPosition {
	pub connection_position: i64,
	pub connection_key: i64,
	pub created_ts: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnectionStream {
	pub connection_position: i64,
	pub stream: String,
	pub room_id: String,
	pub room_status: String,
	pub last_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnectionRoomConfig {
	pub connection_position: i64,
	pub room_id: String,
	pub timeline_limit: i64,
	pub required_state_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnectionRequiredState {
	pub required_state_id: i64,
	pub connection_key: i64,
	pub required_state: Value,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncConnectionLazyMember {
	pub connection_key: i64,
	pub connection_position: Option<i64>,
	pub room_id: String,
	pub user_id: String,
	pub last_seen_ts: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncMembershipSnapshot {
	pub room_id: String,
	pub user_id: String,
	pub sender: String,
	pub membership_event_id: String,
	pub membership: String,
	pub forgotten: bool,
	pub event_stream_ordering: i64,
	pub event_instance_name: String,
	pub has_known_state: bool,
	pub room_type: Option<String>,
	pub room_name: Option<String>,
	pub is_encrypted: bool,
	pub tombstone_successor_room_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncJoinedRoom {
	pub room_id: String,
	pub event_stream_ordering: i64,
	pub bump_stamp: Option<i64>,
	pub room_type: Option<String>,
	pub room_name: Option<String>,
	pub is_encrypted: bool,
	pub tombstone_successor_room_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SynapseSlidingSyncJoinedRoomToRecalculate {
	pub room_id: String,
}

#[derive(Clone, Debug)]
pub struct SynapseStreamPosition {
	pub stream_name: String,
	pub instance_name: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseDelayedEventsStreamPosition {
	pub lock: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseEventPushSummaryLastReceiptStreamId {
	pub lock: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseRoomForgetterStreamPosition {
	pub lock: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseStatsIncrementalPosition {
	pub lock: String,
	pub stream_id: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseAppliedSchemaDelta {
	pub version: i64,
	pub file: String,
}

#[derive(Clone, Debug)]
pub struct SynapseSchemaVersion {
	pub lock: String,
	pub version: i64,
	pub upgraded: bool,
}

#[derive(Clone, Debug)]
pub struct SynapseSchemaCompatVersion {
	pub lock: String,
	pub compat_version: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseBackgroundUpdate {
	pub update_name: String,
	pub progress_json: Value,
	pub depends_on: Option<String>,
	pub ordering: i64,
}

#[derive(Clone, Debug)]
pub struct SynapseScheduledTask {
	pub id: String,
	pub action: String,
	pub status: String,
	pub timestamp: i64,
	pub resource_id: Option<String>,
	pub params: Option<Value>,
	pub result: Option<Value>,
	pub error: Option<String>,
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

#[derive(Clone, Debug)]
pub struct SynapseServerSignatureKey {
	pub server_name: Option<String>,
	pub key_id: Option<String>,
	pub from_server: Option<String>,
	pub ts_added_ms: Option<i64>,
	pub verify_key: Option<Vec<u8>>,
	pub ts_valid_until_ms: Option<i64>,
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

	pub fn user_daily_visits(&self) -> Result<Vec<SynapseUserDailyVisit>> {
		if !self.table_exists("user_daily_visits")? {
			return Ok(Vec::new());
		}

		let user_agent = if self.columns("user_daily_visits")?.contains("user_agent") {
			"user_agent"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, device_id, timestamp, {user_agent}
			FROM user_daily_visits
			ORDER BY timestamp, user_id, device_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserDailyVisit {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					timestamp: row.get(2)?,
					user_agent: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_ips(&self) -> Result<Vec<SynapseUserIp>> {
		if !self.table_exists("user_ips")? {
			return Ok(Vec::new());
		}

		let device_id = if self.columns("user_ips")?.contains("device_id") {
			"device_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, access_token, {device_id}, ip, user_agent, last_seen
			FROM user_ips
			ORDER BY user_id, access_token, ip, user_agent, last_seen
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserIp {
					user_id: row.get(0)?,
					access_token: row.get(1)?,
					device_id: row.get(2)?,
					ip: row.get(3)?,
					user_agent: row.get(4)?,
					last_seen: row.get(5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_stats_current(&self) -> Result<Vec<SynapseUserStatsCurrent>> {
		if !self.table_exists("user_stats_current")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, joined_rooms, completed_delta_stream_id
				FROM user_stats_current
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserStatsCurrent {
					user_id: row.get(0)?,
					joined_rooms: row.get(1)?,
					completed_delta_stream_id: row.get(2)?,
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

	pub fn threepid_validation_sessions(
		&self,
	) -> Result<Vec<SynapseThreepidValidationSession>> {
		if !self.table_exists("threepid_validation_session")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT session_id, medium, address, client_secret, last_send_attempt, validated_at
				FROM threepid_validation_session
				ORDER BY session_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseThreepidValidationSession {
					session_id: row.get(0)?,
					medium: row.get(1)?,
					address: row.get(2)?,
					client_secret: row.get(3)?,
					last_send_attempt: row.get(4)?,
					validated_at: row.get(5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_threepid_id_servers(&self) -> Result<Vec<SynapseThreepidIdServer>> {
		if !self.table_exists("user_threepid_id_server")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, medium, address, id_server
				FROM user_threepid_id_server
				ORDER BY user_id, medium, address, id_server
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseThreepidIdServer {
					user_id: row.get(0)?,
					medium: row.get(1)?,
					address: row.get(2)?,
					id_server: row.get(3)?,
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
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseReceivedTransaction {
					transaction_id: row.get(0)?,
					origin: row.get(1)?,
					ts: row.get(2)?,
					response_code: row.get::<_, Option<i64>>(3)?,
					response_json: optional_bytes(row, 4)?,
					has_been_referenced: int_bool(row, 5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn destinations(&self) -> Result<Vec<SynapseDestination>> {
		if !self.table_exists("destinations")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT destination, retry_last_ts, retry_interval, failure_ts,
				       last_successful_stream_ordering
				FROM destinations
				ORDER BY destination
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDestination {
					destination: row.get(0)?,
					retry_last_ts: row.get(1)?,
					retry_interval: row.get(2)?,
					failure_ts: row.get(3)?,
					last_successful_stream_ordering: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn destination_rooms(&self) -> Result<Vec<SynapseDestinationRoom>> {
		if !self.table_exists("destination_rooms")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT destination, room_id, stream_ordering
				FROM destination_rooms
				ORDER BY destination, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDestinationRoom {
					destination: row.get(0)?,
					room_id: row.get(1)?,
					stream_ordering: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_failed_pull_attempts(&self) -> Result<Vec<SynapseEventFailedPullAttempt>> {
		if !self.table_exists("event_failed_pull_attempts")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, event_id, num_attempts, last_attempt_ts, last_cause
				FROM event_failed_pull_attempts
				ORDER BY room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventFailedPullAttempt {
					room_id: row.get(0)?,
					event_id: row.get(1)?,
					num_attempts: row.get(2)?,
					last_attempt_ts: row.get(3)?,
					last_cause: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn cache_invalidations(&self) -> Result<Vec<SynapseCacheInvalidation>> {
		if !self.table_exists("cache_invalidation_stream_by_instance")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, instance_name, cache_func, keys, invalidation_ts
				FROM cache_invalidation_stream_by_instance
				ORDER BY stream_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseCacheInvalidation {
					stream_id: row.get(0)?,
					instance_name: row.get(1)?,
					cache_func: row.get(2)?,
					keys: optional_string_list(row, 3)?,
					invalidation_ts: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn federation_stream_positions(&self) -> Result<Vec<SynapseFederationStreamPosition>> {
		if !self.table_exists("federation_stream_position")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("federation_stream_position")?.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT type, stream_id, {instance_name}
			FROM federation_stream_position
			ORDER BY type, {instance_name}
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseFederationStreamPosition {
					stream_type: row.get(0)?,
					stream_id: row.get(1)?,
					instance_name: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn federation_inbound_events(&self) -> Result<Vec<SynapseFederationInboundEvent>> {
		if !self.table_exists("federation_inbound_events_staging")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT origin, room_id, event_id, received_ts, event_json, internal_metadata
				FROM federation_inbound_events_staging
				ORDER BY received_ts, origin, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let event_json: String = row.get(4)?;
				let internal_metadata: String = row.get(5)?;
				Ok(SynapseFederationInboundEvent {
					origin: row.get(0)?,
					room_id: row.get(1)?,
					event_id: row.get(2)?,
					received_ts: row.get(3)?,
					event_json: serde_json::from_str(&event_json).unwrap_or(Value::Null),
					internal_metadata: serde_json::from_str(&internal_metadata)
						.unwrap_or(Value::Null),
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

	pub fn device_list_stream_updates(&self) -> Result<Vec<SynapseDeviceListStreamUpdate>> {
		if !self.table_exists("device_lists_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_lists_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, user_id, device_id, {instance_name}
			FROM device_lists_stream
			ORDER BY stream_id, user_id, device_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListStreamUpdate {
					stream_id: row.get(0)?,
					user_id: row.get(1)?,
					device_id: row.get(2)?,
					instance_name: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_outbound_pokes(&self) -> Result<Vec<SynapseDeviceListOutboundPoke>> {
		if !self.table_exists("device_lists_outbound_pokes")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("device_lists_outbound_pokes")?;
		let opentracing_context = if columns.contains("opentracing_context") {
			"opentracing_context"
		} else {
			"NULL"
		};
		let instance_name = if columns.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT destination, stream_id, user_id, device_id, sent, ts,
			       {opentracing_context}, {instance_name}
			FROM device_lists_outbound_pokes
			ORDER BY stream_id, destination, user_id, device_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListOutboundPoke {
					destination: row.get(0)?,
					stream_id: row.get(1)?,
					user_id: row.get(2)?,
					device_id: row.get(3)?,
					sent: row.get(4)?,
					ts: row.get(5)?,
					opentracing_context: row.get(6)?,
					instance_name: row.get(7)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_outbound_last_success(
		&self,
	) -> Result<Vec<SynapseDeviceListOutboundLastSuccess>> {
		if !self.table_exists("device_lists_outbound_last_success")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT destination, user_id, stream_id
				FROM device_lists_outbound_last_success
				ORDER BY stream_id, destination, user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListOutboundLastSuccess {
					destination: row.get(0)?,
					user_id: row.get(1)?,
					stream_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_remote_pending(&self) -> Result<Vec<SynapseDeviceListRemotePending>> {
		if !self.table_exists("device_lists_remote_pending")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("device_lists_remote_pending")?.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, user_id, device_id, {instance_name}
			FROM device_lists_remote_pending
			ORDER BY stream_id, user_id, device_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListRemotePending {
					stream_id: row.get(0)?,
					user_id: row.get(1)?,
					device_id: row.get(2)?,
					instance_name: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_changes_in_room(&self) -> Result<Vec<SynapseDeviceListChangeInRoom>> {
		if !self.table_exists("device_lists_changes_in_room")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("device_lists_changes_in_room")?;
		let converted_to_destinations = if columns.contains("converted_to_destinations") {
			"converted_to_destinations"
		} else {
			"0"
		};
		let opentracing_context = if columns.contains("opentracing_context") {
			"opentracing_context"
		} else {
			"NULL"
		};
		let instance_name = if columns.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let inserted_ts = if columns.contains("inserted_ts") {
			"inserted_ts"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, device_id, room_id, stream_id, {converted_to_destinations},
			       {opentracing_context}, {instance_name}, {inserted_ts}
			FROM device_lists_changes_in_room
			ORDER BY stream_id, room_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListChangeInRoom {
					user_id: row.get(0)?,
					device_id: row.get(1)?,
					room_id: row.get(2)?,
					stream_id: row.get(3)?,
					converted_to_destinations: row.get(4)?,
					opentracing_context: row.get(5)?,
					instance_name: row.get(6)?,
					inserted_ts: row.get(7)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
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
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, room_id, {instance_name}
			FROM device_lists_changes_converted_stream_position
			ORDER BY stream_id, room_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListChangesConvertedPosition {
					stream_id: row.get(0)?,
					room_id: row.get(1)?,
					instance_name: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn device_list_changes_max_pruned(
		&self,
	) -> Result<Vec<SynapseDeviceListChangesMaxPruned>> {
		if !self.table_exists("device_lists_changes_in_room_max_pruned_stream_id")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id
				FROM device_lists_changes_in_room_max_pruned_stream_id
				ORDER BY stream_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDeviceListChangesMaxPruned {
					stream_id: row.get(0)?,
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

	pub fn push_rules_stream(&self) -> Result<Vec<SynapsePushRulesStream>> {
		if !self.table_exists("push_rules_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("push_rules_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, event_stream_ordering, user_id, rule_id, op,
			       priority_class, priority, conditions, actions, {instance_name}
			FROM push_rules_stream
			ORDER BY stream_id, user_id, rule_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let conditions: Option<String> = row.get(7)?;
				let actions: Option<String> = row.get(8)?;
				Ok(SynapsePushRulesStream {
					stream_id: row.get(0)?,
					event_stream_ordering: row.get(1)?,
					user_id: row.get(2)?,
					rule_id: row.get(3)?,
					op: row.get(4)?,
					priority_class: row.get(5)?,
					priority: row.get(6)?,
					conditions: conditions
						.and_then(|json| serde_json::from_str(&json).ok()),
					actions: actions.and_then(|json| serde_json::from_str(&json).ok()),
					instance_name: row.get(9)?,
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

	pub fn room_tag_revisions(&self) -> Result<Vec<SynapseRoomTagRevision>> {
		if !self.table_exists("room_tags_revisions")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, room_id, stream_id, instance_name
				FROM room_tags_revisions
				ORDER BY user_id, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomTagRevision {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
					stream_id: row.get(2)?,
					instance_name: row.get(3)?,
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

	pub fn event_auth(&self) -> Result<Vec<SynapseEventAuth>> {
		if !self.table_exists("event_auth")? {
			return Ok(Vec::new());
		}

		let room_id = if self.columns("event_auth")?.contains("room_id") {
			"room_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT event_id, auth_id, {room_id}
			FROM event_auth
			ORDER BY event_id, auth_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventAuth {
					event_id: row.get(0)?,
					auth_id: row.get(1)?,
					room_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_auth_chains(&self) -> Result<Vec<SynapseEventAuthChain>> {
		if !self.table_exists("event_auth_chains")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, chain_id, sequence_number
				FROM event_auth_chains
				ORDER BY event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventAuthChain {
					event_id: row.get(0)?,
					chain_id: row.get(1)?,
					sequence_number: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_auth_chain_links(&self) -> Result<Vec<SynapseEventAuthChainLink>> {
		if !self.table_exists("event_auth_chain_links")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT origin_chain_id, origin_sequence_number, target_chain_id,
				       target_sequence_number
				FROM event_auth_chain_links
				ORDER BY origin_chain_id, origin_sequence_number, target_chain_id,
				         target_sequence_number
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventAuthChainLink {
					origin_chain_id: row.get(0)?,
					origin_sequence_number: row.get(1)?,
					target_chain_id: row.get(2)?,
					target_sequence_number: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_auth_chain_to_calculate(&self) -> Result<Vec<SynapseEventAuthChainToCalculate>> {
		if !self.table_exists("event_auth_chain_to_calculate")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, room_id, type, state_key
				FROM event_auth_chain_to_calculate
				ORDER BY room_id, type, state_key, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventAuthChainToCalculate {
					event_id: row.get(0)?,
					room_id: row.get(1)?,
					event_type: row.get(2)?,
					state_key: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn rejected_events(&self) -> Result<Vec<SynapseRejectedEvent>> {
		if !self.table_exists("rejections")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, reason, last_check
				FROM rejections
				ORDER BY event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRejectedEvent {
					event_id: row.get(0)?,
					reason: row.get(1)?,
					last_check: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn backward_extremities(&self) -> Result<Vec<SynapseBackwardExtremity>> {
		if !self.table_exists("event_backward_extremities")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, room_id
				FROM event_backward_extremities
				ORDER BY room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseBackwardExtremity {
					event_id: row.get(0)?,
					room_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn timeline_gaps(&self) -> Result<Vec<SynapseTimelineGap>> {
		if !self.table_exists("timeline_gaps")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, instance_name, stream_ordering
				FROM timeline_gaps
				ORDER BY room_id, stream_ordering, instance_name
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseTimelineGap {
					room_id: row.get(0)?,
					instance_name: row.get(1)?,
					stream_ordering: row.get(2)?,
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

	pub fn current_state_delta_stream(&self) -> Result<Vec<SynapseCurrentStateDelta>> {
		if !self.table_exists("current_state_delta_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self
			.columns("current_state_delta_stream")?
			.contains("instance_name")
		{
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT stream_id, room_id, type, state_key, event_id, prev_event_id,
			       {instance_name}
			FROM current_state_delta_stream
			ORDER BY stream_id, room_id, type, state_key
			"
		);
		let mut stmt = self.conn.prepare(&query).map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseCurrentStateDelta {
					stream_id: row.get(0)?,
					room_id: row.get(1)?,
					event_type: row.get(2)?,
					state_key: row.get(3)?,
					event_id: row.get(4)?,
					prev_event_id: row.get(5)?,
					instance_name: row.get(6)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn stream_ordering_to_extremity(&self) -> Result<Vec<SynapseStreamOrderingExtremity>> {
		if !self.table_exists("stream_ordering_to_exterm")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_ordering, room_id, event_id
				FROM stream_ordering_to_exterm
				ORDER BY stream_ordering, room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStreamOrderingExtremity {
					stream_ordering: row.get(0)?,
					room_id: row.get(1)?,
					event_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn ex_outlier_stream(&self) -> Result<Vec<SynapseExOutlierStream>> {
		if !self.table_exists("ex_outlier_stream")? {
			return Ok(Vec::new());
		}

		let instance_name = if self.columns("ex_outlier_stream")?.contains("instance_name") {
			"instance_name"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT event_stream_ordering, event_id, state_group, {instance_name}
			FROM ex_outlier_stream
			ORDER BY event_stream_ordering
			"
		);
		let mut stmt = self.conn.prepare(&query).map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseExOutlierStream {
					event_stream_ordering: row.get(0)?,
					event_id: row.get(1)?,
					state_group: row.get(2)?,
					instance_name: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn state_groups(&self) -> Result<Vec<SynapseStateGroup>> {
		if !self.table_exists("state_groups")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT id, room_id, event_id
				FROM state_groups
				ORDER BY id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStateGroup {
					id: row.get(0)?,
					room_id: row.get(1)?,
					event_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn state_group_edges(&self) -> Result<Vec<SynapseStateGroupEdge>> {
		if !self.table_exists("state_group_edges")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT state_group, prev_state_group
				FROM state_group_edges
				ORDER BY state_group, prev_state_group
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStateGroupEdge {
					state_group: row.get(0)?,
					prev_state_group: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_to_state_groups(&self) -> Result<Vec<SynapseEventToStateGroup>> {
		if !self.table_exists("event_to_state_groups")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT event_id, state_group
				FROM event_to_state_groups
				ORDER BY event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventToStateGroup {
					event_id: row.get(0)?,
					state_group: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn state_groups_state(&self) -> Result<Vec<SynapseStateGroupState>> {
		if !self.table_exists("state_groups_state")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT state_group, room_id, type, state_key, event_id
				FROM state_groups_state
				ORDER BY state_group, type, state_key
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStateGroupState {
					state_group: row.get(0)?,
					room_id: row.get(1)?,
					event_type: row.get(2)?,
					state_key: row.get(3)?,
					event_id: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
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
			"NULL"
		};
		let query = format!(
			"
			SELECT room_id, user_id, event_id, membership, {event_stream_ordering}
			FROM local_current_membership
			ORDER BY room_id, user_id
			"
		);

		let mut stmt = self.conn.prepare(&query).map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseLocalCurrentMembership {
					room_id: row.get(0)?,
					user_id: row.get(1)?,
					event_id: row.get(2)?,
					membership: row.get(3)?,
					event_stream_ordering: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn partial_state_rooms(&self) -> Result<Vec<SynapsePartialStateRoom>> {
		if !self.table_exists("partial_state_rooms")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("partial_state_rooms")?;
		let device_lists_stream_id = if columns.contains("device_lists_stream_id") {
			"device_lists_stream_id"
		} else {
			"NULL"
		};
		let join_event_id = if columns.contains("join_event_id") {
			"join_event_id"
		} else {
			"NULL"
		};
		let joined_via = if columns.contains("joined_via") {
			"joined_via"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT room_id, {device_lists_stream_id}, {join_event_id}, {joined_via}
			FROM partial_state_rooms
			ORDER BY room_id
			"
		);
		let mut stmt = self.conn.prepare(&query).map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapsePartialStateRoom {
					room_id: row.get(0)?,
					device_lists_stream_id: row.get(1)?,
					join_event_id: row.get(2)?,
					joined_via: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn partial_state_room_servers(&self) -> Result<Vec<SynapsePartialStateRoomServer>> {
		if !self.table_exists("partial_state_rooms_servers")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, server_name
				FROM partial_state_rooms_servers
				ORDER BY room_id, server_name
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapsePartialStateRoomServer {
					room_id: row.get(0)?,
					server_name: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn partial_state_events(&self) -> Result<Vec<SynapsePartialStateEvent>> {
		if !self.table_exists("partial_state_events")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, event_id
				FROM partial_state_events
				ORDER BY room_id, event_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapsePartialStateEvent {
					room_id: row.get(0)?,
					event_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn un_partial_stated_rooms(&self) -> Result<Vec<SynapseUnPartialStatedRoom>> {
		if !self.table_exists("un_partial_stated_room_stream")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, instance_name, room_id
				FROM un_partial_stated_room_stream
				ORDER BY stream_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUnPartialStatedRoom {
					stream_id: row.get(0)?,
					instance_name: row.get(1)?,
					room_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn un_partial_stated_events(&self) -> Result<Vec<SynapseUnPartialStatedEvent>> {
		if !self.table_exists("un_partial_stated_event_stream")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_id, instance_name, event_id, rejection_status_changed
				FROM un_partial_stated_event_stream
				ORDER BY stream_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUnPartialStatedEvent {
					stream_id: row.get(0)?,
					instance_name: row.get(1)?,
					event_id: row.get(2)?,
					rejection_status_changed: row.get(3)?,
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

	pub fn room_metadata(&self) -> Result<Vec<SynapseRoomMetadata>> {
		if !self.table_exists("rooms")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("rooms")?;
		let is_public = if columns.contains("is_public") {
			"is_public"
		} else {
			"NULL"
		};
		let creator = if columns.contains("creator") {
			"creator"
		} else {
			"NULL"
		};
		let room_version = if columns.contains("room_version") {
			"room_version"
		} else {
			"NULL"
		};
		let has_auth_chain_index = if columns.contains("has_auth_chain_index") {
			"has_auth_chain_index"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT room_id, {is_public}, {creator}, {room_version}, {has_auth_chain_index}
			FROM rooms
			ORDER BY room_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomMetadata {
					room_id: row.get(0)?,
					is_public: optional_int_bool(row, 1)?,
					creator: row.get(2)?,
					room_version: row.get(3)?,
					has_auth_chain_index: optional_int_bool(row, 4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_depths(&self) -> Result<Vec<SynapseRoomDepth>> {
		if !self.table_exists("room_depth")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, min_depth
				FROM room_depth
				ORDER BY room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomDepth {
					room_id: row.get(0)?,
					min_depth: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn users_in_public_rooms(&self) -> Result<Vec<SynapseUsersInPublicRoom>> {
		if !self.table_exists("users_in_public_rooms")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, room_id
				FROM users_in_public_rooms
				ORDER BY user_id, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUsersInPublicRoom {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn users_who_share_private_rooms(&self) -> Result<Vec<SynapseUsersWhoSharePrivateRoom>> {
		if !self.table_exists("users_who_share_private_rooms")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, other_user_id, room_id
				FROM users_who_share_private_rooms
				ORDER BY user_id, other_user_id, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUsersWhoSharePrivateRoom {
					user_id: row.get(0)?,
					other_user_id: row.get(1)?,
					room_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_directory(&self) -> Result<Vec<SynapseUserDirectoryEntry>> {
		if !self.table_exists("user_directory")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, room_id, display_name, avatar_url
				FROM user_directory
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserDirectoryEntry {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
					display_name: row.get(2)?,
					avatar_url: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_directory_search(&self) -> Result<Vec<SynapseUserDirectorySearch>> {
		if !self.table_exists("user_directory_search")? {
			return Ok(Vec::new());
		}

		let vector = if self.columns("user_directory_search")?.contains("vector") {
			"vector"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, {vector}
			FROM user_directory_search
			ORDER BY user_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserDirectorySearch {
					user_id: row.get(0)?,
					vector: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_directory_stale_remote_users(
		&self,
	) -> Result<Vec<SynapseUserDirectoryStaleRemoteUser>> {
		if !self.table_exists("user_directory_stale_remote_users")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT user_id, user_server_name, next_try_at_ts, retry_counter
				FROM user_directory_stale_remote_users
				ORDER BY user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserDirectoryStaleRemoteUser {
					user_id: row.get(0)?,
					user_server_name: row.get(1)?,
					next_try_at_ts: row.get(2)?,
					retry_counter: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn user_directory_stream_positions(
		&self,
	) -> Result<Vec<SynapseUserDirectoryStreamPosition>> {
		if !self.table_exists("user_directory_stream_pos")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, stream_id
				FROM user_directory_stream_pos
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseUserDirectoryStreamPosition {
					lock: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_stats_current(&self) -> Result<Vec<SynapseRoomStatsCurrent>> {
		if !self.table_exists("room_stats_current")? {
			return Ok(Vec::new());
		}

		let knocked_members = if self.columns("room_stats_current")?.contains("knocked_members") {
			"knocked_members"
		} else {
			"NULL"
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
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomStatsCurrent {
					room_id: row.get(0)?,
					current_state_events: row.get(1)?,
					joined_members: row.get(2)?,
					invited_members: row.get(3)?,
					left_members: row.get(4)?,
					banned_members: row.get(5)?,
					local_users_in_room: row.get(6)?,
					completed_delta_stream_id: row.get(7)?,
					knocked_members: row.get(8)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_stats_state(&self) -> Result<Vec<SynapseRoomStatsState>> {
		if !self.table_exists("room_stats_state")? {
			return Ok(Vec::new());
		}

		let room_type = if self.columns("room_stats_state")?.contains("room_type") {
			"room_type"
		} else {
			"NULL"
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
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomStatsState {
					room_id: row.get(0)?,
					name: row.get(1)?,
					canonical_alias: row.get(2)?,
					join_rules: row.get(3)?,
					history_visibility: row.get(4)?,
					encryption: row.get(5)?,
					avatar: row.get(6)?,
					guest_access: row.get(7)?,
					is_federatable: row.get(8)?,
					topic: row.get(9)?,
					room_type: row.get(10)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_stats_earliest_tokens(&self) -> Result<Vec<SynapseRoomStatsEarliestToken>> {
		if !self.table_exists("room_stats_earliest_token")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, token
				FROM room_stats_earliest_token
				ORDER BY room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomStatsEarliestToken {
					room_id: row.get(0)?,
					token: row.get(1)?,
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

	pub fn receipts_graph(&self) -> Result<Vec<SynapseReceiptGraph>> {
		if !self.table_exists("receipts_graph")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, receipt_type, user_id, event_ids, data, thread_id
				FROM receipts_graph
				ORDER BY room_id, receipt_type, user_id, thread_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let event_ids: String = row.get(3)?;
				let data: String = row.get(4)?;
				Ok(SynapseReceiptGraph {
					room_id: row.get(0)?,
					receipt_type: row.get(1)?,
					user_id: row.get(2)?,
					event_ids: serde_json::from_str(&event_ids).unwrap_or_default(),
					data: serde_json::from_str(&data).unwrap_or(Value::Null),
					thread_id: row.get(5)?,
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

	pub fn event_push_summaries(&self) -> Result<Vec<SynapseEventPushSummary>> {
		if !self.table_exists("event_push_summary")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("event_push_summary")?;
		let unread_count = if columns.contains("unread_count") {
			"unread_count"
		} else {
			"NULL"
		};
		let last_receipt_stream_ordering = if columns.contains("last_receipt_stream_ordering") {
			"last_receipt_stream_ordering"
		} else {
			"NULL"
		};
		let thread_id = if columns.contains("thread_id") {
			"thread_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT user_id, room_id, notif_count, stream_ordering, {unread_count},
			       {last_receipt_stream_ordering}, {thread_id}
			FROM event_push_summary
			ORDER BY user_id, room_id, stream_ordering
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventPushSummary {
					user_id: row.get(0)?,
					room_id: row.get(1)?,
					notif_count: row.get(2)?,
					stream_ordering: row.get(3)?,
					unread_count: row.get(4)?,
					last_receipt_stream_ordering: row.get(5)?,
					thread_id: row.get(6)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_push_actions(&self) -> Result<Vec<SynapseEventPushAction>> {
		if !self.table_exists("event_push_actions")? {
			return Ok(Vec::new());
		}

		let thread_id = if self.columns("event_push_actions")?.contains("thread_id") {
			"thread_id"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT room_id, event_id, user_id, profile_tag, actions, topological_ordering,
			       stream_ordering, notif, highlight, unread, {thread_id}
			FROM event_push_actions
			ORDER BY stream_ordering, room_id, event_id, user_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let actions: String = row.get(4)?;
				Ok(SynapseEventPushAction {
					room_id: row.get(0)?,
					event_id: row.get(1)?,
					user_id: row.get(2)?,
					profile_tag: row.get(3)?,
					actions: serde_json::from_str(&actions).unwrap_or(Value::Null),
					topological_ordering: row.get(5)?,
					stream_ordering: row.get(6)?,
					notif: optional_int_bool(row, 7)?,
					highlight: optional_int_bool(row, 8)?,
					unread: optional_int_bool(row, 9)?,
					thread_id: row.get(10)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_push_actions_staging(&self) -> Result<Vec<SynapseEventPushActionStaging>> {
		if !self.table_exists("event_push_actions_staging")? {
			return Ok(Vec::new());
		}

		let columns = self.columns("event_push_actions_staging")?;
		let thread_id = if columns.contains("thread_id") {
			"thread_id"
		} else {
			"NULL"
		};
		let inserted_ts = if columns.contains("inserted_ts") {
			"inserted_ts"
		} else {
			"NULL"
		};
		let query = format!(
			"
			SELECT event_id, user_id, actions, notif, highlight, unread, {thread_id}, {inserted_ts}
			FROM event_push_actions_staging
			ORDER BY event_id, user_id
			"
		);
		let mut stmt = self
			.conn
			.prepare(&query)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let actions: String = row.get(2)?;
				Ok(SynapseEventPushActionStaging {
					event_id: row.get(0)?,
					user_id: row.get(1)?,
					actions: serde_json::from_str(&actions).unwrap_or(Value::Null),
					notif: int_bool(row, 3)?,
					highlight: int_bool(row, 4)?,
					unread: optional_int_bool(row, 5)?,
					thread_id: row.get(6)?,
					inserted_ts: row.get(7)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_push_summary_stream_positions(
		&self,
	) -> Result<Vec<SynapseEventPushSummaryStreamPosition>> {
		if !self.table_exists("event_push_summary_stream_ordering")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT Lock, stream_ordering
				FROM event_push_summary_stream_ordering
				ORDER BY Lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventPushSummaryStreamPosition {
					lock: row.get(0)?,
					stream_ordering: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connections(&self) -> Result<Vec<SynapseSlidingSyncConnection>> {
		if !self.table_exists("sliding_sync_connections")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT connection_key, user_id, effective_device_id, conn_id, created_ts, last_used_ts
				FROM sliding_sync_connections
				ORDER BY connection_key
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncConnection {
					connection_key: row.get(0)?,
					user_id: row.get(1)?,
					effective_device_id: row.get(2)?,
					conn_id: row.get(3)?,
					created_ts: row.get(4)?,
					last_used_ts: row.get(5)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connection_positions(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionPosition>> {
		if !self.table_exists("sliding_sync_connection_positions")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT connection_position, connection_key, created_ts
				FROM sliding_sync_connection_positions
				ORDER BY connection_position
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncConnectionPosition {
					connection_position: row.get(0)?,
					connection_key: row.get(1)?,
					created_ts: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connection_streams(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionStream>> {
		if !self.table_exists("sliding_sync_connection_streams")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT connection_position, stream, room_id, room_status, last_token
				FROM sliding_sync_connection_streams
				ORDER BY connection_position, stream, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncConnectionStream {
					connection_position: row.get(0)?,
					stream: row.get(1)?,
					room_id: row.get(2)?,
					room_status: row.get(3)?,
					last_token: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connection_room_configs(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionRoomConfig>> {
		if !self.table_exists("sliding_sync_connection_room_configs")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT connection_position, room_id, timeline_limit, required_state_id
				FROM sliding_sync_connection_room_configs
				ORDER BY connection_position, room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncConnectionRoomConfig {
					connection_position: row.get(0)?,
					room_id: row.get(1)?,
					timeline_limit: row.get(2)?,
					required_state_id: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connection_required_state(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionRequiredState>> {
		if !self.table_exists("sliding_sync_connection_required_state")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT required_state_id, connection_key, required_state
				FROM sliding_sync_connection_required_state
				ORDER BY required_state_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let required_state: String = row.get(2)?;
				Ok(SynapseSlidingSyncConnectionRequiredState {
					required_state_id: row.get(0)?,
					connection_key: row.get(1)?,
					required_state: serde_json::from_str(&required_state).unwrap_or(Value::Null),
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_connection_lazy_members(
		&self,
	) -> Result<Vec<SynapseSlidingSyncConnectionLazyMember>> {
		if !self.table_exists("sliding_sync_connection_lazy_members")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT connection_key, connection_position, room_id, user_id, last_seen_ts
				FROM sliding_sync_connection_lazy_members
				ORDER BY connection_key, room_id, user_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncConnectionLazyMember {
					connection_key: row.get(0)?,
					connection_position: row.get(1)?,
					room_id: row.get(2)?,
					user_id: row.get(3)?,
					last_seen_ts: row.get(4)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_membership_snapshots(
		&self,
	) -> Result<Vec<SynapseSlidingSyncMembershipSnapshot>> {
		if !self.table_exists("sliding_sync_membership_snapshots")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, user_id, sender, membership_event_id, membership, forgotten,
				       event_stream_ordering, event_instance_name, has_known_state, room_type,
				       room_name, is_encrypted, tombstone_successor_room_id
				FROM sliding_sync_membership_snapshots
				ORDER BY room_id, user_id, event_stream_ordering
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncMembershipSnapshot {
					room_id: row.get(0)?,
					user_id: row.get(1)?,
					sender: row.get(2)?,
					membership_event_id: row.get(3)?,
					membership: row.get(4)?,
					forgotten: int_bool(row, 5)?,
					event_stream_ordering: row.get(6)?,
					event_instance_name: row.get(7)?,
					has_known_state: int_bool(row, 8)?,
					room_type: row.get(9)?,
					room_name: row.get(10)?,
					is_encrypted: int_bool(row, 11)?,
					tombstone_successor_room_id: row.get(12)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_joined_rooms(&self) -> Result<Vec<SynapseSlidingSyncJoinedRoom>> {
		if !self.table_exists("sliding_sync_joined_rooms")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id, event_stream_ordering, bump_stamp, room_type, room_name,
				       is_encrypted, tombstone_successor_room_id
				FROM sliding_sync_joined_rooms
				ORDER BY room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncJoinedRoom {
					room_id: row.get(0)?,
					event_stream_ordering: row.get(1)?,
					bump_stamp: row.get(2)?,
					room_type: row.get(3)?,
					room_name: row.get(4)?,
					is_encrypted: int_bool(row, 5)?,
					tombstone_successor_room_id: row.get(6)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn sliding_sync_joined_rooms_to_recalculate(
		&self,
	) -> Result<Vec<SynapseSlidingSyncJoinedRoomToRecalculate>> {
		if !self.table_exists("sliding_sync_joined_rooms_to_recalculate")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT room_id
				FROM sliding_sync_joined_rooms_to_recalculate
				ORDER BY room_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSlidingSyncJoinedRoomToRecalculate {
					room_id: row.get(0)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn stream_positions(&self) -> Result<Vec<SynapseStreamPosition>> {
		if !self.table_exists("stream_positions")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT stream_name, instance_name, stream_id
				FROM stream_positions
				ORDER BY stream_name, instance_name
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStreamPosition {
					stream_name: row.get(0)?,
					instance_name: row.get(1)?,
					stream_id: row.get(2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn delayed_events_stream_positions(
		&self,
	) -> Result<Vec<SynapseDelayedEventsStreamPosition>> {
		if !self.table_exists("delayed_events_stream_pos")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, stream_id
				FROM delayed_events_stream_pos
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseDelayedEventsStreamPosition {
					lock: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn event_push_summary_last_receipt_stream_ids(
		&self,
	) -> Result<Vec<SynapseEventPushSummaryLastReceiptStreamId>> {
		if !self.table_exists("event_push_summary_last_receipt_stream_id")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, stream_id
				FROM event_push_summary_last_receipt_stream_id
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseEventPushSummaryLastReceiptStreamId {
					lock: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn room_forgetter_stream_positions(
		&self,
	) -> Result<Vec<SynapseRoomForgetterStreamPosition>> {
		if !self.table_exists("room_forgetter_stream_pos")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, stream_id
				FROM room_forgetter_stream_pos
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseRoomForgetterStreamPosition {
					lock: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn stats_incremental_positions(&self) -> Result<Vec<SynapseStatsIncrementalPosition>> {
		if !self.table_exists("stats_incremental_position")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, stream_id
				FROM stats_incremental_position
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseStatsIncrementalPosition {
					lock: row.get(0)?,
					stream_id: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn applied_schema_deltas(&self) -> Result<Vec<SynapseAppliedSchemaDelta>> {
		if !self.table_exists("applied_schema_deltas")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT version, file
				FROM applied_schema_deltas
				ORDER BY version, file
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseAppliedSchemaDelta {
					version: row.get(0)?,
					file: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn schema_versions(&self) -> Result<Vec<SynapseSchemaVersion>> {
		if !self.table_exists("schema_version")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, version, upgraded
				FROM schema_version
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSchemaVersion {
					lock: row.get(0)?,
					version: row.get(1)?,
					upgraded: int_bool(row, 2)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn schema_compat_versions(&self) -> Result<Vec<SynapseSchemaCompatVersion>> {
		if !self.table_exists("schema_compat_version")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT lock, compat_version
				FROM schema_compat_version
				ORDER BY lock
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseSchemaCompatVersion {
					lock: row.get(0)?,
					compat_version: row.get(1)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn background_updates(&self) -> Result<Vec<SynapseBackgroundUpdate>> {
		if !self.table_exists("background_updates")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT update_name, progress_json, depends_on, ordering
				FROM background_updates
				ORDER BY ordering, update_name
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let progress_json: String = row.get(1)?;
				Ok(SynapseBackgroundUpdate {
					update_name: row.get(0)?,
					progress_json: serde_json::from_str(&progress_json).unwrap_or(Value::Null),
					depends_on: row.get(2)?,
					ordering: row.get(3)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
	}

	pub fn scheduled_tasks(&self) -> Result<Vec<SynapseScheduledTask>> {
		if !self.table_exists("scheduled_tasks")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT id, action, status, timestamp, resource_id, params, result, error
				FROM scheduled_tasks
				ORDER BY timestamp, id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				let params: Option<String> = row.get(5)?;
				let result: Option<String> = row.get(6)?;
				Ok(SynapseScheduledTask {
					id: row.get(0)?,
					action: row.get(1)?,
					status: row.get(2)?,
					timestamp: row.get(3)?,
					resource_id: row.get(4)?,
					params: params.and_then(|json| serde_json::from_str(&json).ok()),
					result: result.and_then(|json| serde_json::from_str(&json).ok()),
					error: row.get(7)?,
				})
			})
			.map_err(|e| Error::sqlite(&self.path, e))?;

		collect_rows(&self.path, rows)
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

	pub fn server_signature_keys(&self) -> Result<Vec<SynapseServerSignatureKey>> {
		if !self.table_exists("server_signature_keys")? {
			return Ok(Vec::new());
		}

		let mut stmt = self
			.conn
			.prepare(
				"
				SELECT server_name, key_id, from_server, ts_added_ms, verify_key,
				       ts_valid_until_ms
				FROM server_signature_keys
				ORDER BY server_name, key_id
				",
			)
			.map_err(|e| Error::sqlite(&self.path, e))?;
		let rows = stmt
			.query_map([], |row| {
				Ok(SynapseServerSignatureKey {
					server_name: row.get(0)?,
					key_id: row.get(1)?,
					from_server: row.get(2)?,
					ts_added_ms: row.get(3)?,
					verify_key: optional_bytes(row, 4)?,
					ts_valid_until_ms: row.get(5)?,
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

fn optional_int_bool(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<bool>> {
	row.get::<_, Option<i64>>(index)
		.map(|value| value.map(|value| value != 0))
}

fn optional_bytes(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<Vec<u8>>> {
	Ok(match row.get_ref(index)? {
		| ValueRef::Null => None,
		| ValueRef::Blob(bytes) | ValueRef::Text(bytes) => Some(bytes.to_vec()),
		| ValueRef::Integer(value) => Some(value.to_string().into_bytes()),
		| ValueRef::Real(value) => Some(value.to_string().into_bytes()),
	})
}

fn optional_string_list(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<Vec<String>>> {
	Ok(match row.get_ref(index)? {
		| ValueRef::Null => None,
		| ValueRef::Blob(bytes) | ValueRef::Text(bytes) => serde_json::from_slice(bytes).ok(),
		| _ => None,
	})
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
