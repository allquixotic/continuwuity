use std::{
	collections::{BTreeMap, BTreeSet},
	fs,
	path::{Path, PathBuf},
	time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use conduwuit_core::utils::hash;
use conduwuit_database as database;
use database::serialize_to_vec;
use rust_rocksdb as rocksdb;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
	Error, Result,
	sqlite::{
		SynapseAccessToken, SynapseAccountData, SynapseDevice, SynapseMedia, SynapseProfile,
		SynapsePusher, SynapseReceipt, SynapseRoomEvent, SynapseRoomState, SynapseUser,
	},
};

const REQUIRED_CFS: &[&str] = &[
	"global",
	"userid_password",
	"userid_displayname",
	"userid_avatarurl",
	"userid_devicelistversion",
	"userdeviceid_metadata",
	"userdeviceid_token",
	"token_userdeviceid",
	"roomuserdataid_accountdata",
	"roomusertype_roomuserdataid",
	"mediaid_file",
	"mediaid_user",
	"roomid_shortroomid",
	"eventid_shorteventid",
	"shorteventid_eventid",
	"eventid_pduid",
	"pduid_pdu",
	"statekey_shortstatekey",
	"shortstatekey_statekey",
	"shorteventid_shortstatehash",
	"roomid_shortstatehash",
	"shortstatehash_statediff",
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
	"roomuserid_privateread",
	"roomuserid_lastprivatereadupdate",
	"senderkey_pusher",
	"pushkey_deviceid",
];

#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
	pub users: u64,
	pub profiles: u64,
	pub devices: u64,
	pub access_tokens: u64,
	pub account_data: u64,
	pub media: u64,
	pub room_events: u64,
	pub room_state: u64,
	pub receipts: u64,
	pub pushers: u64,
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
		password_pepper: Option<&str>,
		report: &mut ImportReport,
	) -> Result<()> {
		let pepper = password_pepper.unwrap_or_default();
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
			report.users = report.users.saturating_add(1);
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

			let count = self.next_count()?;
			let data_key = serialize_account_data_key(
				row.room_id.as_deref(),
				&row.user_id,
				count,
				&row.event_type,
			)?;
			let index_key =
				serialize_account_data_index(row.room_id.as_deref(), &row.user_id, &row.event_type)?;
			let value = serde_json::to_vec(&json!({
				"type": row.event_type,
				"content": row.content,
			}))?;

			self.put_raw("roomuserdataid_accountdata", &data_key, &value)?;
			self.put_raw("roomusertype_roomuserdataid", &index_key, &data_key)?;
			report.account_data = report.account_data.saturating_add(1);
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

	#[cfg(test)]
	pub fn get_raw(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
		self.get_raw_cf(cf, key)
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
			"Imported users={} profiles={} devices={} access_tokens={} account_data={} media={} room_events={} room_state={} receipts={} pushers={} skipped={}",
			self.users,
			self.profiles,
			self.devices,
			self.access_tokens,
			self.account_data,
			self.media,
			self.room_events,
			self.room_state,
			self.receipts,
			self.pushers,
			self.skipped.values().sum::<u64>(),
		)
	}
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

fn positive_stream_ordering(stream_ordering: Option<i64>) -> Option<u64> {
	stream_ordering
		.and_then(|stream_ordering| u64::try_from(stream_ordering).ok())
		.filter(|stream_ordering| *stream_ordering != 0)
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

fn pdu_id(shortroomid: u64, shorteventid: u64) -> Vec<u8> {
	let mut pdu_id = Vec::with_capacity(16);
	pdu_id.extend_from_slice(&shortroomid.to_be_bytes());
	pdu_id.extend_from_slice(&shorteventid.to_be_bytes());
	pdu_id
}
