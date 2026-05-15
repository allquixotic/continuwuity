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
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
	Error, Result,
	sqlite::{
		SynapseAccessToken, SynapseAccountData, SynapseDevice, SynapseMedia, SynapseProfile,
		SynapseUser,
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
];

#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
	pub users: u64,
	pub profiles: u64,
	pub devices: u64,
	pub access_tokens: u64,
	pub account_data: u64,
	pub media: u64,
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

	#[cfg(test)]
	pub fn get_raw(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
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
			"Imported users={} profiles={} devices={} access_tokens={} account_data={} media={} skipped={}",
			self.users,
			self.profiles,
			self.devices,
			self.access_tokens,
			self.account_data,
			self.media,
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
