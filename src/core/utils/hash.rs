mod argon;
pub mod sha256;
mod synapse;

use crate::Result;

pub fn verify_password(password: &str, password_hash: &str) -> Result {
	if synapse::is_synapse_bcrypt_hash(password_hash) {
		synapse::verify_bcrypt_password(password, password_hash)
	} else {
		argon::verify_password(password, password_hash)
	}
}

pub fn password(password: &str) -> Result<String> {
	argon::password(password)
}

pub fn synapse_bcrypt_password_hash(password_hash: &str, pepper: &str) -> Result<String> {
	synapse::encode_bcrypt_hash(password_hash, pepper)
}
