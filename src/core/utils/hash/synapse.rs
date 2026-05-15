use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use unicode_normalization::UnicodeNormalization;

use crate::{Result, err};

const PREFIX: &str = "$synapse$bcrypt$";
const BCRYPT_INPUT_LIMIT: usize = 72;

pub(super) fn is_synapse_bcrypt_hash(password_hash: &str) -> bool {
	password_hash.starts_with(PREFIX)
}

pub(super) fn encode_bcrypt_hash(password_hash: &str, pepper: &str) -> Result<String> {
	if !password_hash.starts_with("$2") {
		return Err(err!("Synapse bcrypt hash must start with '$2'."));
	}

	let pepper = BASE64_URL_SAFE_NO_PAD.encode(pepper.as_bytes());
	Ok(format!("{PREFIX}{pepper}${password_hash}"))
}

pub(super) fn verify_bcrypt_password(password: &str, encoded_hash: &str) -> Result {
	let (pepper, password_hash) = encoded_hash
		.strip_prefix(PREFIX)
		.and_then(|value| value.split_once('$'))
		.ok_or_else(|| err!("Malformed Synapse bcrypt password hash."))?;

	let pepper = BASE64_URL_SAFE_NO_PAD
		.decode(pepper)
		.map_err(|e| err!("Malformed Synapse bcrypt pepper: {e}"))?;

	let mut password = password.nfkc().collect::<String>().into_bytes();
	password.extend_from_slice(&pepper);
	password.truncate(BCRYPT_INPUT_LIMIT);

	bcrypt::verify(password, &format!("${password_hash}"))
		.map_err(|e| err!("Synapse bcrypt password verification failed: {e}"))?
		.then_some(())
		.ok_or_else(|| err!("Invalid identifier or password."))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn verifies_synapse_bcrypt_hash_without_pepper() {
		let password = "correct horse battery staple";
		let password_hash = bcrypt::hash(password, 4).expect("bcrypt hash");
		let encoded = encode_bcrypt_hash(&password_hash, "").expect("encoded hash");

		verify_bcrypt_password(password, &encoded).expect("password should verify");
	}

	#[test]
	fn verifies_synapse_bcrypt_hash_with_pepper() {
		let password = "p\u{212b}ssword";
		let pepper = "server-side pepper";
		let mut preimage = "p\u{00c5}ssword".as_bytes().to_vec();
		preimage.extend_from_slice(pepper.as_bytes());
		let password_hash = bcrypt::hash(preimage, 4).expect("bcrypt hash");
		let encoded = encode_bcrypt_hash(&password_hash, pepper).expect("encoded hash");

		verify_bcrypt_password(password, &encoded).expect("password should verify");
	}

	#[test]
	fn rejects_wrong_synapse_bcrypt_password() {
		let password_hash = bcrypt::hash("right", 4).expect("bcrypt hash");
		let encoded = encode_bcrypt_hash(&password_hash, "").expect("encoded hash");

		assert!(verify_bcrypt_password("wrong", &encoded).is_err());
	}

	#[test]
	fn rejects_non_bcrypt_hash_when_encoding() {
		assert!(encode_bcrypt_hash("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$hash", "").is_err());
	}
}
