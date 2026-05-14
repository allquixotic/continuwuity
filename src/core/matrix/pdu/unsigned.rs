use std::{borrow::Borrow, collections::BTreeMap};

use ruma::{MilliSecondsSinceUnixEpoch, events::room::member::MembershipState};
use serde_json::value::{RawValue as RawJsonValue, Value as JsonValue, to_raw_value};

use super::Pdu;
use crate::{Result, err, implement, result::LogErr};

/// Set the `unsigned` field of the PDU using only information in the PDU.
/// Some unsigned data is already set within the database (eg. prev events,
/// threads). Once this is done, other data must be calculated from the database
/// (eg. relations) This is for server-to-client events.
/// Backfill handles this itself.
#[implement(Pdu)]
pub fn set_unsigned(&mut self, user_id: Option<&ruma::UserId>) {
	if Some(self.sender.borrow()) != user_id {
		self.remove_transaction_id().log_err().ok();
	}
	self.add_age().log_err().ok();
}

#[implement(Pdu)]
pub fn remove_transaction_id(&mut self) -> Result {
	use BTreeMap as Map;

	let Some(unsigned) = &self.unsigned else {
		return Ok(());
	};

	let mut unsigned: Map<&str, Box<RawJsonValue>> = serde_json::from_str(unsigned.get())
		.map_err(|e| err!(Database("Invalid unsigned in pdu event: {e}")))?;

	unsigned.remove("transaction_id");
	self.unsigned = to_raw_value(&unsigned)
		.map(Some)
		.expect("unsigned is valid");

	Ok(())
}

#[implement(Pdu)]
pub fn add_age(&mut self) -> Result {
	use BTreeMap as Map;

	let mut unsigned: Map<&str, Box<RawJsonValue>> = self
		.unsigned
		.as_deref()
		.map(RawJsonValue::get)
		.map_or_else(|| Ok(Map::new()), serde_json::from_str)
		.map_err(|e| err!(Database("Invalid unsigned in pdu event: {e}")))?;

	// deliberately allowing for the possibility of negative age
	let now: i128 = MilliSecondsSinceUnixEpoch::now().get().into();
	let then: i128 = self.origin_server_ts.into();
	let this_age = now.saturating_sub(then);

	unsigned.insert("age", to_raw_value(&this_age)?);
	self.unsigned = Some(to_raw_value(&unsigned)?);

	Ok(())
}

#[implement(Pdu)]
pub fn add_membership(&mut self, membership: MembershipState) -> Result {
	use serde_json::Map;

	let mut unsigned: Map<String, JsonValue> = self
		.unsigned
		.as_deref()
		.map(RawJsonValue::get)
		.map_or_else(|| Ok(Map::new()), serde_json::from_str)
		.map_err(|e| err!(Database("Invalid unsigned in pdu event: {e}")))?;

	unsigned.insert("membership".to_owned(), serde_json::to_value(membership)?);
	self.unsigned = Some(to_raw_value(&unsigned)?);

	Ok(())
}

#[implement(Pdu)]
pub fn add_relation(&mut self, name: &str, pdu: Option<&Pdu>) -> Result {
	use serde_json::Map;

	let mut unsigned: Map<String, JsonValue> = self
		.unsigned
		.as_deref()
		.map(RawJsonValue::get)
		.map_or_else(|| Ok(Map::new()), serde_json::from_str)
		.map_err(|e| err!(Database("Invalid unsigned in pdu event: {e}")))?;

	let pdu = pdu
		.map(serde_json::to_value)
		.transpose()?
		.unwrap_or_else(|| JsonValue::Object(Map::new()));

	unsigned
		.entry("m.relations")
		.or_insert(JsonValue::Object(Map::new()))
		.as_object_mut()
		.map(|object| object.insert(name.to_owned(), pdu));

	self.unsigned = Some(to_raw_value(&unsigned)?);

	Ok(())
}

#[cfg(test)]
mod tests {
	use ruma::events::room::member::MembershipState;
	use serde_json::{Value, json};

	use super::Pdu;

	fn pdu() -> Pdu {
		serde_json::from_value(json!({
			"auth_events": [],
			"content": {},
			"depth": 1,
			"event_id": "$event:example.com",
			"hashes": { "sha256": "hash" },
			"origin_server_ts": 1,
			"prev_events": [],
			"room_id": "!room:example.com",
			"sender": "@sender:example.com",
			"type": "m.room.message",
			"unsigned": {
				"age": 5,
				"m.relations": { "m.annotation": {} }
			}
		}))
		.unwrap()
	}

	#[test]
	fn add_membership_preserves_existing_unsigned() {
		let mut pdu = pdu();

		pdu.add_membership(MembershipState::Join).unwrap();

		let unsigned: Value = serde_json::from_str(pdu.unsigned.unwrap().get()).unwrap();
		assert_eq!(unsigned["membership"], "join");
		assert_eq!(unsigned["age"], 5);
		assert!(unsigned["m.relations"].is_object());
	}

	#[test]
	fn add_membership_is_per_event_instance() {
		let mut joined = pdu();
		let mut left = joined.clone();

		joined.add_membership(MembershipState::Join).unwrap();
		left.add_membership(MembershipState::Leave).unwrap();

		let joined_unsigned: Value =
			serde_json::from_str(joined.unsigned.unwrap().get()).unwrap();
		let left_unsigned: Value = serde_json::from_str(left.unsigned.unwrap().get()).unwrap();

		assert_eq!(joined_unsigned["membership"], "join");
		assert_eq!(left_unsigned["membership"], "leave");
	}
}
