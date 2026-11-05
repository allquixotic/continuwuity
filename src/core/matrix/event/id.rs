use ruma::{
	CanonicalJsonObject, CanonicalJsonValue, EventId, OwnedEventId,
	room_version_rules::{EventIdFormatVersion, RoomVersionRules},
};
use serde_json::value::RawValue as RawJsonValue;

use crate::{Result, err};

/// Generates a correct eventId for the incoming pdu.
///
/// Returns a tuple of the new `EventId` and the PDU as a `BTreeMap<String,
/// CanonicalJsonValue>`.
pub fn gen_event_id_canonical_json(
	pdu: &RawJsonValue,
	room_version_rules: &RoomVersionRules,
) -> Result<(OwnedEventId, CanonicalJsonObject)> {
	let value: CanonicalJsonObject = serde_json::from_str(pdu.get())
		.map_err(|e| err!(BadServerResponse(warn!("Error parsing incoming event: {e:?}"))))?;

	let event_id = gen_event_id(&value, room_version_rules)?;

	Ok((event_id, value))
}

/// Generates a correct eventId for the PDU.
///
/// For legacy rooms (V1/V2) the event ID is server-supplied and carried in the
/// PDU's `event_id` field; we use it directly. For all later room versions the
/// event ID is the reference hash of the canonical JSON. If a V1 PDU is missing
/// the `event_id` field (e.g. when we are constructing a new outbound event and
/// have not yet assigned one), we fall back to the reference hash so the
/// caller still receives an identifier.
pub fn gen_event_id(
	value: &CanonicalJsonObject,
	room_version_rules: &RoomVersionRules,
) -> Result<OwnedEventId> {
	if room_version_rules.event_id_format == EventIdFormatVersion::V1 {
		if let Some(event_id) = value.get("event_id").and_then(CanonicalJsonValue::as_str) {
			return EventId::parse(event_id).map_err(|e| {
				err!(Request(BadJson("Invalid event_id in legacy PDU: {e}")))
			});
		}
	}

	let reference_hash = ruma::signatures::reference_hash(value, room_version_rules)?;
	let event_id: OwnedEventId = format!("${reference_hash}").try_into()?;

	Ok(event_id)
}

#[cfg(test)]
mod tests {
	use ruma::room_version_rules::RoomVersionRules;
	use serde_json::json;

	use super::{CanonicalJsonObject, gen_event_id};

	fn canonical(value: serde_json::Value) -> CanonicalJsonObject {
		serde_json::from_value(value).expect("valid canonical JSON")
	}

	#[test]
	fn v1_room_uses_event_id_field_verbatim() {
		// A V1 PDU's identifier is the `event_id` field assigned by the
		// originating server. gen_event_id must return that string and must NOT
		// compute a reference hash, otherwise federation comparisons against
		// the sender's event_id always mismatch.
		let pdu = canonical(json!({
			"event_id": "$177988923260pEcSC:matrix.bertieb.org",
			"room_id": "!AkvstdcyVkEZFJjQUK:roota.cc",
			"type": "m.room.message",
			"sender": "@bertieb:matrix.bertieb.org",
			"origin_server_ts": 1779889232103_i64,
			"content": {},
			"auth_events": [["$auth:matrix.bertieb.org", {"sha256": "h"}]],
			"prev_events": [["$prev:matrix.bertieb.org", {"sha256": "h"}]]
		}));

		let event_id = gen_event_id(&pdu, &RoomVersionRules::V1).expect("v1 event id");
		assert_eq!(event_id.as_str(), "$177988923260pEcSC:matrix.bertieb.org");
	}

	#[test]
	fn modern_room_computes_reference_hash() {
		// For V3+ rooms gen_event_id must compute the reference hash regardless
		// of any event_id field present in the PDU. A stale event_id field
		// must not leak into the identifier.
		let pdu = canonical(json!({
			"event_id": "$stale:should-not-be-used",
			"room_id": "!r:example.org",
			"type": "m.room.message",
			"sender": "@alice:example.org",
			"origin_server_ts": 1_i64,
			"content": {},
			"auth_events": [],
			"prev_events": []
		}));

		let event_id = gen_event_id(&pdu, &RoomVersionRules::V11).expect("v11 event id");
		assert_ne!(event_id.as_str(), "$stale:should-not-be-used");
		assert!(event_id.as_str().starts_with('$'));
	}
}
