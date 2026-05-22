use std::str::FromStr;

use conduwuit::{
	Err, Result, err, implement,
	matrix::event::gen_event_id,
};
use itertools::Itertools;
use ruma::{
	CanonicalJsonObject, CanonicalJsonValue, EventId, OwnedEventId, OwnedRoomId, RoomId,
	RoomVersionId,
	room_version_rules::{
		EventIdFormatVersion, EventsReferenceFormatVersion, RoomVersionRules,
	},
};
use serde_json::value::RawValue as RawJsonValue;

type Parsed = (OwnedRoomId, OwnedEventId, CanonicalJsonObject);

/// Extracts the expected room ID from the PDU. If the PDU claims its own room
/// ID, that is returned. Since `m.room.create` in v12 and onward lacks this
/// field over federation, it will be calculated if not provided, otherwise a
/// validation error will be returned.
fn extract_room_id(event_type: &str, pdu: &CanonicalJsonObject) -> Result<OwnedRoomId> {
	if let Some(room_id) = pdu.get("room_id").and_then(CanonicalJsonValue::as_str) {
		return RoomId::parse(room_id)
			.map_err(|e| err!(Request(BadJson("Invalid room_id {room_id:?} in pdu: {e}"))));
	}
	// If there's no room ID, and this is not a create event, it is illegal.
	if event_type != "m.room.create" || pdu.get("state_key").is_none() {
		return Err!(Request(BadJson("Missing room_id in pdu")));
	}

	// Room versions 11 and below require the room ID is present.
	let room_version = RoomVersionId::from_str(
		pdu.get("content")
			.and_then(CanonicalJsonValue::as_object)
			.ok_or_else(|| err!(Request(InvalidParam("Missing or invalid content in pdu"))))?
			.get("room_version")
			.and_then(CanonicalJsonValue::as_str)
			.unwrap_or("1"), // Omitted room versions default to v1
	)
	.map_err(|e| err!(Request(BadJson("Invalid room_version in pdu: {e}"))))?;

	let Some(room_version_rules) = room_version.rules() else {
		return Err!(Request(BadJson("Unknown room version in pdu")));
	};

	if !room_version_rules
		.authorization
		.room_create_event_id_as_room_id
	{
		return Err!(Request(BadJson("Missing room_id in pdu")));
	}

	let event_id = gen_event_id(pdu, &room_version_rules)?;
	Ok(RoomId::parse(event_id.as_str().replace('$', "!"))
		.expect("constructed room ID has to be valid"))
}

/// Parses every entry in an array as an event ID, returning an error if any
/// step fails.
fn expect_event_reference(
	value: &CanonicalJsonValue,
	field: &str,
	legacy_references: bool,
) -> Result<OwnedEventId> {
	if let Some(event_id) = value.as_str() {
		return EventId::parse(event_id)
			.map_err(|e| err!(Request(BadJson("invalid event ID in `{field}`: {e}"))));
	}

	if legacy_references {
		if let Some(event_id) = value
			.as_array()
			.and_then(|tuple| tuple.first())
			.and_then(CanonicalJsonValue::as_str)
		{
			return EventId::parse(event_id).map_err(|e| {
				err!(Request(BadJson("invalid event ID in `{field}` tuple: {e}")))
			});
		}
	}

	Err!(Request(BadJson("expected an array of event IDs for `{field}`")))
}

fn expect_event_id_array(
	value: &CanonicalJsonObject,
	field: &str,
	room_version_rules: &RoomVersionRules,
) -> Result<Vec<OwnedEventId>> {
	let legacy_references =
		room_version_rules.events_reference_format == EventsReferenceFormatVersion::V1;

	value
		.get(field)
		.ok_or_else(|| err!(Request(BadJson("missing field `{field}` on PDU"))))?
		.as_array()
		.ok_or_else(|| err!(Request(BadJson("expected an array PDU field `{field}`"))))?
		.iter()
		.map(|v| expect_event_reference(v, field, legacy_references))
		.try_collect()
}

fn normalize_event_reference_field(
	pdu: &mut CanonicalJsonObject,
	field: &str,
	room_version_rules: &RoomVersionRules,
) -> Result {
	if room_version_rules.events_reference_format != EventsReferenceFormatVersion::V1 {
		return Ok(());
	}

	let references = expect_event_id_array(pdu, field, room_version_rules)?
		.into_iter()
		.map(|event_id| CanonicalJsonValue::String(event_id.to_string()))
		.collect();

	pdu.insert(field.to_owned(), CanonicalJsonValue::Array(references));
	Ok(())
}

fn extract_event_id(
	pdu: &CanonicalJsonObject,
	room_version_rules: &RoomVersionRules,
) -> Result<OwnedEventId> {
	if room_version_rules.event_id_format != EventIdFormatVersion::V1 {
		return gen_event_id(pdu, room_version_rules);
	}

	let event_id = pdu
		.get("event_id")
		.and_then(CanonicalJsonValue::as_str)
		.ok_or_else(|| err!(Request(BadJson("missing event_id in legacy PDU"))))?;

	EventId::parse(event_id)
		.map_err(|e| err!(Request(BadJson("invalid event_id in legacy PDU: {e}"))))
}

/// Performs some basic validation on the PDU to make sure it's not obviously
/// malformed. This is not a full validation, but guards against extreme errors.
///
/// Currently, this just validates that prev/auth events are within acceptable
/// ranges. Other servers do some additional things like checking depth range,
/// but serde will do that later when converting the object to a PduEvent.
#[implement(super::Service)]
pub fn validate_pdu(
	&self,
	pdu: &CanonicalJsonObject,
	room_version_rules: &RoomVersionRules,
) -> Result {
	// Since v3:
	// `event_id` should not be present on the PDU.
	// NOTE: The above is ignored since technically it's still allowed to be
	// included, but should be ignored instead.
	// `auth_events` and `prev_events` must be an array of event IDs
	let auth_events = expect_event_id_array(pdu, "auth_events", room_version_rules)?;
	if auth_events.len() > 10 {
		return Err!(Request(BadJson("PDU has too many auth events")));
	}
	let prev_events = expect_event_id_array(pdu, "prev_events", room_version_rules)?;
	if prev_events.len() > 20 {
		return Err!(Request(BadJson("PDU has too many prev events")));
	}
	Ok(())
}

#[implement(super::Service)]
pub fn normalize_incoming_event_format(
	&self,
	pdu: &mut CanonicalJsonObject,
	room_version_rules: &RoomVersionRules,
) -> Result {
	normalize_event_reference_field(pdu, "auth_events", room_version_rules)?;
	normalize_event_reference_field(pdu, "prev_events", room_version_rules)?;
	Ok(())
}

#[implement(super::Service)]
pub async fn parse_incoming_pdu(&self, pdu: &RawJsonValue) -> Result<Parsed> {
	let value = serde_json::from_str::<CanonicalJsonObject>(pdu.get()).map_err(|e| {
		err!(BadServerResponse(debug_warn!("Error parsing incoming event {e:?}")))
	})?;
	let event_type = value
		.get("type")
		.and_then(CanonicalJsonValue::as_str)
		.ok_or_else(|| err!(Request(InvalidParam("Missing or invalid type in pdu"))))?;

	let room_id = extract_room_id(event_type, &value)?;

	let room_version_rules = self
		.services
		.state
		.get_room_version(&room_id)
		.await
		.unwrap_or(RoomVersionId::V1)
		.rules()
		.unwrap();

	let event_id = extract_event_id(&value, &room_version_rules).map_err(|e| {
		err!(Request(InvalidParam("Could not determine event ID from PDU: {e}")))
	})?;
	self.validate_pdu(&value, &room_version_rules)?;
	Ok((room_id, event_id, value))
}

#[cfg(test)]
mod tests {
	use ruma::{CanonicalJsonObject, CanonicalJsonValue, room_version_rules::RoomVersionRules};
	use serde_json::json;

	use super::{expect_event_id_array, extract_event_id, normalize_event_reference_field};

	fn canonical(value: serde_json::Value) -> CanonicalJsonObject {
		serde_json::from_value(value).expect("valid canonical JSON")
	}

	#[test]
	fn legacy_event_references_accept_tuples() {
		let pdu = canonical(json!({
			"auth_events": [["$auth:example.org", {"sha256": "authhash"}]],
			"prev_events": [["$prev:example.org", {"sha256": "prevhash"}]]
		}));

		let auth_events =
			expect_event_id_array(&pdu, "auth_events", &RoomVersionRules::V1).unwrap();
		let prev_events =
			expect_event_id_array(&pdu, "prev_events", &RoomVersionRules::V1).unwrap();

		assert_eq!(auth_events[0].as_str(), "$auth:example.org");
		assert_eq!(prev_events[0].as_str(), "$prev:example.org");
	}

	#[test]
	fn legacy_event_references_normalize_to_internal_strings() {
		let mut pdu = canonical(json!({
			"auth_events": [["$auth:example.org", {"sha256": "authhash"}]],
			"prev_events": [["$prev:example.org", {"sha256": "prevhash"}]]
		}));

		normalize_event_reference_field(&mut pdu, "auth_events", &RoomVersionRules::V1).unwrap();
		normalize_event_reference_field(&mut pdu, "prev_events", &RoomVersionRules::V1).unwrap();

		assert_eq!(
			pdu["auth_events"],
			vec![CanonicalJsonValue::String("$auth:example.org".to_owned())]
		);
		assert_eq!(
			pdu["prev_events"],
			vec![CanonicalJsonValue::String("$prev:example.org".to_owned())]
		);
	}

	#[test]
	fn modern_event_references_reject_tuples() {
		let pdu = canonical(json!({
			"auth_events": [["$auth:example.org", {"sha256": "authhash"}]]
		}));

		assert!(expect_event_id_array(&pdu, "auth_events", &RoomVersionRules::V3).is_err());
	}

	#[test]
	fn legacy_event_id_is_taken_from_pdu() {
		let pdu = canonical(json!({
			"event_id": "$legacy:example.org"
		}));

		let event_id = extract_event_id(&pdu, &RoomVersionRules::V1).unwrap();

		assert_eq!(event_id.as_str(), "$legacy:example.org");
	}
}
