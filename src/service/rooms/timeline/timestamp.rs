use conduwuit::{
	Result, err, implement,
	matrix::{event::Event, pdu::PduCount},
};
use futures::{TryStreamExt, pin_mut};
use ruma::{MilliSecondsSinceUnixEpoch, RoomId, api::Direction};

use super::PdusIterItem;

#[implement(super::Service)]
pub async fn get_pdu_by_timestamp(
	&self,
	room_id: &RoomId,
	ts: MilliSecondsSinceUnixEpoch,
	dir: Direction,
) -> Result<PdusIterItem> {
	let pdus = self.pdus(room_id, None);
	pin_mut!(pdus);

	let mut best = None;
	while let Some(item) = pdus.try_next().await? {
		best = closest_timestamp_candidate(best, item, ts, dir);
	}

	best.ok_or_else(|| {
		err!(Request(NotFound(
			"Unable to find event from {} in direction {}",
			ts.get(),
			direction_query_value(dir),
		)))
	})
}

fn closest_timestamp_candidate(
	best: Option<PdusIterItem>,
	item: PdusIterItem,
	ts: MilliSecondsSinceUnixEpoch,
	dir: Direction,
) -> Option<PdusIterItem> {
	let event_ts = item.1.origin_server_ts();

	if !timestamp_in_direction(event_ts, ts, dir) {
		return best;
	}

	if best
		.as_ref()
		.is_none_or(|current| timestamp_candidate_is_better(&item, current, dir))
	{
		Some(item)
	} else {
		best
	}
}

fn timestamp_candidate_is_better(
	candidate: &PdusIterItem,
	current: &PdusIterItem,
	dir: Direction,
) -> bool {
	let candidate_key = timestamp_candidate_key(candidate);
	let current_key = timestamp_candidate_key(current);

	match dir {
		| Direction::Forward => candidate_key < current_key,
		| Direction::Backward => candidate_key > current_key,
	}
}

fn timestamp_candidate_key(item: &PdusIterItem) -> (MilliSecondsSinceUnixEpoch, PduCount) {
	(item.1.origin_server_ts(), item.0)
}

fn timestamp_in_direction(
	event_ts: MilliSecondsSinceUnixEpoch,
	ts: MilliSecondsSinceUnixEpoch,
	dir: Direction,
) -> bool {
	match dir {
		| Direction::Forward => event_ts >= ts,
		| Direction::Backward => event_ts <= ts,
	}
}

fn direction_query_value(dir: Direction) -> &'static str {
	match dir {
		| Direction::Forward => "f",
		| Direction::Backward => "b",
	}
}

#[cfg(test)]
mod tests {
	use conduwuit::matrix::pdu::{EventHash, PduCount, PduEvent};
	use ruma::{
		MilliSecondsSinceUnixEpoch, OwnedEventId, UInt, api::Direction,
		events::TimelineEventType, owned_event_id, owned_room_id, owned_user_id,
	};
	use serde_json::{json, value::to_raw_value};

	fn pdu(count: u64, ts: u64, event_id: &'static str) -> (PduCount, PduEvent) {
		(PduCount::Normal(count), PduEvent {
			event_id: OwnedEventId::try_from(event_id).unwrap(),
			room_id: Some(owned_room_id!("!room:example.com")),
			sender: owned_user_id!("@sender:example.com"),
			origin_server_ts: UInt::try_from(ts).unwrap(),
			kind: TimelineEventType::RoomMessage,
			content: to_raw_value(&json!({"msgtype": "m.text", "body": "test"})).unwrap(),
			state_key: None,
			prev_events: vec![],
			depth: UInt::try_from(count).unwrap(),
			auth_events: vec![],
			redacts: None,
			unsigned: None,
			hashes: EventHash { sha256: "hash".to_owned() },
			signatures: None,
			origin: None,
		})
	}

	fn select(
		events: Vec<(PduCount, PduEvent)>,
		ts: u64,
		dir: Direction,
	) -> Option<(PduCount, PduEvent)> {
		events.into_iter().fold(None, |best, item| {
			super::closest_timestamp_candidate(
				best,
				item,
				MilliSecondsSinceUnixEpoch(UInt::try_from(ts).unwrap()),
				dir,
			)
		})
	}

	#[test]
	fn backward_lookup_at_current_time_returns_last_event() {
		let events = vec![pdu(1, 1000, "$one:example.com"), pdu(2, 2000, "$two:example.com")];

		let (_, selected) = select(events, 3000, Direction::Backward).unwrap();

		assert_eq!(selected.event_id, owned_event_id!("$two:example.com"));
	}

	#[test]
	fn backward_lookup_ignores_events_after_timestamp() {
		let events = vec![
			pdu(1, 1000, "$one:example.com"),
			pdu(2, 2000, "$two:example.com"),
			pdu(3, 3000, "$three:example.com"),
		];

		let (_, selected) = select(events, 2500, Direction::Backward).unwrap();

		assert_eq!(selected.event_id, owned_event_id!("$two:example.com"));
	}

	#[test]
	fn forward_lookup_ignores_events_before_timestamp() {
		let events = vec![
			pdu(1, 1000, "$one:example.com"),
			pdu(2, 2000, "$two:example.com"),
			pdu(3, 3000, "$three:example.com"),
		];

		let (_, selected) = select(events, 2500, Direction::Forward).unwrap();

		assert_eq!(selected.event_id, owned_event_id!("$three:example.com"));
	}

	#[test]
	fn outliers_are_not_selected_when_absent_from_timeline_items() {
		let outlier = pdu(99, 2500, "$outlier:remote.example");
		let events = vec![pdu(1, 1000, "$one:example.com"), pdu(2, 2000, "$two:example.com")];

		let (_, selected) = select(events, 2500, Direction::Backward).unwrap();

		assert_ne!(selected.event_id, outlier.1.event_id);
		assert_eq!(selected.event_id, owned_event_id!("$two:example.com"));
	}
}
