use axum::extract::State;
use conduwuit::{Err, Result, err, info, matrix::event::Event};
use ruma::{
	MilliSecondsSinceUnixEpoch, RoomId,
	api::federation::event::{get_event, get_event_by_timestamp},
};

use super::AccessCheck;
use crate::Ruma;

/// # `GET /_matrix/federation/v1/event/{eventId}`
///
/// Retrieves a single event from the server.
///
/// - Only works if a user of this server is currently invited or joined the
///   room
pub(crate) async fn get_event_route(
	State(services): State<crate::State>,
	body: Ruma<get_event::v1::Request>,
) -> Result<get_event::v1::Response> {
	let event = services
		.rooms
		.timeline
		.get_pdu_json(&body.event_id)
		.await
		.map_err(|_| err!(Request(NotFound("Event not found."))))?;

	let room_id: &RoomId = event
		.get("room_id")
		.and_then(|val| val.as_str())
		.ok_or_else(|| err!(Database("Invalid event in database.")))?
		.try_into()
		.map_err(|_| err!(Database("Invalid room_id in event in database.")))?;

	AccessCheck {
		services: &services,
		origin: body.origin(),
		room_id,
		event_id: Some(&body.event_id),
	}
	.check()
	.await?;

	if !services
		.rooms
		.state_cache
		.server_in_room(services.globals.server_name(), room_id)
		.await
	{
		info!(
			origin = body.origin().as_str(),
			"Refusing to serve state for room we aren't participating in"
		);
		return Err!(Request(NotFound("This server is not participating in that room.")));
	}

	Ok(get_event::v1::Response::new(
		services.globals.server_name().to_owned(),
		MilliSecondsSinceUnixEpoch::now(),
		services
			.sending
			.convert_to_outgoing_federation_event(event)
			.await,
	))
}

/// # `GET /_matrix/federation/v1/timestamp_to_event/{roomId}`
///
/// Retrieves the closest timeline event at or before / after a timestamp.
pub(crate) async fn get_event_by_timestamp_route(
	State(services): State<crate::State>,
	body: Ruma<get_event_by_timestamp::v1::Request>,
) -> Result<get_event_by_timestamp::v1::Response> {
	let room_id = &body.room_id;

	AccessCheck {
		services: &services,
		origin: body.origin(),
		room_id,
		event_id: None,
	}
	.check()
	.await?;

	if !services
		.rooms
		.state_cache
		.server_in_room(services.globals.server_name(), room_id)
		.await
	{
		info!(
			origin = body.origin().as_str(),
			"Refusing to serve timestamp lookup for room we aren't participating in"
		);
		return Err!(Request(NotFound("This server is not participating in that room.")));
	}

	let (_, pdu) = services
		.rooms
		.timeline
		.get_pdu_by_timestamp(room_id, body.ts, body.dir)
		.await?;

	AccessCheck {
		services: &services,
		origin: body.origin(),
		room_id,
		event_id: Some(&pdu.event_id),
	}
	.check()
	.await?;

	let origin_server_ts = pdu.origin_server_ts();

	Ok(get_event_by_timestamp::v1::Response::new(pdu.event_id, origin_server_ts))
}
