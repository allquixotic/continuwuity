use axum::extract::State;
use conduwuit::{
	Err, Event, Result, at,
	utils::{BoolExt, stream::TryTools},
};
use futures::{FutureExt, TryStreamExt, future::try_join4};
use ruma::{
	api::client::peeking::get_current_state::v3::{PaginationChunk, Request, Response},
	assign,
};

use crate::Ruma;

const LIMIT_MAX: usize = 100;

pub(crate) async fn room_initial_sync_route(
	State(services): State<crate::State>,
	body: Ruma<Request>,
) -> Result<Response> {
	let room_id = &body.room_id;

	if !services
		.rooms
		.state_accessor
		.user_can_see_state_events(body.sender_user(), room_id)
		.await
	{
		return Err!(Request(Forbidden("No room preview available.")));
	}

	let membership = services
		.rooms
		.state_cache
		.user_membership(body.sender_user(), room_id)
		.map(Ok);

	let visibility = services.rooms.directory.visibility(room_id).map(Ok);

	let state = services
		.rooms
		.state_accessor
		.room_state_full_pdus(room_id)
		.and_then(async |pdu| {
			let mut pdu = pdu.into_pdu();
			if let Some(sender_user) = body.sender_user.as_deref() {
				services
					.rooms
					.pdu_metadata
					.add_user_unsigned_to_pdu(sender_user, &mut pdu)
					.await;
			}

			Ok(pdu)
		})
		.map_ok(Event::into_format)
		.try_collect::<Vec<_>>();

	// Events are returned in body

	let limit = LIMIT_MAX;
	let events = services
		.rooms
		.timeline
		.pdus_rev(room_id, None)
		.try_take(limit)
		.and_then(async |mut pdu| {
			if let Some(sender_user) = body.sender_user.as_deref() {
				services
					.rooms
					.pdu_metadata
					.add_user_unsigned_with_bundled_aggregations_to_pdu(sender_user, &mut pdu.1)
					.await;
			}
			Ok(pdu)
		})
		.try_collect::<Vec<_>>();

	let (membership, visibility, state, events) =
		try_join4(membership, visibility, state, events)
			.boxed()
			.await?;

	let end = events
		.first()
		.map(at!(0))
		.as_ref()
		.map(ToString::to_string)
		.unwrap_or_default();
	let start = events.last().map(at!(0)).as_ref().map(ToString::to_string);

	let chunk = events
		.into_iter()
		.map(at!(1))
		.map(Event::into_format)
		.collect();

	let messages = assign!(PaginationChunk::new(chunk, end), { start });

	Ok(assign!(Response::new(room_id.to_owned()), {
		account_data: vec![],
		state: state,
		messages: messages.chunk.is_empty().or_some(messages),
		visibility: visibility.into(),
		membership,
	}))
}
