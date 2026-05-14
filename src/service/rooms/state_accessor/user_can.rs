use conduwuit::{Err, PduEvent, Result, debug_warn, implement, matrix::Event, pdu::PartialPdu};
use ruma::{
	EventId, RoomId, UserId,
	events::{
		StateEventType, TimelineEventType,
		room::{
			history_visibility::{HistoryVisibility, RoomHistoryVisibilityEventContent},
			member::{MembershipState, RoomMemberEventContent},
		},
	},
};
use serde_json::json;

use crate::rooms::state::RoomMutexGuard;

/// Checks if a given user can redact a given event
///
/// If federation is true, it allows redaction events from any user of the
/// same server as the original event sender
#[implement(super::Service)]
pub async fn user_can_redact(
	&self,
	redacts: &EventId,
	sender: &UserId,
	room_id: &RoomId,
	federation: bool,
) -> Result<bool> {
	let redacting_event = self.services.timeline.get_pdu(redacts).await;

	if redacting_event
		.as_ref()
		.is_ok_and(|pdu| *pdu.kind() == TimelineEventType::RoomCreate)
	{
		return Err!(Request(Forbidden("Redacting m.room.create is not safe, forbidding.")));
	}

	if redacting_event
		.as_ref()
		.is_ok_and(|pdu| *pdu.kind() == TimelineEventType::RoomServerAcl)
	{
		return Err!(Request(Forbidden(
			"Redacting m.room.server_acl will result in the room being inaccessible for \
			 everyone (empty allow key), forbidding."
		)));
	}

	let power_levels = self.get_room_power_levels(room_id).await;

	if power_levels.user_can_redact_event_of_other(sender) {
		return Ok(true);
	}

	if power_levels.user_can_redact_own_event(sender) {
		let is_own_event = match redacting_event {
			| Ok(redacting_event) =>
				if federation {
					redacting_event.sender().server_name() == sender.server_name()
				} else {
					redacting_event.sender() == sender
				},
			| _ => false,
		};

		return Ok(is_own_event);
	}

	Ok(false)
}

/// Whether a user is allowed to see an event, based on
/// the room's history_visibility at that event's state.
#[implement(super::Service)]
#[tracing::instrument(skip_all, level = "trace")]
pub async fn user_can_see_event(
	&self,
	user_id: &UserId,
	room_id: &RoomId,
	event_id: &EventId,
) -> bool {
	let Ok(shortstatehash) = self.pdu_shortstatehash(event_id).await else {
		return true;
	};

	let currently_member = self.services.state_cache.is_joined(user_id, room_id).await;

	let history_visibility = self
		.state_get_content(shortstatehash, &StateEventType::RoomHistoryVisibility, "")
		.await
		.map_or(HistoryVisibility::Shared, |c: RoomHistoryVisibilityEventContent| {
			c.history_visibility
		});

	match history_visibility {
		| HistoryVisibility::Invited => {
			// Allow if any member on requesting server was AT LEAST invited, else deny
			self.user_was_invited(shortstatehash, user_id).await
		},
		| HistoryVisibility::Joined => {
			// Allow if any member on requested server was joined, else deny
			self.user_was_joined(shortstatehash, user_id).await
		},
		| HistoryVisibility::WorldReadable => true,
		| HistoryVisibility::Shared | _ => currently_member,
	}
}

/// Redact an erased sender's event for a requester who was not joined when the
/// event happened.
#[implement(super::Service)]
#[tracing::instrument(skip_all, level = "trace")]
pub async fn redact_erased_sender_event_for_user(
	&self,
	user_id: &UserId,
	pdu: &mut PduEvent,
) -> Result<()> {
	if !self.sender_erasure_requires_redaction(user_id, pdu).await {
		return Ok(());
	}

	let room_version = self
		.services
		.state
		.get_room_version(&pdu.room_id_or_hash())
		.await?;
	if let Err(e) = pdu.redact(&room_version, json!({})) {
		debug_warn!(
			%user_id,
			event_id = %pdu.event_id(),
			sender = %pdu.sender(),
			"Failed to redact erased sender event for requester: {e}"
		);
		return Err(e);
	}

	Ok(())
}

#[implement(super::Service)]
#[tracing::instrument(skip_all, level = "trace")]
pub async fn sender_erasure_requires_redaction(&self, user_id: &UserId, pdu: &PduEvent) -> bool {
	let sender_erased = self.db.userid_erased.contains(pdu.sender()).await;
	if !sender_erased {
		return false;
	}

	let Ok(shortstatehash) = self.pdu_shortstatehash(pdu.event_id()).await else {
		return false;
	};

	erased_sender_needs_redaction(
		sender_erased,
		self.user_was_joined(shortstatehash, user_id).await,
	)
}

fn erased_sender_needs_redaction(sender_erased: bool, requester_joined_at_event: bool) -> bool {
	sender_erased && !requester_joined_at_event
}

/// Whether a user is allowed to see an event, based on
/// the room's history_visibility at that event's state.
#[implement(super::Service)]
#[tracing::instrument(skip_all, level = "trace")]
pub async fn user_can_see_state_events(&self, user_id: &UserId, room_id: &RoomId) -> bool {
	if self.services.state_cache.is_joined(user_id, room_id).await {
		return true;
	}

	let history_visibility = self
		.room_state_get_content(room_id, &StateEventType::RoomHistoryVisibility, "")
		.await
		.map_or(HistoryVisibility::Shared, |c: RoomHistoryVisibilityEventContent| {
			c.history_visibility
		});

	match history_visibility {
		| HistoryVisibility::Invited =>
			self.services.state_cache.is_invited(user_id, room_id).await,
		| HistoryVisibility::WorldReadable => true,
		| _ => false,
	}
}

#[implement(super::Service)]
pub async fn user_can_invite(
	&self,
	room_id: &RoomId,
	sender: &UserId,
	target_user: &UserId,
	state_lock: &RoomMutexGuard,
) -> bool {
	self.services
		.timeline
		.create_hash_and_sign_event(
			PartialPdu::state(
				target_user.as_str(),
				&RoomMemberEventContent::new(MembershipState::Invite),
			),
			sender,
			Some(room_id),
			state_lock,
		)
		.await
		.is_ok()
}

#[cfg(test)]
mod tests {
	use super::erased_sender_needs_redaction;

	#[test]
	fn erased_sender_redacts_only_for_users_not_joined_at_event() {
		assert!(erased_sender_needs_redaction(true, false));
		assert!(!erased_sender_needs_redaction(true, true));
		assert!(!erased_sender_needs_redaction(false, false));
		assert!(!erased_sender_needs_redaction(false, true));
	}
}
