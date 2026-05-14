use axum::extract::State;
use conduwuit::{Err, Result};
use ruminuwuity::admin::allow_cross_signing_reset as allow_cross_signing_reset_endpoint;

use crate::Ruma;

/// # `POST /_matrix/client/unstable/org.matrix.msc4312/admin/allow_cross_signing_reset/{userId}`
///
/// Allow a user to replace cross-signing keys once without UIAA after approving
/// the reset through OAuth account management.
pub(crate) async fn allow_cross_signing_reset(
	State(services): State<crate::State>,
	body: Ruma<allow_cross_signing_reset_endpoint::unstable::Request>,
) -> Result<allow_cross_signing_reset_endpoint::unstable::Response> {
	let sender_user = body.sender_user();

	if !services.users.is_admin(sender_user).await {
		return Err!(Request(Forbidden("Only server admins may allow cross-signing reset.")));
	}

	if !services.users.exists(&body.user_id).await {
		return Err!(Request(NotFound("User does not exist.")));
	}

	let expires_at = services
		.users
		.allow_cross_signing_reset_without_uia(&body.user_id);

	Ok(allow_cross_signing_reset_endpoint::unstable::Response::new(expires_at))
}
