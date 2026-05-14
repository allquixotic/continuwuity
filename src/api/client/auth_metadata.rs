use axum::extract::State;
use conduwuit::{Err, Result};
use ruma::{api::client::discovery::get_authorization_server_metadata, serde::Raw};

use crate::Ruma;

/// # `GET /_matrix/client/v1/auth_metadata`
///
/// Returns OAuth 2.0 authorization server metadata when next-generation auth
/// has been configured for this homeserver.
pub(crate) async fn get_authorization_server_metadata_route(
	State(services): State<crate::State>,
	_body: Ruma<get_authorization_server_metadata::v1::Request>,
) -> Result<get_authorization_server_metadata::v1::Response> {
	let Some(metadata) = services.config.oauth.authorization_server_metadata() else {
		return Err!(Request(
			Unrecognized("OAuth authorization server metadata is not configured."),
			NOT_FOUND
		));
	};

	Ok(get_authorization_server_metadata::v1::Response::new(
		Raw::new(&metadata)?.cast_unchecked(),
	))
}
