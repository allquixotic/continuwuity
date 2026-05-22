use std::collections::BTreeMap;

use axum::{
	extract::State,
	response::{IntoResponse, Response},
};
use conduwuit::{Result, Server};
use http::{
	HeaderValue,
	header::{CACHE_CONTROL, EXPIRES, PRAGMA},
};
use ruma::{
	RoomVersionId,
	api::client::discovery::get_capabilities::{
		self,
		v3::{
			Capabilities, GetLoginTokenCapability, RoomVersionStability, RoomVersionsCapability,
			ThirdPartyIdChangesCapability,
		},
	},
};
use serde_json::json;

use crate::Ruma;

/// # `GET /_matrix/client/v3/capabilities`
///
/// Get information on the supported feature set and other relevant capabilities
/// of this server.
pub(crate) async fn get_capabilities_route(
	State(services): State<crate::State>,
	body: Ruma<get_capabilities::v3::Request>,
) -> Result<Response> {
	let available: BTreeMap<RoomVersionId, RoomVersionStability> =
		Server::available_room_versions().collect();

	let mut capabilities = Capabilities::default();
	capabilities.room_versions = RoomVersionsCapability::new(
		services.server.config.default_room_version.clone(),
		available,
	);

	// Only allow 3pid changes if SMTP is configured
	capabilities.thirdparty_id_changes =
		ThirdPartyIdChangesCapability::new(services.threepid.email_requirement().may_change());

	capabilities.get_login_token =
		GetLoginTokenCapability::new(services.server.config.login_via_existing_session);

	// MSC4133 capability
	capabilities.set("uk.tcpip.msc4133.profile_fields", json!({"enabled": true}))?;

	capabilities.set(
		"org.matrix.msc4267.forget_forced_upon_leave",
		json!({"enabled": services.config.forget_forced_upon_leave}),
	)?;

	if services
		.users
		.is_admin(body.sender_user.as_ref().unwrap())
		.await
	{
		// Advertise suspension API
		capabilities.set("uk.timedout.msc4323", json!({"suspend": true, "lock": false}))?;
	}

	Ok(no_store_response(crate::RumaResponse(
		get_capabilities::v3::Response::new(capabilities),
	)))
}

fn no_store_response(response: impl IntoResponse) -> Response {
	let mut response = response.into_response();
	let headers = response.headers_mut();

	headers.insert(
		CACHE_CONTROL,
		HeaderValue::from_static("no-store, no-cache, max-age=0, must-revalidate"),
	);
	headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
	headers.insert(EXPIRES, HeaderValue::from_static("0"));

	response
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn room_versions_capability_advertises_historical_versions_as_stable() {
		let available: BTreeMap<RoomVersionId, RoomVersionStability> =
			Server::available_room_versions().collect();
		let mut capabilities = Capabilities::default();
		capabilities.room_versions = RoomVersionsCapability::new(RoomVersionId::V12, available);

		let serialized = serde_json::to_value(capabilities).unwrap();

		for room_version in ["1", "2", "3", "4", "5"] {
			assert_eq!(serialized["m.room_versions"]["available"][room_version], json!("stable"));
		}
	}

	#[test]
	fn capabilities_responses_are_not_cacheable() {
		let response = no_store_response(http::StatusCode::OK);

		assert_eq!(
			response.headers().get(CACHE_CONTROL).unwrap(),
			"no-store, no-cache, max-age=0, must-revalidate",
		);
		assert_eq!(response.headers().get(PRAGMA).unwrap(), "no-cache");
		assert_eq!(response.headers().get(EXPIRES).unwrap(), "0");
	}
}
