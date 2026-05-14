use std::collections::BTreeMap;

use axum::extract::State;
use conduwuit::{Result, Server};
use ruma::{
	RoomVersionId,
	api::client::discovery::get_capabilities::{
		self,
		v3::{
			Capabilities, GetLoginTokenCapability, ProfileFieldsCapability, RoomVersionStability,
			RoomVersionsCapability, ThirdPartyIdChangesCapability,
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
) -> Result<get_capabilities::v3::Response> {
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

	add_profile_fields_capabilities(&mut capabilities)?;

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

	Ok(get_capabilities::v3::Response::new(capabilities))
}

fn add_profile_fields_capabilities(capabilities: &mut Capabilities) -> Result<()> {
	let profile_fields = ProfileFieldsCapability::new(true);

	capabilities.profile_fields = Some(profile_fields.clone());
	capabilities.set("uk.tcpip.msc4133.profile_fields", serde_json::to_value(profile_fields)?)?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn profile_fields_capability_uses_stable_and_unstable_names() {
		let mut capabilities = Capabilities::default();

		add_profile_fields_capabilities(&mut capabilities).unwrap();

		let serialized = serde_json::to_value(capabilities).unwrap();

		assert_eq!(serialized["m.profile_fields"], json!({"enabled": true}));
		assert_eq!(serialized["uk.tcpip.msc4133.profile_fields"], json!({"enabled": true}));
		assert_eq!(serialized.get("m.set_displayname"), None);
		assert_eq!(serialized.get("m.set_avatar_url"), None);
	}
}
