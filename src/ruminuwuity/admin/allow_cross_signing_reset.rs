//! `POST /_matrix/client/unstable/org.matrix.msc4312/admin/
//! allow_cross_signing_reset/{userId}`
//!
//! Grants one timed cross-signing key replacement without UIAA.

pub mod unstable {
	use ruma::{
		OwnedUserId,
		api::{auth_scheme::AccessToken, request, response},
		metadata,
	};

	metadata! {
		method: POST,
		rate_limited: false,
		authentication: AccessToken,
		history: {
			unstable => "/_matrix/client/unstable/org.matrix.msc4312/admin/allow_cross_signing_reset/{user_id}",
		}
	}

	/// Request type for granting a cross-signing reset.
	#[request(error = ruma::api::error::Error)]
	pub struct Request {
		/// The user who may replace their cross-signing keys once.
		#[ruma_api(path)]
		pub user_id: OwnedUserId,
	}

	/// Response type for granting a cross-signing reset.
	#[response(error = ruma::api::error::Error)]
	pub struct Response {
		/// Unix timestamp in milliseconds when the grant expires.
		pub updatable_without_uia_before_ms: u64,
	}

	impl Request {
		/// Creates a new `Request` with the given user id.
		#[must_use]
		pub fn new(user_id: OwnedUserId) -> Self { Self { user_id } }
	}

	impl Response {
		/// Creates a new `Response` with the given expiry timestamp.
		#[must_use]
		pub fn new(updatable_without_uia_before_ms: u64) -> Self {
			Self { updatable_without_uia_before_ms }
		}
	}
}
