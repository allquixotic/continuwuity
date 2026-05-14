use axum::response::IntoResponse;
use bytes::BytesMut;
use http::StatusCode;
use http_body_util::Full;
use ruma::api::{
	OutgoingResponse,
	client::uiaa::UiaaResponse,
	error::{ErrorBody, ErrorKind, StandardErrorBody},
};
use serde_json::json;

use super::Error;
use crate::error;

impl IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		let status = self.status_code();
		if status.is_server_error() {
			error!(
				error = %self,
				error_debug = ?self,
				kind = ?self.kind(),
				status = %status,
				"Server error"
			);
		} else if status.is_client_error() {
			use crate::debug_error;
			debug_error!(
				error = %self,
				kind = ?self.kind(),
				status = %status,
				"Client error"
			);
		}

		let error = match self {
			| Error::UiaaRaw(body) =>
				return json_response(StatusCode::UNAUTHORIZED, body.get(), "raw uiaa"),
			| Error::UnknownDevice(message) =>
				return json_response(
					StatusCode::BAD_REQUEST,
					json!({
						"errcode": "M_UNKNOWN_DEVICE",
						"error": message,
					})
					.to_string(),
					"unknown device",
				),
			| error => error,
		};

		let response: UiaaResponse = error.into();
		response
			.try_into_http_response::<BytesMut>()
			.inspect_err(|e| error!("error response error: {e}"))
			.map_or_else(
				|_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
				|r| r.map(BytesMut::freeze).map(Full::new).into_response(),
			)
	}
}

impl From<Error> for UiaaResponse {
	#[inline]
	fn from(error: Error) -> Self {
		let error = match error {
			| Error::Uiaa(uiaainfo) => return Self::AuthResponse(uiaainfo),
			| Error::UiaaRaw(_) | Error::UnknownDevice(_) =>
				unreachable!("raw JSON errors are handled before UiaaResponse conversion"),
			| error => error,
		};

		let body = ErrorBody::Standard(StandardErrorBody::new(error.kind(), error.message()));

		Self::MatrixError(ruma::api::error::Error::new(error.status_code(), body))
	}
}

fn json_response(
	status: StatusCode,
	body: impl AsRef<[u8]>,
	label: &str,
) -> axum::response::Response {
	http::Response::builder()
		.status(status)
		.header(http::header::CONTENT_TYPE, "application/json")
		.body(Full::new(BytesMut::from(body.as_ref()).freeze()))
		.inspect_err(|e| error!("{label} response error: {e}"))
		.map_or_else(
			|_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
			IntoResponse::into_response,
		)
}

pub(super) fn status_code(kind: &ErrorKind, hint: StatusCode) -> StatusCode {
	if hint == StatusCode::BAD_REQUEST {
		bad_request_code(kind)
	} else {
		hint
	}
}

pub(super) fn bad_request_code(kind: &ErrorKind) -> StatusCode {
	use ErrorKind::*;

	match kind {
		// 429
		| LimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,

		// 413
		| TooLarge => StatusCode::PAYLOAD_TOO_LARGE,

		// 405
		| Unrecognized => StatusCode::METHOD_NOT_ALLOWED,

		// 404
		| NotFound => StatusCode::NOT_FOUND,

		// 403
		| GuestAccessForbidden
		| ThreepidAuthFailed
		| UserDeactivated
		| ThreepidDenied
		| WrongRoomKeysVersion(_)
		| UserSuspended
		| Forbidden => StatusCode::FORBIDDEN,

		// 401
		| UnknownToken(_) | MissingToken | Unauthorized | UserLocked => StatusCode::UNAUTHORIZED,

		// 400
		| _ => StatusCode::BAD_REQUEST,
	}
}

pub(super) fn ruma_error_message(error: &ruma::api::error::Error) -> String {
	if let ErrorBody::Standard(StandardErrorBody { message, .. }) = &error.body {
		return message.clone();
	}

	format!("{error}")
}

pub(super) fn ruma_error_kind(e: &ruma::api::error::Error) -> &ErrorKind {
	e.error_kind().unwrap_or(&ErrorKind::Unknown)
}

pub(super) fn io_error_code(kind: std::io::ErrorKind) -> StatusCode {
	use std::io::ErrorKind;

	match kind {
		| ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
		| ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
		| ErrorKind::NotFound => StatusCode::NOT_FOUND,
		| ErrorKind::TimedOut => StatusCode::GATEWAY_TIMEOUT,
		| ErrorKind::FileTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
		| ErrorKind::StorageFull => StatusCode::INSUFFICIENT_STORAGE,
		| ErrorKind::Interrupted => StatusCode::SERVICE_UNAVAILABLE,
		| _ => StatusCode::INTERNAL_SERVER_ERROR,
	}
}

#[cfg(test)]
mod tests {
	use axum::response::IntoResponse;
	use http::StatusCode;
	use http_body_util::BodyExt;
	use serde_json::Value as JsonValue;

	use super::Error;

	#[tokio::test]
	async fn unknown_device_error_uses_matrix_errcode() {
		let response = Error::UnknownDevice("missing device".into()).into_response();

		assert_eq!(response.status(), StatusCode::BAD_REQUEST);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let body: JsonValue = serde_json::from_slice(&body).unwrap();

		assert_eq!(body["errcode"], "M_UNKNOWN_DEVICE");
		assert_eq!(body["error"], "missing device");
	}
}
