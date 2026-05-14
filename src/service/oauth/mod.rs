use std::{
	collections::HashMap,
	sync::Arc,
	time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use conduwuit::{Err, Error, Result, err};
use http::StatusCode;
use ruma::{
	OwnedDeviceId, OwnedUserId, ServerName, UserId,
	api::error::{ErrorKind, UnknownTokenErrorData},
};
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::{Dep, client, config, globals, service, users};

const STABLE_API_SCOPE: &str = "urn:matrix:client:api:*";
const UNSTABLE_API_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:api:*";
const STABLE_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:client:device:";
const UNSTABLE_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";
const INTROSPECTION_CACHE_TTL: Duration = Duration::from_secs(120);

pub struct Service {
	services: Services,
	cache: RwLock<HashMap<String, CachedToken>>,
}

struct Services {
	client: Dep<client::Service>,
	config: Dep<config::Service>,
	globals: Dep<globals::Service>,
	users: Dep<users::Service>,
}

#[derive(Clone, Debug)]
pub struct OAuthBearer {
	pub sender_user: OwnedUserId,
	pub sender_device: Option<OwnedDeviceId>,
}

#[derive(Clone)]
struct CachedToken {
	bearer: OAuthBearer,
	expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
	#[serde(default)]
	active: bool,
	sub: Option<String>,
	username: Option<String>,
	scope: Option<String>,
	device_id: Option<String>,
	expires_in: Option<u64>,
	exp: Option<u64>,
}

#[derive(Clone)]
struct IntrospectionConfig {
	endpoint: Url,
	client_id: String,
	client_secret: Option<String>,
}

#[derive(Debug)]
struct MatrixScope {
	has_api_access: bool,
	device_id: Option<OwnedDeviceId>,
}

#[async_trait]
impl crate::Service for Service {
	fn build(args: crate::Args<'_>) -> Result<Arc<Self>> {
		Ok(Arc::new(Self {
			services: Services {
				client: args.depend::<client::Service>("client"),
				config: args.depend::<config::Service>("config"),
				globals: args.depend::<globals::Service>("globals"),
				users: args.depend::<users::Service>("users"),
			},
			cache: RwLock::new(HashMap::new()),
		}))
	}

	fn name(&self) -> &str { service::make_name(std::module_path!()) }

	async fn clear_cache(&self) { self.cache.write().await.clear(); }
}

impl Service {
	pub async fn authenticate(&self, token: &str) -> Result<Option<OAuthBearer>> {
		let Some(config) = self.delegated_auth_config() else {
			return Ok(None);
		};

		if let Some(cached) = self.cached(token).await {
			return Ok(Some(cached));
		}

		let received_at = Instant::now();
		let response = self.introspect_token(token, &config).await?;
		let bearer = self.resolve_response(&response).await?;
		let expires_at = response.cache_expires_at(received_at);

		if expires_at > received_at {
			let mut cache = self.cache.write().await;
			cache.retain(|_, cached| cached.expires_at > received_at);
			cache.insert(token.to_owned(), CachedToken { bearer: bearer.clone(), expires_at });
		}

		Ok(Some(bearer))
	}

	fn delegated_auth_config(&self) -> Option<IntrospectionConfig> {
		let config = self.services.config.oauth.delegated_auth()?;

		Some(IntrospectionConfig {
			endpoint: config.introspection_endpoint.clone(),
			client_id: config.client_id.to_owned(),
			client_secret: config.client_secret.map(ToOwned::to_owned),
		})
	}

	async fn cached(&self, token: &str) -> Option<OAuthBearer> {
		let now = Instant::now();
		let cached = self.cache.read().await.get(token).cloned();

		match cached {
			| Some(cached) if cached.expires_at > now => Some(cached.bearer),
			| Some(_) => {
				self.cache.write().await.remove(token);
				None
			},
			| None => None,
		}
	}

	async fn introspect_token(
		&self,
		token: &str,
		config: &IntrospectionConfig,
	) -> Result<IntrospectionResponse> {
		let form = {
			let mut form = url::form_urlencoded::Serializer::new(String::new());
			form.append_pair("token", token)
				.append_pair("token_type_hint", "access_token")
				.append_pair("client_id", config.client_id.as_str());

			if let Some(client_secret) = config.client_secret.as_deref() {
				form.append_pair("client_secret", client_secret);
			}

			form.finish()
		};

		let response = self
			.services
			.client
			.default
			.post(config.endpoint.clone())
			.header(reqwest::header::ACCEPT, "application/json")
			.header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
			.header("X-MAS-Supports-Device-Id", "1")
			.body(form)
			.send()
			.await
			.and_then(reqwest::Response::error_for_status)
			.map_err(|_| introspection_unavailable())?;

		let body = response
			.bytes()
			.await
			.map_err(|_| introspection_unavailable())?;

		serde_json::from_slice(&body).map_err(|_| introspection_unavailable())
	}

	async fn resolve_response(&self, response: &IntrospectionResponse) -> Result<OAuthBearer> {
		if !response.is_active() {
			return Err(invalid_token());
		}

		let scope = parse_matrix_scope(response.scope.as_deref(), response.device_id.as_deref())
			.map_err(|_| invalid_token())?;

		if !scope.has_api_access {
			return Err(invalid_token());
		}

		let user_id = oauth_user_id(
			response.sub.as_deref(),
			response.username.as_deref(),
			self.services.globals.server_name(),
		)?;

		if !self.services.users.is_active_local(&user_id).await {
			return Err(invalid_token());
		}

		if let Some(device_id) = &scope.device_id {
			self.services
				.users
				.get_device_metadata(&user_id, device_id)
				.await
				.map_err(|_| invalid_token())?;
		}

		Ok(OAuthBearer {
			sender_user: user_id,
			sender_device: scope.device_id,
		})
	}
}

impl IntrospectionResponse {
	fn is_active(&self) -> bool {
		if !self.active {
			return false;
		}

		if self.expires_in == Some(0) {
			return false;
		}

		if let Some(exp) = self.exp {
			return exp > unix_timestamp_secs();
		}

		true
	}

	fn cache_expires_at(&self, received_at: Instant) -> Instant {
		let ttl = [self.expires_in.map(Duration::from_secs), self.ttl_from_exp()]
			.into_iter()
			.flatten()
			.min()
			.unwrap_or(INTROSPECTION_CACHE_TTL)
			.min(INTROSPECTION_CACHE_TTL);

		received_at.checked_add(ttl).unwrap_or(received_at)
	}

	fn ttl_from_exp(&self) -> Option<Duration> {
		self.exp
			.and_then(|exp| exp.checked_sub(unix_timestamp_secs()))
			.map(Duration::from_secs)
	}
}

fn parse_matrix_scope(
	scope: Option<&str>,
	explicit_device_id: Option<&str>,
) -> Result<MatrixScope> {
	let mut has_api_access = false;
	let mut device_id = explicit_device_id.map(owned_device_id);

	for token in scope.unwrap_or_default().split_ascii_whitespace() {
		has_api_access |= token == STABLE_API_SCOPE || token == UNSTABLE_API_SCOPE;

		if explicit_device_id.is_none() {
			let scoped_device_id = token
				.strip_prefix(STABLE_DEVICE_SCOPE_PREFIX)
				.or_else(|| token.strip_prefix(UNSTABLE_DEVICE_SCOPE_PREFIX));

			if let Some(scoped_device_id) = scoped_device_id {
				if scoped_device_id.is_empty() {
					return Err!("OAuth access token has an empty Matrix device scope.");
				}

				let scoped_device_id = owned_device_id(scoped_device_id);
				if device_id
					.as_ref()
					.is_some_and(|device_id| device_id != &scoped_device_id)
				{
					return Err!("OAuth access token has multiple Matrix device scopes.");
				}

				device_id = Some(scoped_device_id);
			}
		}
	}

	if device_id
		.as_ref()
		.is_some_and(|device_id| device_id.as_str().is_empty() || device_id.as_str().len() > 255)
	{
		return Err!("OAuth access token has an invalid Matrix device ID.");
	}

	Ok(MatrixScope { has_api_access, device_id })
}

fn oauth_user_id(
	sub: Option<&str>,
	username: Option<&str>,
	server_name: &ServerName,
) -> Result<OwnedUserId> {
	let Some(sub) = sub else {
		return Err(invalid_token());
	};

	let user = username.unwrap_or(sub);
	let user_id = if user.starts_with('@') {
		UserId::parse(user)
	} else {
		UserId::parse_with_server_name(user, server_name)
	}
	.map_err(|_| invalid_token())?;

	Ok(user_id)
}

fn owned_device_id(device_id: &str) -> OwnedDeviceId { device_id.into() }

fn unix_timestamp_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

fn invalid_token() -> Error {
	Error::Request(
		ErrorKind::UnknownToken(UnknownTokenErrorData::new()),
		"Invalid access token.".into(),
		StatusCode::UNAUTHORIZED,
	)
}

fn introspection_unavailable() -> Error {
	err!(Request(Unknown("Unable to introspect the access token."), SERVICE_UNAVAILABLE))
}

#[cfg(test)]
mod tests {
	use super::{IntrospectionResponse, parse_matrix_scope};

	#[test]
	fn stable_scope_grants_api_and_device() {
		let scope = parse_matrix_scope(
			Some("urn:matrix:client:api:* urn:matrix:client:device:AABBCC"),
			None,
		)
		.unwrap();

		assert!(scope.has_api_access);
		assert_eq!(scope.device_id.unwrap().as_str(), "AABBCC");
	}

	#[test]
	fn unstable_scope_grants_api_and_device() {
		let scope = parse_matrix_scope(
			Some(
				"urn:matrix:org.matrix.msc2967.client:api:* \
				 urn:matrix:org.matrix.msc2967.client:device:DDEEFF",
			),
			None,
		)
		.unwrap();

		assert!(scope.has_api_access);
		assert_eq!(scope.device_id.unwrap().as_str(), "DDEEFF");
	}

	#[test]
	fn explicit_device_id_overrides_scope_device() {
		let scope = parse_matrix_scope(
			Some("urn:matrix:client:api:* urn:matrix:client:device:AABBCC"),
			Some("MASDEVICE"),
		)
		.unwrap();

		assert!(scope.has_api_access);
		assert_eq!(scope.device_id.unwrap().as_str(), "MASDEVICE");
	}

	#[test]
	fn multiple_device_scopes_are_rejected() {
		let err = parse_matrix_scope(
			Some(
				"urn:matrix:client:api:* urn:matrix:client:device:AABBCC \
				 urn:matrix:client:device:DDEEFF",
			),
			None,
		)
		.unwrap_err();

		assert!(err.to_string().contains("multiple Matrix device scopes"));
	}

	#[test]
	fn inactive_or_expired_introspection_is_not_active() {
		assert!(
			!IntrospectionResponse {
				active: false,
				sub: None,
				username: None,
				scope: None,
				device_id: None,
				expires_in: None,
				exp: None,
			}
			.is_active()
		);

		assert!(
			!IntrospectionResponse {
				active: true,
				sub: None,
				username: None,
				scope: None,
				device_id: None,
				expires_in: Some(0),
				exp: None,
			}
			.is_active()
		);
	}
}
