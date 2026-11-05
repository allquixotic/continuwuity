use ruma::{CanonicalJsonObject, EventId, OwnedEventId};
use serde::{Deserialize, Serialize};

/// Event graph reference. Legacy room versions sign the entire reference tuple,
/// including its hash. Preserve it across storage and forwarding; graph
/// traversal only needs the event ID. Modern references remain plain strings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EventReference {
	Id(OwnedEventId),
	Legacy((OwnedEventId, CanonicalJsonObject)),
}

impl AsRef<EventId> for EventReference {
	fn as_ref(&self) -> &EventId {
		match self {
			| Self::Id(id) | Self::Legacy((id, _)) => id,
		}
	}
}

impl From<OwnedEventId> for EventReference {
	fn from(id: OwnedEventId) -> Self { Self::Id(id) }
}
