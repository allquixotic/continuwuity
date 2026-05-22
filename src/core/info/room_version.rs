//! Room version support

use std::iter::once;

use ruma::{RoomVersionId, api::client::discovery::get_capabilities::v3::RoomVersionStability};

use crate::{at, is_equal_to};

/// Supported Matrix room versions whose spec stability is stable.
///
/// Stability here is not the same thing as recommendedness. Historical room
/// versions remain stable protocol versions and must be advertised as such so
/// clients do not prompt admins to upgrade migrated legacy rooms unnecessarily.
pub const STABLE_ROOM_VERSIONS: &[RoomVersionId] = &[
	RoomVersionId::V1,
	RoomVersionId::V2,
	RoomVersionId::V3,
	RoomVersionId::V4,
	RoomVersionId::V5,
	RoomVersionId::V6,
	RoomVersionId::V7,
	RoomVersionId::V8,
	RoomVersionId::V9,
	RoomVersionId::V10,
	RoomVersionId::V11,
	RoomVersionId::V12,
];

/// Experimental, partially supported room versions
pub const UNSTABLE_ROOM_VERSIONS: &[RoomVersionId] = &[];

type RoomVersion = (RoomVersionId, RoomVersionStability);

impl crate::Server {
	#[inline]
	pub fn supported_room_version(&self, version: &RoomVersionId) -> bool {
		self.supported_room_versions().any(is_equal_to!(*version))
	}

	#[inline]
	pub fn supported_room_versions(&self) -> impl Iterator<Item = RoomVersionId> + '_ {
		Self::available_room_versions()
			.filter(|(_, stability)| self.supported_stability(stability))
			.map(at!(0))
	}

	#[inline]
	pub fn available_room_versions() -> impl Iterator<Item = RoomVersion> {
		available_room_versions()
	}

	#[inline]
	fn supported_stability(&self, stability: &RoomVersionStability) -> bool {
		self.config.allow_unstable_room_versions || *stability == RoomVersionStability::Stable
	}
}

pub fn available_room_versions() -> impl Iterator<Item = RoomVersion> {
	let unstable_room_versions = UNSTABLE_ROOM_VERSIONS
		.iter()
		.cloned()
		.zip(once(RoomVersionStability::Unstable).cycle());

	STABLE_ROOM_VERSIONS
		.iter()
		.cloned()
		.zip(once(RoomVersionStability::Stable).cycle())
		.chain(unstable_room_versions)
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeMap;

	use ruma::{
		RoomVersionId, api::client::discovery::get_capabilities::v3::RoomVersionStability,
	};

	use super::available_room_versions;

	#[test]
	fn historical_stable_room_versions_are_not_advertised_as_unstable() {
		let available = available_room_versions().collect::<BTreeMap<_, _>>();

		for room_version in [
			RoomVersionId::V1,
			RoomVersionId::V2,
			RoomVersionId::V3,
			RoomVersionId::V4,
			RoomVersionId::V5,
		] {
			assert_eq!(available.get(&room_version), Some(&RoomVersionStability::Stable));
		}
	}
}
