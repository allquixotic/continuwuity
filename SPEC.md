# SPEC

## §G GOAL
Upgrade deployed roota fork to upstream stable v26.9.1; preserve migrated accounts, history, media, legacy federation.

## §C CONSTRAINTS
- Upgrade deployed `codex/synapse-migration` patches only; audit `codex/matrix-spec-features` separately.
- Preserve remote dirty source; publish recovery branch before deployment.
- Production replacement requires passing protocol tests and isolated database-upgrade rehearsal.
- Keep production configuration, credentials, signing identity, database private.
- Preserve d6n uptime; no host reboot.

## §I INTERFACES
- I.client: Matrix client API, password login, room creation, messages, pagination, media.
- I.federation: Matrix federation API; room versions 1–12.
- I.migration: `continuwuity-synapse-migrate`; archived Synapse import/repair CLI.
- I.deploy: roota VM 107, `conduwuit.service`, `/usr/local/bin/conduwuit`.

## §V INVARIANTS
V1: Legacy room creation and bidirectional messages ! pass real two-server test across restart; see `tests/compat_smoke.py`.
V2: PDU validation, signatures, storage and forwarding ! preserve room-version wire format; legacy `event_id` preserved, modern `event_id` stripped.
V2a: Unsigned-data migration ! modify only `unsigned`; historical `prev_state`, membership and unknown event fields ! survive typed round trips; redaction ! apply room-version field rules.
V3: Upgraded production database ! pass isolated rehearsal before live replacement; rollback ! include pre-migration database.
V3a: Account-data preservation ! compare payloads and logical indexes; startup stream-counter exception ! prove only server push-rule pointer changed, bind proof to audited family hashes.

V4: Pagination arithmetic ! retain valid count variant when crossing zero; legacy `s0` ! HTTP 200.
V5: Protocol fixture capacity ! cover all advertised room versions 1–12 for both creators; test-only room creation budget ! exceed suite demand.
V6: Release artifact ! report its pinned source revision; cached Git metadata ! refresh through explicit build environment; binary revision assertion ! pass before deployment.

## §T TASKS
id|status|task|cites
---|---|---|---
T1|x|Recover deployed fork and dirty source; merge v26.9.1|I.deploy
T2|x|Pass workspace tests and real client/federation compatibility tests|V1,V2,I.client,I.federation
T3|~|Build Linux binary and rehearse upgrade on isolated roota copy|V3,I.deploy
T4|.|Publish tested candidate and upgrade production with rollback evidence|V3,I.deploy
T5|x|Audit undeployed feature branch against stable upstream|§C

## §B BUGS
id|date|cause|fix
---|---|---|---
B1|2026-11-05|Upstream sending service removed room-state dependency; legacy conversion could not compile|Restore explicit state dependency; workspace compile/tests
B2|2026-11-05|New policy-server assertion assumed every supported room strips `event_id`; legacy createRoom returned HTTP 500|V1,V2
B3|2026-11-05|Federated joins stripped legacy IDs and deserialized tuple references as modern strings|V1,V2; preserve negotiated wire format through signing, retain signed tuples through storage
B4|2026-11-05|Advancing legacy zero token produced positive Backfilled count; pagination panicked|V4; classify addition result by sign
B5|2026-11-05|Normalizing signed legacy reference tuples lost peer hashes; federation re-export changed content hash|V2; typed references preserve exact wire tuples, verified with Synapse crypto
B6|2026-11-05|Expanded 12-version test exceeded Synapse fixture's default ten-room burst budget|V5; increase disposable fixture budget, exercise all advertised versions
B7|2026-11-05|Production copy contains 616770 `prev_state` fields and 14 oversized metadata integers; typed PDU reserialization discarded or rejected historical fields|V2a; preserve extra fields, redact by room rules, migrate unsigned on raw stored JSON rows
B8|2026-11-05|Upstream build metadata disables Git-change triggers; cached release reported old 3ae1d1da despite new source|V6; export pinned Git revision, assert executable label
B9|2026-11-05|CI revision assertion required eight characters while upstream Git default emitted seven|V6; pin full and eight-character short revision from actual checkout before Cargo
B10|2026-11-05|Offline audit required byte-identical account-data indexes although startup rewrites server push-rule stream counter|V3a; separately prove exact payload preservation and sole server pointer change, retain strict checks for all user data
