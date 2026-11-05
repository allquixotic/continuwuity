# roota stable-upstream integration

## Scope and provenance

This upgrade carries forward the deployed `codex/synapse-migration` fork only.
The undeployed `codex/matrix-spec-features` branch is audited separately below;
none of its divergent feature commits is included in this upgrade.

| Source | Revision |
| --- | --- |
| Production binary version | `continuwuity 0.5.9 (c6d0e1c8)` |
| Production source HEAD | `c6d0e1c813394d1108be82cbff0d03a37ff91afd` |
| Recovery branch, including six uncommitted files | `recovery/roota-2026-11-05`, `dc4cd5d16` |
| Upstream stable | [`v26.9.1`](https://forgejo.ellis.link/continuwuation/continuwuity/releases/tag/v26.9.1), `046074bbc2c8d1af6dd86f93e1c512fbd8b78da8` |
| Initial integration merge | `3ae1d1da508b057f06ccce0ae217ac44301fd0ae` |
| Undeployed feature branch audited | `11fa5f980487427c501f715d95497c452a2fabe8` |

The production executable's SHA-256 was
`a84ddc055d7ce3f6f5abbac42c90bd5f3786c601cefe8aed4a3ae017af3c3782`.
Its embedded revision does not establish whether the executable was built from
the dirty working tree. Recovery preserves both the committed source and the
six changed files without making that assumption.

The recovered dirty patch has SHA-256
`2cc63dc1eb814f054a0ab3393616873af20a5dc6acb17442d6d25eba0f53fcea`.
Production configuration, keys, database, access tokens, and private test data
are excluded from this repository.

## Deployed patch decisions

| Patch family | Decision | Evidence and implications |
| --- | --- | --- |
| Synapse bcrypt passwords, normalization and pepper handling | Retain | Upstream password authentication uses Argon2. `src/core/utils/hash/synapse.rs` retains migrated-password support and focused tests. |
| Synapse stream tokens | Retain | Upstream parses native numeric counts. `src/core/matrix/pdu/count.rs` also accepts historic `s`, `t`, and multi-writer `m` tokens. A protocol test exposed and now covers advancing across zero. |
| Room versions 1 and 2 | Retain and adapt | Stable upstream rejects these versions and assumes hash-based event IDs. Keep server-assigned IDs, tuple references, signing, validation, and negotiation compatible with legacy rooms. |
| Historical room-version stability and capability cache headers | Retain | Upstream does not advertise all historical versions as stable or send these cache-control headers. Preserve the migrated server's capabilities without losing upstream's new capability fields. |
| Missing room summary returns 404 | Retain | Upstream's corresponding missing-room path still needed the local response correction. |
| Authenticated-first remote media for legacy client endpoints | Retain | Upstream's legacy wrappers still call unauthenticated federation media directly. Keep the authenticated path and fallback, with current metadata types. |
| Legacy event references | Replace normalization | Preserve upstream's new PDU checks, auth-chain fetcher, graph sorting, rate limits and security fixes. Preserve the original signed tuples in typed PDUs and stored JSON; normalize only graph traversal through the event-ID interface. |
| Old standalone incoming transaction graph builder | Retire implementation | Upstream has a new graph builder under `event_handler/fetch_and_handle_outliers.rs`. Port the necessary tuple-reference handling there rather than retain the old transaction implementation. |
| Missing-room-version fallback to version 1 and diagnostic logging | Retire | Upstream's room-version lookup now propagates failure. Guessing version 1 is unnecessary and weakens validation. |
| Old `built` / `serde_json` dependency bumps | Retire | Use stable upstream's newer versions. Keep only dependencies required by the retained importer and bcrypt support. |
| Axum query extractor feature | Retain | Required by the existing fork's routes. |
| Synapse SQLite/PostgreSQL migration, repair and auxiliary metadata tools | Retain as separate executable | Upstream has no equivalent importer. These are recovery/provenance tools, not a reason to re-import the running database. Adapt dependencies and media metadata encoding to stable upstream. |

An upstream feature with a similar name is insufficient evidence that an import
or compatibility patch is obsolete. In particular, native OAuth does not replace
authentication of existing Synapse bcrypt accounts, and newer room versions do
not eliminate existing version-1/2 history.

## Undeployed feature branch audit

This is a source comparison against stable `v26.9.1`, not a claim that the older
feature branch has been rebased or tested against it. “Covered” means upstream
contains the main behavior; historical unstable aliases may still differ.

| Feature-branch commit | Feature | Stable-upstream assessment |
| --- | --- | --- |
| `95d0e9ff1` | Dependency refresh | Superseded by stable upstream's dependency set. Do not carry forward the older version pins. |
| `992f1b5fa` | MSC3030 timestamp lookup | Still distinct. Stable has no corresponding client/federation timestamp route or timeline timestamp implementation. |
| `1d09a8099` | MSC2705 animated thumbnails | Still distinct. Upstream requests animated remote thumbnails but its thumbnail `Dim` and client handling do not implement the branch's per-request animation behavior/cache separation. |
| `6e77a0986` | MSC4115 membership metadata | Main behavior covered. Upstream `timeline/helpers.rs::get_unsigned_context` derives membership from event state and `pdu/unsigned.rs` emits it. Review edge cases before deleting the old work. |
| `7e325eb21` | MSC2246 asynchronous media upload | Still distinct. Stable lacks the reserve-MXC and deferred-upload routes and pending-media storage. |
| `f9e283776` | MSC2409 appservice EDUs | Partial infrastructure only. Upstream can serialize queued appservice ephemeral events, but the branch adds producers/routing for presence, typing, and receipts. Keep this as a separate feature candidate. |
| `5aa7b7969` | MSC4222 `state_after` sync | Main behavior covered in upstream `sync/v3/{mod,joined,left,state}.rs`. No need to preserve the old sync implementation for this feature. |
| `531e33358` | MSC4025 local user erasure | Still distinct. Stable's deactivation does not consume `body.erase` or perform the branch's erased-user/account-data/media handling. |
| `be908720a` | Appservice device management | Partly superseded. Stable creates the requested device ID and handles appservice identity; it still leaves outgoing appservice `to_device` as a TODO. The branch's full device-list/to-device delivery is not replaced. |
| `a747a41f4` | Extended URL preview metadata | Partial overlap. Stable supports image, video and audio previews; compare the branch's additional OpenGraph fields and metadata parsing individually. |
| `059fcd2e1` | OAuth metadata discovery | Discovery endpoint covered by upstream `api/client/oauth/server_metadata.rs`. Its metadata describes upstream's native OAuth server, rather than the branch's configured external server. |
| `9e4376b42` | MSC4312 cross-signing reset UIA | Native OAuth flow covered by upstream `OAuthTicket::CrossSigningReset`, UIAA, and account web flow. The branch's external delegation/admin reset authorization is architecturally different. |
| `9bcea8444` | MSC4326 device masquerading | Core behavior covered in upstream `api/router/auth.rs`, including stable `device_id`, the historic query alias, and device-existence checks. Audit the branch's remaining endpoint details before discarding it. |
| `7fa75183d` | MSC3861 delegated OAuth authentication | Not a drop-in replacement. Upstream now implements native OAuth authorization/token/device flows and OIDC login; the branch implements external token introspection/delegation. Prefer upstream's model unless external delegation is still a requirement. |
| `9306dc471` | MSC4133 capability advertisement | Stable `m.profile_fields` is covered, including upstream restrictions. The branch additionally emits a historic unstable alias. |
| `3d7ee749c` | MSC3882 login-token advertisement | Stable capability and login-token route are covered. The branch additionally provides historic unstable aliases/feature flags. |
| `64118c37f` | MSC4289 creator transfer | Partial overlap. Stable accepts additional creators on creation/upgrade. The branch adds trusted-private-chat creator derivation and creator-transfer rules/validation that require separate behavioral review. |
| `d8fa9037f` | Matrix v1.17 advertisement | Superseded. Stable already advertises v1.17 and v1.18; copying the old list would regress upstream's declaration. This does not assert complete conformance to every endpoint in those versions. |
| `11fa5f980` | Blurhash dependency removal | Covered: stable no longer contains the removed direct blurhash dependency. |

## Verification and deployment gates

`tests/compat_smoke.py` uses disposable loopback-only homeservers and synthetic
accounts. It exercises rooms created on each implementation, bidirectional
messages, historical pagination tokens, remote authenticated/legacy media, and
restart persistence. With `--synapse-python`, it uses a separate
`matrix-synapse==1.164.2` installation and independently checks legacy event
exports. Test-only TLS bypasses never enter production configuration.

Completed during integration:

- macOS ARM64 workspace tests: 287 passed, 0 failed, 2 pre-existing ignored.
- Production executable Clippy: `cargo clippy -p conduwuit --locked -- -D warnings` passed.
- Six-version two-server federation test passed.
- Synapse interoperability: both creators, six versions, 24 delivered messages,
  remote media, existing tokens and history after restart passed. Legacy federation re-export signatures and content hashes are verified with Synapse crypto.

Whole-workspace strict Clippy exposes existing lint debt in the standalone
Synapse importer. Passing its 52 unit tests does not remove that debt or validate fresh imports against every new upstream schema. The importer is retained for recovery; do not run its old reference-normalization repair on upgraded databases, because new code preserves signed tuples. The
production executable has a separate passing strict lint check.

Before live replacement, the Linux artifact must pass tests and an isolated
upgrade of a production database copy. The copy must have no network adapter
before boot, because it contains the real server identity. Database migrations
must be observed to completion. A rollback must restore the pre-upgrade
database together with the old executable; swapping only the executable is
insufficient after schema changes. Deployment results and artifact hashes are
recorded after those gates pass.
