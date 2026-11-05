# Offline upgrade preservation checks

These tools compare two **closed** RocksDB databases during an isolated upgrade
rehearsal. Run the copy without a network adapter because it holds the real
homeserver signing identity. Never open the live database with these tools.

`dbscan.cc` opens every column family read-only and verifies RocksDB checksums.
Compile it with C++20 against the RocksDB headers and static archive from the homeserver's
Cargo build; an older external RocksDB library may not support its table format.
It emits a binary stream consumed by `db_audit.py`, not a human-readable dump.
The scanner accepts a database path followed by optional column-family names.
Use a large file-descriptor limit (the rehearsal used 1048576).

Run `db_audit.py --db DATABASE --scanner DBSCAN --output AUDIT.json` before and
after the upgrade. The JSON records family counts/digests, a digest of timeline
events excluding only `unsigned`, historical-field counts, and identity/password
digests. The adjacent `.private` file contains access-token and media fixtures;
keep it private, with its containing directory accessible only to the operator.
Do not commit or upload audit output or private fixtures.

`compare_audits.py BEFORE.json AFTER.json --output COMPARISON.json` requires
unchanged critical data, all signed timeline content, all outliers, signing
identity, and nonempty password hashes. It also requires migration markers.

Upstream's emergency-access startup worker rewrites the server account's
`m.push_rules` entry with a fresh stream counter on every start. If that is the
only account-data difference, run `account_data_proof.py --before OLD_DATABASE
--after NEW_DATABASE --scanner DBSCAN --server-user SERVER_USER --output PROOF.json`.
It requires identical payloads and logical keys, byte-identical remaining rows,
and exactly one changed pointer for that server-account entry. Pass the result
to `compare_audits.py --account-data-proof PROOF.json`; its before/after family
hashes must match the full audit. Other account-data changes remain failures.

Run the synthetic proof regressions with
`python3 -m unittest discover -s tests/upgrade_audit -p 'test_*.py'`.

The scanner preserves MANIFEST WAL tracking and disables compaction during
read-only recovery. Default RocksDB options can try to clear WAL tracking or
move levels through a missing writable recovery context. Compile
`wal_fixture.cc` against the same RocksDB headers/archive and compression
libraries, then run `python3 tests/upgrade_audit/check_recovery.py --fixture
WAL_FIXTURE --scanner DBSCAN`. This creates a disposable real tracked WAL and
requires the scanner to replay its exact record. The regression and the fresh
production cold-backup read both passed with the corrected scanner.
