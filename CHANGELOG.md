# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), with one
addition: every release that needs an operator to do something carries an **Upgrade
steps** section. In this project those steps are not optional — a release that adds a
table will not run until `schema.sql` is re-imported, and a release that adds a required
key will not start until it is set. Burying that under "Changed" gets it skipped.

Versions follow [Semantic Versioning](https://semver.org/), keyed to the **deployment
surface** rather than to the Rust API. Consumers never link against this crate; what can
break them is the contract, the schema and the configuration:

| Change | Bump |
|---|---|
| A path, field or error code removed or renamed in `contracts/openapi.yaml` | minor while 0.x, major after 1.0 |
| A new **required** configuration key (an existing deployment stops starting) | minor |
| A new table or column in `schema.sql` | minor, plus an Upgrade steps section |
| A new optional configuration key | patch |
| Internal refactoring, bug fixes, documentation | patch |

**On 1.0:** `tests/conformance.rs` still carries 7 architecture invariants that do not
hold yet. Releasing 1.0 while the suite says a stage is unfinished would claim something
the tests themselves contradict, so 1.0 waits until that count reaches zero.

Format note: this file is kept in English only. The rest of the repository keeps a
Chinese copy of each document, but a changelog is appended to on every release and a
translated copy drifts within weeks.

## [Unreleased]

### Security

- **The MFA encryption key is no longer derived from `JWT_SECRET`.** When
  `MFA_SECRET_ENCRYPTION_KEY` was unset, the key that seals every stored TOTP secret was
  derived from `JWT_SECRET` and the process carried on with a warning. `JWT_SECRET` is a
  secret that gets rotated — on exposure, on a schedule, on an algorithm change — and
  rotating it made every stored TOTP secret permanently undecryptable: every enrolled
  user locked out at once, with a startup log line from months earlier as the only clue.
  There is now no fallback. The three keys (token signing, credential encryption, audit
  integrity) are independent, which `tests/conformance.rs::b5` asserts.

### Removed

- **`GET /api/ops/memberships/overview`.** The endpoint reported how many accounts sat
  in each membership tier, and carried a hard-coded price list in its response
  (`"PRO": {"price": 19.9}`). Pricing is not an authentication concern, and an identity
  service that ships one cannot be deployed by anyone whose tiers differ. Membership
  reporting belongs to whatever system owns billing, which can aggregate the field it
  already owns. The contract is now 71 paths and 84 operations.

### Changed

- **Membership level is an opaque label.** `PUT /api/users/:user_id/membership` validated
  the value against five hard-coded tier names and rejected anything else, so adding a
  tier meant changing SoulAuth and redeploying it. It now validates shape only —
  uppercased, 1 to 32 characters, letters, digits, `_` and `-` — and stores the label
  without interpreting it. Values that were previously rejected are now accepted; the
  contract already declared this field as a plain string.
- **MFA requires `MFA_SECRET_ENCRYPTION_KEY`.** Without it the MFA endpoints return
  `503 service_unavailable` naming the missing variable, instead of working on a derived
  key. Startup is unaffected: an instance that does not use MFA still runs on the four
  variables the quickstart sets. A non-loopback `APP_URL` already required the key at
  startup and still does.

### Upgrade steps

1. **If you enrolled MFA users while `MFA_SECRET_ENCRYPTION_KEY` was unset**, their
   stored secrets were sealed with a key derived from `JWT_SECRET` and cannot be carried
   over — the derivation no longer exists. Those users must re-enrol. Count them before
   upgrading:

   ```bash
   surreal sql --endpoint http://127.0.0.1:8000 --user root --pass root \
       --namespace auth --database main --pretty \
       <<< "SELECT count() FROM user_mfa WHERE totp_secret != NONE GROUP ALL;"
   ```

   If that returns zero, there is nothing to do.

2. **Set the key** if you use MFA at all, not only in production:

   ```bash
   MFA_SECRET_ENCRYPTION_KEY=$(openssl rand -base64 32)
   ```

   Keep it with your other secrets and separately from database backups: a database dump
   alone yields no usable TOTP codes, a dump plus this key does.

3. **If anything calls `/api/ops/memberships/overview`**, it now receives 404. The same
   figure comes from one query against the database you already have:

   ```sql
   SELECT membership_level, count() AS total FROM user
     WHERE account_status != 'Deleted' GROUP BY membership_level;
   ```

## [0.1.0] - 2026-09-09

First public release, and the version referenced by the SoulAuth paper. The tag
`v0.1.0` points at the commit this section describes; `CITATION.cff` records the same
version and commit so a citation resolves to one fixed state of the code rather than to
whatever `main` happens to be.

Everything below is relative to the pre-release state of the codebase.

### Added

- **Tamper-evident audit.** Every `user_activity` row carries `seq`, `previous_hash` and
  `event_hash`; the chain head is signed hourly with an Ed25519 key held outside the
  database. `GET /api/audit/integrity` re-derives every chain and verifies each
  checkpoint. Editing a row breaks its own hash, deleting one breaks the next row's link
  and leaves a gap in the sequence, and rewriting a whole chain no longer matches the
  signatures already issued.
- **Graceful shutdown.** SIGTERM and Ctrl+C stop the server accepting new requests and
  then drain the audit queue before the process exits. There was previously no shutdown
  handling at all, so `docker compose down`, `systemctl stop` and a rolling update each
  cut in-flight requests mid-way.
- `RESET_PASSWORD_PAGE_URL`, so a frontend on another origin can host the password reset
  page. Only the verification page was overridable before, which left the reset link
  pointing at a path that deployment did not serve.
- `AUDIT_INTEGRITY_KEY` and `SOULAUTH_INSTANCE_ID`. Both are required once `APP_URL` is
  not a loopback address; see Upgrade steps.
- Bootstrap can now be resumed. If creating the first administrator fails after the
  account exists but before the role is granted, retrying with the same token and email
  continues from there instead of leaving the instance with no administrator and an
  email address that cannot be reused.

### Changed

- Audit writes go through a queue drained by a dedicated writer, with retries on
  transient database errors, instead of one spawned task per event.
- `APP_URL` must be https once it is not a loopback address. Plaintext there costs the
  session cookie its `Secure` flag, sends mail links unencrypted, and produces an OIDC
  issuer that violates the Discovery specification.
- `OAUTH_REDIRECT_URL` is validated the way the endpoint overrides already were: an
  absolute https URL, or plaintext http only for an exact loopback host.
- `CORS_ALLOWED_ORIGINS=*` is now a startup configuration error. It previously reached
  `tower-http` and panicked, with nothing in the message naming the setting.
- The OIDC client list reports the real total rather than the size of the current page.
- Login, registration and MFA responses are produced by the same error mapping as every
  other endpoint. Two human-facing messages changed wording as a result; error codes and
  status codes did not.
- `schema.sql` is idempotent: every `DEFINE` carries `IF NOT EXISTS`, so re-importing is
  a no-op rather than an error.

### Fixed

- **Redirect URI validation accepted hostile hosts.** The loopback exemption was a
  prefix match, so `http://localhost.evil.example/cb` was treated as local while the
  legitimate `http://[::1]:3000/cb` was rejected. It now compares the parsed host
  exactly.
- **TOTP codes and backup codes could be used twice.** Both were read-modify-write, so
  two concurrent requests could each pass and each be issued a session. Consumption is
  now a single conditional update.
- **The first-administrator endpoint was not atomic.** Concurrent requests holding the
  same token could each create an administrator.
- **`/api/audit/security-report` and `/security-metrics` had been returning empty data,
  not 200-with-no-events.** A record column was selected without projection, so the rows
  never deserialised; the failure was swallowed into an empty list. Monitoring could not
  tell "no suspicious activity" from "the read failed".
- An https proxy configured through `PROXY_URL` was silently rewritten to http, and the
  full proxy URL — credentials included — was written to the log.

### Security

- The audit log is tamper-evident (see Added). It was an ordinary table.
- Three separate keys, none derived from another: `JWT_SECRET`, the OIDC signing key,
  `MFA_SECRET_ENCRYPTION_KEY` and `AUDIT_INTEGRITY_KEY`. Rotating one must not
  invalidate the others.

### Upgrade steps

1. **Re-import both SQL files** against the existing database:

   ```bash
   surreal import --endpoint … --namespace auth --database main schema.sql
   surreal import --endpoint … --namespace auth --database main initial_data.sql
   ```

   You do not have to work out which statements are new. Every `DEFINE` carries
   `IF NOT EXISTS` and the seed data is all `UPSERT`, so re-importing is a no-op for
   anything already there. Skipping this step is what breaks the upgrade: the endpoints
   that use the new tables fail at runtime, not at startup.

2. **Set two new keys** before restarting, if `APP_URL` is not a loopback address —
   the process refuses to start without them:

   ```bash
   AUDIT_INTEGRITY_KEY=$(openssl rand -base64 32)   # same value on every replica
   SOULAUTH_INSTANCE_ID=<pod or host name>          # different on every replica
   ```

   `SOULAUTH_INSTANCE_ID` is the one setting that must *differ* between replicas: it
   names that replica's audit chain, and two replicas sharing a name collide on a unique
   index, which silently drops the later one's audit events.

3. **Confirm `APP_URL` is https.** A non-loopback plaintext address now refuses to
   start.

4. Rows written before this release have no hash chain. `GET /api/audit/integrity`
   counts them separately as `unchained` rather than reporting a break — an upgrade does
   not accuse your existing history of having been tampered with.
