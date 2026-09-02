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

**On 1.0:** `tests/conformance.rs` still carries 9 architecture invariants that do not
hold yet. Releasing 1.0 while the suite says a stage is unfinished would claim something
the tests themselves contradict, so 1.0 waits until that count reaches zero.

Format note: this file is kept in English only. The rest of the repository keeps a
Chinese copy of each document, but a changelog is appended to on every release and a
translated copy drifts within weeks.

## [Unreleased]

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
