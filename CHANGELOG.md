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

**On 1.0:** `tests/conformance.rs` still carries 1 architecture invariant that does not
hold yet. Releasing 1.0 while the suite says a stage is unfinished would claim something
the tests themselves contradict, so 1.0 waits until that count reaches zero.

Format note: this file is kept in English only. The rest of the repository keeps a
Chinese copy of each document, but a changelog is appended to on every release and a
translated copy drifts within weeks.

## [Unreleased]

Nothing yet.

## [0.2.0] - 2026-09-12

The release in which Actor Identity stops being a data-model claim and becomes the
authentication subject on every path: session and OIDC `sub` are the identity root,
every credential path passes one gate, and the audit chain can be verified end to end.

Every SQL statement in the **Upgrade steps** below is executed by
`tests/migration_walkthrough.sh` against a database seeded in the previous release's
shape, on every push. Two of them were wrong before that script existed.

### Security

- **Human authentication now resolves to the identity root, not the account row.** The
  session JWT `sub`, the OIDC `sub` and UserInfo `sub` were all the `user` table's primary
  key, while an AI actor's `sub` was its `actor_identity` key. The two kinds of subject
  were said to enter one identity contract, and in the tokens they were two different
  things. Every authentication path — password, MFA second step, OAuth callback, bearer
  extractor, OIDC authorize / refresh / userinfo — now passes through one gate that
  resolves the identity root, checks the actor kind matches, and checks the status allows
  authentication. `tests/conformance.rs::j21` asserts the gate covers all of them.

  Before this, suspending a Human's `actor_identity` had **no effect on authentication**:
  most paths only read `user.account_status`, so the object the architecture calls the
  identity boundary did not control authentication eligibility.
- **The OIDC subject is the identity root's stable `subject_key`.** It no longer changes
  if the account row is migrated, and it is the same subject across clients.
- **OAuth resolves only through canonical `identity_binding`, and never merges accounts by
  email.** The path used to read the V1 `identity_provider` table, log in on a hit, then
  "backfill" the binding — failures logged and ignored. So the canonical binding was
  neither a precondition nor the source of truth. Worse, an external identity whose email
  matched an existing account was attached to it automatically: a verified email in two
  identity domains proves each domain considers it reachable, **not** that the subjects are
  the same, and addresses get recycled and transferred. That is now refused, with a message
  telling the caller to sign in and link explicitly. A binding that cannot be created makes
  the first federated login fail instead of leaving an account that can log in once and
  never again.
- **`identity_provider` is removed.** Nothing resolves identity through it any more.
- **The database connection must be encrypted and must not be root in production.** Both
  were deployment advice — a warning at startup and a line in SECURITY.md. For a service
  holding every password hash, session fingerprint and signing key, they belong in the
  startup gate.
- **The MFA encryption key is no longer derived from `JWT_SECRET`.** When
  `MFA_SECRET_ENCRYPTION_KEY` was unset, the key that seals every stored TOTP secret was
  derived from `JWT_SECRET` and the process carried on with a warning. `JWT_SECRET` is a
  secret that gets rotated — on exposure, on a schedule, on an algorithm change — and
  rotating it made every stored TOTP secret permanently undecryptable: every enrolled
  user locked out at once, with a startup log line from months earlier as the only clue.
  There is now no fallback. The three keys (token signing, credential encryption, audit
  integrity) are independent, which `tests/conformance.rs::b5` asserts.

### Fixed

- **A signed checkpoint was never compared against the chain node it claims to anchor.**
  The integrity report verified that the chain was internally consistent and that some
  checkpoint's signature was valid, then returned `intact`. It never checked that
  `checkpoint.head_hash` equals the actual `event_hash` at `(chain_id, seq_to)`. So anyone
  with write access could keep one old, validly signed checkpoint, rewrite the whole chain
  and recompute every hash: the new chain is self-consistent, the old signature still
  verifies, and the system reports intact. Preventing exactly that is the only reason
  checkpoints exist. A checkpoint whose anchor does not match is now reported as a break
  (`broken_reason: "checkpoint_anchor"`), not as one fewer verifiable checkpoint.
- **A database error while reading the audit chain head was treated as "empty table".**
  `load_chain_head` ended in `.unwrap_or_default()`, so one failed query reset the head to
  genesis and the next write started at `seq = 1` — colliding with the existing rows on the
  unique `(chain_id, seq)` index, after which **that process could never write another audit
  event**. The only trace was one log line. Reading the head can now fail distinctly, the
  event is not written from genesis, and the subsystem is marked unhealthy.
- **Audit event loss is now counted and observable.** The module claimed it never loses
  events. It can: a full queue, exhausted write retries and a flush timeout all drop. Drops
  are counted and surface as `audit_writes_healthy` / `audit_events_dropped` on
  `GET /api/audit/system-health`. The claim is gone from the documentation.
- **AI actor authentication is attributed through a foreign key.** A successful key
  authentication only put the actor id inside free-form `details`, leaving
  `user_activity.actor_identity_id` as `NONE` — so the authentication history of a subject
  could not be queried by relationship, and the value was mutable weakly-typed text. The
  failure event's actor id, which comes from an unverified request parameter, is now
  `claimed_actor_id` so it cannot be mistaken for attribution.
- **OIDC `auth_time` came from `user.last_login_at`.** That field is updated by *any later*
  login, so an ID token issued from an old session could carry an authentication time later
  than its own. It now comes from the session that was actually established.
- **Revocation no longer reports success when it failed.** Password reset and `logout-all`
  logged a failed OIDC token revocation and returned 200, telling the user that access had
  been withdrawn while it had not. Both now fail the request. RP-initiated logout must
  still redirect per the specification, so there it records a `Failed` audit event — which
  goes into the hash chain — instead of only logging.
- **The audit hash chain could not be verified for any attributed row.** The digest was
  computed over the normalised user key, while the row stored the resolved identity-root
  reference — two different strings. `GET /api/audit/integrity` recomputes the digest from
  the row, so every event that had a user attached came back as a hash mismatch, and the
  endpoint reported an intact chain as broken. A tamper-evidence check that cries wolf is
  worse than none: it teaches people to ignore it.

  The writer now resolves the identity root *before* computing the digest and stores that
  same value, so verification can recompute from the row alone. `tests/conformance.rs::f1`
  asserts the ordering and that the digest field and the column agree; the integration
  suite now asserts `intact` and `checked > 0` rather than only a 200, which is what would
  have caught this.
- **Top active users always reported an empty email.** The report took the attribution
  value from the audit row — an `actor_identity` address — stripped a `user:` prefix that
  was never there, and looked it up against `user.id`. The two keys are unrelated, so the
  lookup never matched. It now resolves through `user.subject_id`, which is where the
  relationship actually lives.

### Removed

- **`GET /api/ops/memberships/overview`.** The endpoint reported how many accounts sat
  in each membership tier, and carried a hard-coded price list in its response
  (`"PRO": {"price": 19.9}`). Pricing is not an authentication concern, and an identity
  service that ships one cannot be deployed by anyone whose tiers differ. Membership
  reporting belongs to whatever system owns billing, which can aggregate the field it
  already owns. The contract is now 71 paths and 84 operations.

### Changed

- **The password has its own object.** A password hash was a column on the `user` row, so
  the credential had no lifecycle of its own: changing a password meant rewriting the
  account row, revoking one credential could not be expressed at all, and the state
  "this credential is revoked but the subject still exists" could not be written down.
  Clearing the column left "revoked" and "never set" looking identical in the database,
  which are entirely different things.

  Passwords now live in a `credential` table keyed to the identity root, with `status`,
  `rotated_at` and `revoked_at`. One row per (identity, kind): rotation updates that row
  and records when, rather than appending and relying on a "take the newest" convention.
  `services::credential` is the only place that reads or writes it, which
  `tests/conformance.rs::a2` asserts — the four paths that used to touch the column
  (registration, login, first-password, password reset) each went through it
  independently, and missing one was invisible.

  AI actor keys stay in `ai_actor_credential` (one identity holds many, each revoked
  independently) and TOTP secrets stay in `user_mfa` (reversible, with its own key).
  Merging either needs its own decision about semantics, not a table move.

  `UserResponse` keeps `has_password`, so the API shape is unchanged. It is no longer
  derivable from the account row, so the conversion now takes it as an explicit argument
  and every construction site answers the question — a `From` impl could only have
  quietly filled in `false`, which would have sent people who already have a password
  back to the set-a-password page with nothing reporting an error.
- **Deleting an account revokes its password credential.** Suspension does not: it is
  reversible, and the password should still work on reinstatement. Deletion is not, so the
  credential stops being usable — by a change of status rather than a deletion of the row,
  because "this credential existed and was revoked" and "there was never one" are
  different facts.
- **`user_profile` references the identity root by name, not just by type.** The column
  was `user_id TYPE record<actor_identity>` — it pointed at the right table while calling
  itself something else, and a reader had no way to know which half was true. Both the
  column and its unique index are now `actor_identity_id`, and so is the field in
  `UserProfileResponse`: the API no longer claims a profile belongs to a `user` row.
  `tests/conformance.rs::h2` asserts the old name is gone rather than merely that the new
  one exists, because two names for one reference is worse than one wrong name.
- **Both authentication paths produce one result type.** A human proving itself with a
  password, MFA, an external identity or a mail link, and an AI actor proving itself with
  an Ed25519 challenge-response, now produce the same `AuthenticationResult`: identity
  root, actor kind, credential kind, credential label, token, expiry. The AI path had its
  own `ActorSession` with nearly the same fields and a different type, so every consumer
  needed a branch per kind of subject and "both enter one Actor Identity Contract" had
  nothing behind it in the code. Wire shapes are unchanged. The audit record for AI actor
  authentication gains `credential_kind`.
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

4. **Move existing passwords into `credential` before starting the new build.** Login
   reads the credential table, so an account whose hash is still only on the `user` row
   cannot sign in. Re-import `schema.sql` first so the table exists, then:

   ```sql
   INSERT INTO credential (
       SELECT subject_id AS actor_identity_id,
              'password' AS kind,
              password AS secret_hash,
              'active' AS status,
              time::unix(time::now()) AS created_at
         FROM user WHERE password != NONE AND subject_id != NONE
   );
   ```

   Check the counts match before removing the column — the left side is how many accounts
   had a password, the right side how many credentials now exist:

   ```sql
   SELECT count() FROM user WHERE password != NONE GROUP ALL;
   SELECT count() FROM credential WHERE kind = 'password' GROUP ALL;
   ```

   Then drop the column, so there is one answer to "where is the password":

   ```sql
   REMOVE FIELD password ON TABLE user;
   ```

5. **Migrate `user_activity.user_id` to `actor_identity_id`.** The column is renamed, and
   the integrity report reads the new name:

   ```sql
   UPDATE user_activity SET actor_identity_id = user_id WHERE actor_identity_id = NONE;
   REMOVE FIELD user_id ON TABLE user_activity;
   REMOVE INDEX user_activity_user_idx ON TABLE user_activity;
   ```

   Re-import `schema.sql` after the `REMOVE INDEX` to rebuild it on the new column.

   Rows written before this release carry a digest computed over a value that is not in
   the row, so they cannot be re-derived and the report will flag the first of them. The
   chain is verifiable from this release onward. If you want a clean report, re-chain the
   existing rows once — this is a deliberate one-time rewrite of hashes for rows whose
   digests were never verifiable, not a routine operation:

   ```sql
   DELETE user_activity WHERE chain_id != NONE;
   ```

   Consumers reading `user_id` from `/api/audit/activity-summary`, `security-report` or an
   activity log must read `actor_identity_id`; the value is unchanged.

6. **Every issued token stops working.** The session JWT `sub` and the OIDC `sub` changed
   from the account row's key to the identity root's. There is no dual-accept window: a
   token whose `sub` is a `user` key no longer resolves. Plan the upgrade as a forced
   re-login, and tell relying parties that `sub` values change once — a consumer that
   stored the old `sub` as a user identifier must re-map it:

   ```sql
   -- 旧 sub（user key） → 新 sub（subject_key）的对应表，导出给接入方
   SELECT type::string(id) AS old_sub, subject_id.subject_key AS new_sub
     FROM user WHERE subject_id != NONE;
   ```

7. **Move `identity_provider` rows into `identity_binding`, then drop the table.** OAuth
   resolves only through the binding now, so a social account with no binding cannot sign
   in until this runs:

   ```sql
   INSERT INTO identity_binding (
       SELECT user_id AS actor_identity_id,
              provider,
              provider_user_id AS provider_subject,
              'federated' AS binding_type,
              'verified' AS verification_state,
              time::unix(time::now()) AS bound_at
         FROM identity_provider
   );
   REMOVE TABLE identity_provider;
   ```

   Check the counts match before dropping the table.

8. **Apply the new constraints with `OVERWRITE` — re-importing `schema.sql` is not
   enough.** The canonical enums (`actor_kind`, `actor_identity.status`, `identity_source`,
   `binding_type`, `verification_state`, credential `kind` / `status`) are now enforced by
   `ASSERT`, and `human_account` / `ai_actor_credential` assert the actor kind they may
   attach to. But `DEFINE FIELD IF NOT EXISTS` **skips a column that already exists**, so on
   an upgraded database the re-import leaves the old, unconstrained definitions in place and
   the `ASSERT`s silently never take effect. `tests/migration_walkthrough.sh` caught this.
   Redefine them explicitly:

   ```sql
DEFINE FIELD OVERWRITE actor_kind ON actor_identity TYPE string
    ASSERT $value IN ['human', 'ai_actor'];
DEFINE FIELD OVERWRITE identity_source ON actor_identity TYPE string DEFAULT "local"
    ASSERT $value IN ['local', 'soulseed', 'external'];
DEFINE FIELD OVERWRITE status ON actor_identity TYPE string DEFAULT "active"
    ASSERT $value IN ['active', 'suspended', 'retired'];
DEFINE FIELD OVERWRITE actor_identity_id ON human_account TYPE record<actor_identity>
    ASSERT $value.actor_kind = 'human';
DEFINE FIELD OVERWRITE binding_type ON identity_binding TYPE string DEFAULT "federated"
    ASSERT $value IN ['federated', 'canonical'];
DEFINE FIELD OVERWRITE verification_state ON identity_binding TYPE string DEFAULT "verified"
    ASSERT $value IN ['verified', 'pending', 'revoked'];
DEFINE FIELD OVERWRITE kind ON credential TYPE string
    ASSERT $value IN ['password'];
DEFINE FIELD OVERWRITE status ON credential TYPE string DEFAULT "active"
    ASSERT $value IN ['active', 'revoked'];
DEFINE FIELD OVERWRITE actor_identity_id ON ai_actor_credential TYPE record<actor_identity>
    ASSERT $value.actor_kind = 'ai_actor';
   ```

   Before that, check no existing row holds a value outside the allowed set — otherwise
   the `OVERWRITE` succeeds but later writes to that row fail:

   ```sql
   SELECT type::string(id), status, actor_kind FROM actor_identity
     WHERE status NOT IN ['active','suspended','retired']
        OR actor_kind NOT IN ['human','ai_actor'];
   ```

9. **Set a database user that is not `root`, over TLS**, if the database is not on
   loopback. The process now refuses to start otherwise.

10. **Migrate `user_profile.user_id` to `actor_identity_id`** before restarting. Re-importing
   `schema.sql` defines the new column but does not move the data, and a profile whose
   reference is empty reads back as "no profile":

   ```sql
   UPDATE user_profile SET actor_identity_id = user_id WHERE actor_identity_id = NONE;
   REMOVE FIELD user_id ON TABLE user_profile;
   REMOVE INDEX user_profile_user_idx ON TABLE user_profile;
   ```

   Re-import `schema.sql` after the `REMOVE INDEX`, so the unique index is rebuilt on the
   new column. Clients reading `user_id` from a profile response must read
   `actor_identity_id` instead; the value is unchanged.

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
