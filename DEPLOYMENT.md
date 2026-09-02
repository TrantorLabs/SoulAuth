# Deploying SoulAuth

> 中文版本见 [DEPLOYMENT.zh-CN.md](DEPLOYMENT.zh-CN.md)。

How to get SoulAuth running in production.

> **The namespace and database must match everywhere.** This file uses `auth` / `main`
> throughout (the defaults for `DATABASE_NAMESPACE` / `DATABASE_NAME`). If you pick
> different names, **the pair you import the SQL into must be the pair the process
> connects with** — this is the most common way a deployment fails: the schema lands in
> one place, the process connects to another, it starts fine, `/health` returns ok, and
> the first real request 500s. The process now checks this at startup and refuses to
> run, but it can only check what you gave it.

This file keeps the **deployment steps themselves**, because `tests/deployment_walkthrough.sh`
executes them one by one — it has to live in the same repository as the script for CI to
run this document on every push.

Everything else is on the documentation site, in more detail:

| What you want | Where |
|---|---|
| Docker Compose / systemd / reverse proxy / upgrades | [Deployment](https://soulauth.trantorlabs.sg/operate/deployment) |
| What to change before going live | [Production checklist](https://soulauth.trantorlabs.sg/operate/production-checklist) |
| Backups, key rotation, incident response | [Operations and recovery](https://soulauth.trantorlabs.sg/operate/operations-and-recovery) |
| Troubleshooting (13 symptoms) | [Troubleshooting](https://soulauth.trantorlabs.sg/operate/troubleshooting) |
| Wiring it in as an OIDC provider | [Integration path](https://soulauth.trantorlabs.sg/start/integration-path) |
| The permission list | [Administration](https://soulauth.trantorlabs.sg/reference/administration) |

---

## Environment variables

**Four are required** — the process will not start without them:

```env
JWT_SECRET=<at least 32 characters>
APP_URL=https://auth.example.com
SMTP_HOST=smtp.example.com
SMTP_FROM=noreply@example.com
```

`APP_URL` is the public address, not the listen address. It decides three things: the
OIDC `issuer`, the prefix of links in outgoing mail, and whether cookies get `Secure`.
What goes wrong when it's wrong is covered in
[Configuration](https://soulauth.trantorlabs.sg/reference/configuration),
under "`APP_URL` is not the listen address".

#### Also required in production (enforced when `APP_URL` is not loopback)

When the host in `APP_URL` is not `127.0.0.1` / `localhost` / `[::1]`, **`APP_URL` itself
must be https** — plaintext there costs the session cookie its `Secure` flag, sends mail
links unencrypted, and produces an OIDC `issuer` that violates the Discovery spec, which
conforming relying parties reject. Terminate TLS in front of SoulAuth and put the public
https address here.

On top of that, missing any of these three is a **hard startup failure**:

```env
OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem   # or _PEM for the contents
MFA_SECRET_ENCRYPTION_KEY=<openssl rand -base64 32>
AUDIT_INTEGRITY_KEY=<openssl rand -base64 32>
```

Why refuse to start rather than warn: **none of the three consequences shows up at
startup.**

- No signing key → one is generated per process, so **every ID token already issued
  stops verifying the moment you restart**. Across replicas each one signs with its own
  key and they never agree, which shows up as random login failures from day one.
- No MFA key → it's derived from `JWT_SECRET`, so **the day you rotate `JWT_SECRET`
  every stored TOTP secret becomes undecryptable** and every MFA user is locked out.
- No audit integrity key → the hash chain is still written but **no checkpoint is ever
  signed**, and a chain on its own can be recomputed end to end by anyone holding
  database write access. You find out on the day you need the log as evidence.

These are three separate keys on purpose. Rotating one must not invalidate the other
two, and audit integrity is the one that should least of all be broken by a routine
rotation elsewhere.

By the time either surfaces on its own you have an incident. Local development is still
allowed through — otherwise people route around the gate with an environment variable.

#### Database

```env
DATABASE_URL=127.0.0.1:8000        # default http://localhost:8000; https:// switches to TLS
DATABASE_USER=root
DATABASE_PASS=root
DATABASE_NAMESPACE=auth            # default auth
DATABASE_NAME=main                 # default main
DATABASE_CONNECTION_TIMEOUT=30
```

**On encrypting the database link**: an `https://` prefix on `DATABASE_URL` selects the
TLS connector, anything else is plaintext. Pointing at a non-loopback address in
plaintext logs a WARN at startup — what travels over that link is the database password,
password hashes, and session tokens. Inside a trusted private segment that is a
reasonable call; across segments, use https.

> Earlier versions used the plaintext connector whether or not you wrote `https://`
> (the scheme was stripped and discarded), and said nothing about it. If you configured
> `https://` back then, check that the database side really has TLS on.

#### Network and frontend

```env
BIND_ADDR=0.0.0.0:8080             # listen address, default 0.0.0.0:8080
SOULAUTH_INSTANCE_ID=              # this replica's audit chain; required in production
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
TRUST_PROXY_HEADERS=true           # required behind a reverse proxy
LOGIN_PAGE_URL=                    # default {APP_URL}/login
VERIFY_EMAIL_PAGE_URL=             # default {APP_URL}/verify-email
RESET_PASSWORD_PAGE_URL=           # default {APP_URL}/reset-password
```

`CORS_ALLOWED_ORIGINS` falls back to `APP_URL` itself when empty. `*` is rejected at
startup — it would let any site call this service with the user's `Authorization` header.

The three page URLs are where mail links and post-login redirects land. Set them when
your frontend lives somewhere other than `APP_URL`. The reset token is appended to
`RESET_PASSWORD_PAGE_URL` as a path segment (`{page}/{token}`); the verification token
goes on as a query parameter (`{page}?token=...`).

`TRUST_PROXY_HEADERS` **must be on** behind a reverse proxy: without it every request
carries the proxy's IP, so rate limiting and account lockout count all users as one
client — one person gets locked out and everyone goes down with them. And it **must be
off** when there is no proxy: otherwise a client can forge `X-Forwarded-For` and walk
around the rate limiter.

#### Social login (optional — leave it unset and it stays off)

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
OAUTH_REDIRECT_URL=https://auth.example.com/api/auth/callback
```

A deployment that only does email and password **needs none of these**. Unconfigured,
`GET /api/auth/login/google` returns **501 "not enabled in this deployment"** instead of
taking fake credentials to the token endpoint and returning an OAuth error nobody can
read.

Two rules decide what counts as configured:

- **An id without a secret counts as unconfigured.** Half-configured is worse than not
  configured at all, because it looks like it's on.
- **Configure any provider and `OAUTH_REDIRECT_URL` becomes mandatory**, or startup
  fails. Without it the redirect URI is assembled into a broken address and login dies
  at the first hop. It follows the same rule as the endpoint overrides below: an
  absolute https URL, or plaintext http only for an exact loopback host — a remote
  plaintext callback puts the authorization code on the wire in the clear.

Endpoint overrides are optional (the official endpoints are the default):

```env
GOOGLE_OAUTH_BASE_URL=
GITHUB_OAUTH_BASE_URL=https://ghe.example.com    # self-hosted GitHub Enterprise
```

An override replaces the root and keeps that provider's real path shape: Google is
`{base}/o/oauth2/v2/auth` · `/token` · `/oauth2/v2/userinfo`; GitHub is
`{base}/login/oauth/{authorize,access_token}` plus `{base}/api/v3/user[/emails]` — which
is exactly the GitHub Enterprise convention.

**Plaintext http is only accepted for loopback**, and never with a trailing slash;
anything else refuses to start. A remote endpoint over plaintext hands your
`client_secret` and access tokens to everyone on the path.

#### Account lockout

```env
LOCKOUT_MAX_ATTEMPTS=5             # consecutive failures before locking, must be >= 1
LOCKOUT_DURATION_MINUTES=15        # how long the lock lasts, must be >= 1
LOCKOUT_RESET_WINDOW_MINUTES=60    # how long without a failure before the count resets
LOCKOUT_USER_ENABLED=true          # per account
LOCKOUT_IP_ENABLED=true            # per IP
```

Zero is rejected at startup for the first two: locking after zero attempts means everyone
is locked out on their first login, and a zero-minute lock is no lock at all. Neither is
"stricter" — both are a broken service.

**Unlocking by hand** (needs `soulauth:security.write`, granted to admin and
security_manager in the seed data):

```bash
# check
curl "$APP_URL/api/security/lockout?scope=user&identifier=user%40example.com" \
  -H "Authorization: Bearer $TOKEN"
# → {"is_locked":true,"remaining_lockout_seconds":812,…}

# unlock (scope is user or ip; unlocking is idempotent and returns unlocked:false
# when nothing was locked)
curl -X POST "$APP_URL/api/security/unlock" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"user","identifier":"user@example.com"}'
# → {"unlocked":true}
```

The identifier on the user side is the **email address**: the counter goes up on a failed
login, at which point there may be no user record at all. Addresses that don't exist are
counted too — otherwise "did this leave a lockout record" becomes an account enumeration
channel.

Every unlock writes a `lockout_cleared` audit record, including the no-ops.

#### Mail

```env
SMTP_PORT=587                      # default 587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_INSECURE=false                # local testing only
EMAIL_VERIFICATION_ENABLED=false   # when on, registration requires a verified address
```

**A failed send is logged, not propagated.** So with SMTP misconfigured, registration
succeeds, the verification mail never arrives, and nothing outside the log says so. Walk
through a real registration after you go live and confirm the mail lands.

#### Everything else

```env
JWT_EXPIRATION=86400               # session and access token lifetime in seconds, default 1 day
PASSWORD_MIN_LENGTH=12
AUTH_SESSION_CACHE_TTL_SECONDS=5   # 0 = validate the session on every request
PROXY_ENABLED=false                # route outbound OAuth requests through a proxy
PROXY_URL=
```

`AUTH_SESSION_CACHE_TTL_SECONDS` is the **upper bound on revocation lag across
replicas**: a logout, password change, or deactivation clears the cache on the instance
that handled it immediately, and the others trail by at most one TTL. Set it to 0 and
revocation is instant, at the cost of two extra queries per request.


---

## Deployment steps

1. **Start SurrealDB** and confirm it answers:
   ```bash
   surreal start --bind 127.0.0.1:8000 --user root --pass "$DB_PASS" \
     surrealkv:///var/lib/surrealdb/soulauth.db
   curl -f http://127.0.0.1:8000/health && echo " SurrealDB OK"
   ```

2. **Set the environment.** Four required, plus two more in production (see
   "Environment variables" above):
   ```bash
   export DATABASE_URL=127.0.0.1:8000
   export DATABASE_NAMESPACE=auth      # the import in the next step must use this value
   export DATABASE_NAME=main           # and this one
   export DATABASE_USER=root
   export DATABASE_PASS="$DB_PASS"
   export JWT_SECRET=$(openssl rand -hex 32)
   export APP_URL=https://auth.example.com
   export SMTP_HOST=smtp.example.com
   export SMTP_FROM=noreply@example.com
   export OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem
   export MFA_SECRET_ENCRYPTION_KEY=$(openssl rand -base64 32)
   ```

3. **Prepare the database.** This reuses the variables exported above on purpose, so the
   import target and the pair the process connects to cannot drift apart:
   ```bash
   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" schema.sql

   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" initial_data.sql
   ```

   Both files are safe to re-run: every `DEFINE` carries `IF NOT EXISTS` and the seed
   data is all `UPSERT`.

4. **Build**:
   ```bash
   cargo build --release
   ```

5. **Run**:
   ```bash
   ./target/release/soulauth
   ```

6. **Check it came up**:
   ```bash
   curl http://localhost:8080/health
   # → {"status":"ok","uptime_seconds":12}
   ```

7. **Create the first administrator**:

   You never touch the database for this. A fresh instance prints a single-use bootstrap
   token in its startup log (at `WARN`, so it's visible at the default log level), and
   you trade that for the first administrator:

   ```bash
   # ① take the token from the startup log
   #    WARN No administrator found. Bootstrap token for this process: 7f3a…
   #
   #    Across replicas, pin it with SOULAUTH_BOOTSTRAP_TOKEN; set that to an empty
   #    string to close the path entirely.

   # ② create the administrator. The password has to satisfy the policy: at least
   #    12 characters (PASSWORD_MIN_LENGTH) and three of the four classes
   #    upper / lower / digit / symbol
   curl -X POST http://localhost:8080/api/bootstrap/admin \
     -H 'Content-Type: application/json' \
     -d '{"token":"7f3a…","email":"admin@your-domain.com",
          "username":"admin","password":"CorrectHorse42!"}'
   # → {"user_id":"…","email":"admin@your-domain.com","is_admin":true}

   # ③ log in for a session token (the bootstrap response does not contain one)
   curl -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}'

   # ④ confirm the permissions took
   curl http://localhost:8080/api/auth/me -H "Authorization: Bearer <token>"
   # → "is_admin": true
   ```

   The door is single-use: once an administrator exists the endpoint refuses forever, and
   it returns a **byte-identical** response for "wrong token" and "door already closed" —
   so a dead token can't be used to probe whether an instance has been initialised.

   The token belongs to **that process** (the log says `for this process`): restart and
   you get a new one, so go read the new `WARN` line.

## Verifying this document

`tests/deployment_walkthrough.sh` runs steps 1–7 of "Deployment steps" above from an
empty database and asserts it ends with an administrator whose `is_admin` is true:

```bash
cargo build && ./tests/deployment_walkthrough.sh
```

Run it whenever you change the steps here. A misspelled flag, or an ns/db pair that
disagrees between the three places it appears, only shows up when something actually
executes them.
