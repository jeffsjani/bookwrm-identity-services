# HAPI ID V2-E Stage 3 — `staging-web` Client-Secret Rotation Runbook (Railway private network)

**Status: PREPARED — NOT YET EXECUTED.** This runbook is the operator procedure for blocker **B3**
(secure provisioning of the `staging-web` secret) ahead of the Stage 3 live email/OIDC
certification. Nothing in this document has been run against Railway or the staging database.

- Repository: `jeffsjani/bookwrm-identity-services`
- Rotation script (reviewed, unmodified): [`scripts/rotate-staging-web-secret.sql`](../scripts/rotate-staging-web-secret.sql)
- Reviewed/pinned commit: `0dc1cdb9fad7aab9b12a22c1f07af79994c8879a`
- Script SHA-256 at that commit:
  `ed2fa23a8ac00b703a3f9c8bec2c4af58293a91d5e4b34a165a1fcba7e3cf708`
- Railway staging project: `charismatic-charm` (issuer `https://id-staging.hapiinc.com`)
- Verification basis: D1 fail-closed matrix 6/6 on PostgreSQL 16.16
  ([Stage 3 build report §2.2](HAPI-ID-V2E-Stage3-Final-Activation-Preparation-Build-Report.md))

---

## 0. Ground rules (binding)

1. **Use the reviewed script exactly as committed.** Never edit its guards, its phase ordering, or
   any other line. The Phase 1 fail-closed guards (log-capture checks, foreign-client check,
   BOOKWRM-application check, `hapi-staging` tenant check, client-shape checks) run **before**
   `\getenv` ever reads the secret, so the staging database is confirmed before the secret is
   accessed. If any guard trips, **stop and report** — do not weaken a guard to proceed.
2. **Private network only.** The job connects via the Railway private domain
   (`*.railway.internal`). The public TCP proxy (`DATABASE_PUBLIC_URL`) is prohibited.
3. **The new secret must never appear in:** Git (any branch, any file), agent/Copilot chat,
   command-line arguments (argv / process lists / shell history), build or deploy or database
   logs, or **any persistent Railway variable — sealed variables included** (sealed values are
   write-only in the dashboard but are still retained server-side in Railway's variable store).
   The only durable copy lives in the operator secret manager.
4. **Scope:** the script mutates exactly one row — `oidc_clients.client_id = 'staging-web'` — in
   the verified staging database, asserts exactly 1 row updated, and asserts `staging-native` is
   byte-identical afterwards (rollback on any drift). `staging-native` is a public client
   (`token_endpoint_auth_method = none`) and is never touched.
5. **No rollback to the old value exists.** The original `staging-web` secret is **unavailable**
   (confirmed by the operator). Rollback therefore means **rotating again to a fresh secret**
   with this same procedure — never restoring the old value. Consequently, keep the Stage 3 test
   configuration pointed at the secret-manager entry, which is always current.
6. Out of scope / must not change: HAPI backend deployment or revision, Railway variables on
   existing services, HAPI email authentication, Universal Login, Apple, Google, persistent
   sessions, refresh grants.

## 0.1 Residual exposure statement (required disclosure)

Secret injection through SQL — even with this script's logging guards — has **residual exposure
to privileged database administrators and monitoring systems**:

- `oidc_clients.client_secret` is stored as **plaintext at rest** (verified against the running
  code; see the script header). Any role that can read the table — superusers, the Railway
  platform operators who administer the managed PostgreSQL instance, or anyone with a future
  dump/backup — can read the current secret at any time after rotation.
- While the Phase 2 `SET` executes, its statement text is momentarily visible to **superusers**
  via `pg_stat_activity`, and the new value subsequently traverses the **WAL stream,
  replication, point-in-time-recovery archives, and backups** of the staging instance.
- The guards eliminate the *persistent server-log* capture paths (`log_statement`,
  `log_min_duration_statement`, `pg_stat_statements.track_utility`) but cannot defend against a
  platform-level observer of the managed database.

This residual risk is **accepted for staging** because the database is dedicated, synthetic-only,
and isolated (Stage 1/2 certifications). Hashed-at-rest client credentials remain a documented
**production** hardening requirement and are out of scope here.

## 0.2 Secret-injection mechanism (why `railway ssh`, not dashboard variables)

The Railway dashboard cannot inject an ephemeral secret: every dashboard variable (sealed or not)
persists in Railway's variable store until deleted, violating ground rule 3. The approved
mechanism is therefore:

> Dashboard creates a **secret-free** temporary job → operator opens an **interactive
> `railway ssh` session** into it → the secret is pasted at a silent `read -rs` prompt →
> exists only as a shell environment variable in that session → consumed by psql `\getenv` into
> a session-local GUC → `RESET` by the script → `unset` → session ends → container deleted.

Verified tooling (2026-11-20): Railway CLI **v5.75.0** (latest release, 2026-11-17);
`railway ssh` is a stable top-level command (`railway ssh [OPTIONS] [COMMAND...]`) with
`-p/--project`, `-s/--service`, `-e/--environment` flags, documented at
<https://docs.railway.com/cli/ssh>. Requirements: an SSH key registered with Railway (the CLI
prompts to register a local key on first `railway ssh`), and the target service must have a
**running deployment** (which is why the job idles on `sleep`). VS Code Remote-SSH is not
supported; use the CLI directly.

**Stop condition:** if `railway ssh` is unavailable to the operator (CLI/permissions), **stop**.
Do not fall back to a Railway variable of any kind; report back for an alternative design.

---

## 1. Phase 0 — Generate and retain the secret (operator workstation)

```bash
export NEW_STAGING_WEB_SECRET="$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-48)"
```

- Command substitution keeps the value out of shell history; never echo it.
- **Immediately store it in the operator secret manager** (before any rotation step), preferably
  via the manager's CLI reading from the environment or stdin so the value is never displayed.
  This stored copy is what the Stage 3 Phase D harness will use as `STAGING_CLIENT_SECRET`.
- Then `unset NEW_STAGING_WEB_SECRET` locally. From here on, retrieve the value only from the
  secret manager (paste targets below are silent `read -rs` prompts).

## 2. Phase 1 — Create the temporary job (Railway dashboard, project `charismatic-charm`)

1. Open project **charismatic-charm**; confirm the dedicated staging **PostgreSQL service**
   (the one backing `id-staging.hapiinc.com`) is present in the target environment.
2. **+ New → Docker Image** → image **`postgres:16`** → name **`tmp-rotate-staging-web`**.
   Do not deploy yet. The image choice is deliberate:
   - ships **psql 16.x**, satisfying the script's `\getenv` requirement (psql ≥ 15) and matching
     the PostgreSQL 16 staging server (fail-closed matrix verified on 16.16);
   - Debian-based, so `bash`, `sha256sum`, `md5sum` are present and `curl` is installable,
     allowing it to fetch and execute the pinned script;
   - fully compatible with interactive `railway ssh` shell access (long-running container).
3. **Settings → Deploy → Custom Start Command** — this **replaces the image's default
   entrypoint** (mandatory: otherwise the job would boot a stray PostgreSQL server):

   ```
   bash -c 'apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null && curl -fsSL https://raw.githubusercontent.com/jeffsjani/bookwrm-identity-services/0dc1cdb9fad7aab9b12a22c1f07af79994c8879a/scripts/rotate-staging-web-secret.sql -o /tmp/rotate-staging-web-secret.sql && echo "ed2fa23a8ac00b703a3f9c8bec2c4af58293a91d5e4b34a165a1fcba7e3cf708  /tmp/rotate-staging-web-secret.sql" | sha256sum -c - && echo JOB-READY && sleep 7200'
   ```

   - Fetches the script **pinned to the reviewed commit** (the repository is public; no token
     needed) and **enforces the SHA-256** — a mismatch fails startup, and with the restart
     policy below the job simply stops (fail closed).
   - Idles for a bounded 2-hour window; contains no secret; deploy logs show only `JOB-READY`.
4. **Settings → Deploy → Restart Policy: Never.**
5. **Variables** → add exactly **one** variable, as a reference (use the autocomplete name of
   the staging Postgres service):

   ```
   DATABASE_URL = ${{Postgres.DATABASE_URL}}
   ```

   This resolves to the **private** URL (`…@<service>.railway.internal:5432/…`). Do **not**
   reference `DATABASE_PUBLIC_URL`. Add no other variables — the job carries no secret.
6. **Settings → Networking**: confirm the job has **no public domain and no TCP proxy**
   (none are created by default for an image service; remove any if present).
7. Deploy and wait for **`JOB-READY`** in the deploy logs (proves fetch + hash verification).

## 3. Phase 2 — Execute over the private network (`railway ssh`)

From the operator workstation:

```bash
railway login                                   # if not already authenticated
railway link                                    # select charismatic-charm + its environment
railway ssh --service tmp-rotate-staging-web    # interactive shell in the job container
```

(`railway ssh` prompts to register an SSH key on first use. Because the job intentionally has no
public domain, if you invoke plain `ssh` instead of the CLI you must use the **service instance
ID** as the username — dashboard command palette → *Copy Service Instance ID* →
`ssh <service-instance-id>@ssh.railway.com`. The dashboard's right-click **Copy SSH Command** on
the service yields the equivalent ready-made command.)

Inside the SSH session, in order:

```bash
# 1. Private-network + dedicated-service confirmation (never prints credentials)
case "$DATABASE_URL" in *".railway.internal"*) echo PRIVATE-OK ;; *) echo "ABORT: NOT PRIVATE" ;; esac

# 2. Version compatibility: psql 16.x (>= 15 for \getenv) against server 16.x
psql --version
psql "$DATABASE_URL" -tAc "SELECT current_database() || ' | server ' || current_setting('server_version');"

# 3. Pre-rotation snapshot (no secret columns) — record staging-native's updated_at
psql "$DATABASE_URL" -c "SELECT client_id, token_endpoint_auth_method, status, updated_at FROM oidc_clients ORDER BY client_id;"

# 4. Re-verify script integrity in-session (must match the pinned hash exactly)
sha256sum /tmp/rotate-staging-web-secret.sql
#   ed2fa23a8ac00b703a3f9c8bec2c4af58293a91d5e4b34a165a1fcba7e3cf708

# 5. Inject the secret: paste from the secret manager at the silent prompt
#    (no echo, no argv, no file, no Railway variable)
IFS= read -rs NEW_STAGING_WEB_SECRET && export NEW_STAGING_WEB_SECRET
echo "length=${#NEW_STAGING_WEB_SECRET}"        # expect 48 — length only, never the value

# 6. Run the reviewed script, unmodified
psql "$DATABASE_URL" -f /tmp/rotate-staging-web-secret.sql

# 7. Compare the script's NOTICE fingerprint with the locally computed md5-8
printf %s "$NEW_STAGING_WEB_SECRET" | md5sum | cut -c1-8

# 8. Post-rotation snapshot — staging-web.updated_at advanced;
#    staging-native row identical to step 3 (same updated_at)
psql "$DATABASE_URL" -c "SELECT client_id, token_endpoint_auth_method, status, updated_at FROM oidc_clients ORDER BY client_id;"

# 9. Scrub and leave
unset NEW_STAGING_WEB_SECRET
exit
```

**Abort conditions** (all fail closed; the database needs no cleanup): step 1 not `PRIVATE-OK`;
step 2 unexpected database or version; step 4 hash mismatch; any script guard exception
(server-logging guards, foreign OIDC client present, BOOKWRM application present, `hapi-staging`
tenant missing, `staging-web`/`staging-native` shape unexpected, secret missing or < 32 chars).
On any abort: `unset NEW_STAGING_WEB_SECRET`, exit, report. Re-running later with a fresh secret
is safe (the script is verified idempotent/repeat-safe).

## 4. Phase 3 — Post-rotation authentication checks (operator workstation, HTTPS only)

These mirror the certified `secret.accepted` / `secret.rejected` probes of
[`scripts/stage3-email-auth-test.mjs`](../scripts/stage3-email-auth-test.mjs) without the
Phase-D-gated OTP flow (no email is sent; no identity or OIDC state is created — audit rows
only). They talk to the public staging issuer over TLS, never to the database.

```bash
IFS= read -rs STAGING_CLIENT_SECRET && export STAGING_CLIENT_SECRET   # paste from secret manager
node --input-type=module -e '
import crypto from "node:crypto";
const secret = process.env.STAGING_CLIENT_SECRET;
if (!secret || secret.length < 32) { console.error("secret missing (env only, never argv)"); process.exit(1); }
const url = "https://id-staging.hapiinc.com/v1/registration/complete";
const basic = s => "Basic " + Buffer.from(`staging-web:${encodeURIComponent(s)}`).toString("base64");
const probe = async auth => (await fetch(url, { method: "POST",
  headers: { authorization: auth, "content-type": "application/json" },
  body: JSON.stringify({ verificationId: crypto.randomUUID() }) })).status;
const good = await probe(basic(secret));
const bad  = await probe(basic(crypto.randomBytes(24).toString("base64url")));
console.log(`new secret   -> HTTP ${good} (expected 400: client authenticated, evidence invalid)`);
console.log(`wrong secret -> HTTP ${bad} (expected 401: rejected)`);
process.exit(good === 400 && bad === 401 ? 0 : 1);'
unset STAGING_CLIENT_SECRET
```

Success criteria:

| Check | Expected | Meaning |
|---|---|---|
| New secret + random evidence | **HTTP 400** | Client authentication **succeeded**; only the synthetic evidence was rejected |
| Incorrect secret | **HTTP 401** | Client authentication **rejected** |
| `staging-native` | Phase 2 step 8 snapshot identical to step 3 | Untouched (also asserted in-transaction by the script, with rollback on drift) |

If either probe returns an unexpected status, do **not** retry blindly: re-run Phase 2 with a
fresh secret (rotation-as-rollback, ground rule 5) and re-verify.

## 5. Phase 4 — Cleanup (only after Phase 3 passes)

1. Dashboard → `tmp-rotate-staging-web` → **Settings → Delete Service**. This destroys the
   container, its `DATABASE_URL` reference variable, and the fetched script copy. (Even if
   forgotten, `sleep 7200` + Restart Policy *Never* bounds the job's lifetime.)
2. Confirm the project canvas shows only the original services; the staging PostgreSQL service
   and the deployed HAPI backend revision are unchanged.
3. The new secret now exists **only** in the operator secret manager, ready to be supplied as
   `STAGING_CLIENT_SECRET` (environment-only) to the Stage 3 Phase D harness.

---

*Prepared 2026-11-20. Execution requires the operator to follow this runbook verbatim; any
deviation, guard failure, or tooling gap is a stop-and-report condition.*
