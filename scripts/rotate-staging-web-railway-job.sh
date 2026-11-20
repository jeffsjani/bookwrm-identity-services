#!/usr/bin/env bash
# =============================================================================
# HAPI ID V2-E Stage 3 — staging-web secret rotation job (Railway, one-time)
# =============================================================================
# Non-interactive wrapper around the reviewed scripts/rotate-staging-web-secret.sql.
# The SQL file — with ALL of its fail-closed staging-only guards — is fetched
# pinned to its certified commit, SHA-256 enforced, and executed UNMODIFIED.
#
# Execution context (full procedure: runbook §6, "Simplified Railway-variable
# procedure"):
#   * Runs as the Custom Start Command payload of a temporary 'postgres:16'
#     service in Railway project 'charismatic-charm' (Restart Policy: Never,
#     no public domain, no TCP proxy).
#   * Expects exactly two Railway variables on the job service, both references
#     (the service configuration itself carries no secret value):
#       DATABASE_URL           = ${{Postgres.DATABASE_URL}}            (private)
#       NEW_STAGING_WEB_SECRET = ${{<backend-service>.STAGING_WEB_CLIENT_SECRET}}
#   * psql \getenv in the reviewed SQL reads NEW_STAGING_WEB_SECRET directly
#     from this process environment — no SSH, no paste, no argv, no file copy.
#
# Output policy: this job prints ONLY statuses, lengths, md5-8 fingerprints and
# non-secret oidc_clients columns. The secret value and DATABASE_URL are never
# echoed, never placed on a command line of any spawned process, and never
# written to disk.
#
# Fail-closed: any error aborts immediately (set -e); the SQL's own guards and
# single-transaction mutation mean the database never needs cleanup. The only
# cleanup is deleting this temporary Railway service after the run.
# =============================================================================
set -euo pipefail
trap 'echo "JOB-FAILED: aborted fail-closed; the database needs no cleanup" >&2' ERR

SQL_COMMIT="0dc1cdb9fad7aab9b12a22c1f07af79994c8879a"
SQL_SHA256="ed2fa23a8ac00b703a3f9c8bec2c4af58293a91d5e4b34a165a1fcba7e3cf708"
SQL_URL="https://raw.githubusercontent.com/jeffsjani/bookwrm-identity-services/${SQL_COMMIT}/scripts/rotate-staging-web-secret.sql"
SNAPSHOT_SQL="SELECT client_id, token_endpoint_auth_method, status, updated_at FROM oidc_clients ORDER BY client_id;"

# --- 0. Preconditions (no secret material in any message) --------------------
case "${DATABASE_URL:-}" in
	*".railway.internal"*) echo "PRIVATE-OK" ;;
	*) echo "ABORT: DATABASE_URL is not a Railway private-network URL" >&2; exit 1 ;;
esac
SECRET="${NEW_STAGING_WEB_SECRET:-}"
if [ "${#SECRET}" -lt 32 ]; then
	echo "ABORT: NEW_STAGING_WEB_SECRET missing or shorter than 32 characters (is the variable reference resolving?)" >&2
	exit 1
fi
echo "secret present: length=${#SECRET}"

# --- 1. Tooling: psql 16 ships in postgres:16; add node for the HTTPS probes -
apt-get update -qq >/dev/null
apt-get install -y -qq nodejs >/dev/null
echo "tooling: $(psql --version) | node $(node --version)"

# --- 2. Fetch the reviewed SQL pinned to its certified commit; enforce hash --
curl -fsSL "$SQL_URL" -o /tmp/rotate-staging-web-secret.sql
echo "${SQL_SHA256}  /tmp/rotate-staging-web-secret.sql" | sha256sum -c -

# --- 3. Pre-rotation snapshot (non-secret columns only) ----------------------
echo "--- pre-rotation oidc_clients snapshot ---"
psql "$DATABASE_URL" -c "$SNAPSHOT_SQL"
NATIVE_BEFORE="$(psql "$DATABASE_URL" -tAc "SELECT status || '|' || token_endpoint_auth_method || '|' || updated_at FROM oidc_clients WHERE client_id = 'staging-native'")"

# --- 4. The rotation: reviewed script, unmodified (guards + single-row UPDATE
#        + in-transaction staging-native byte-identity assertion, rollback on
#        any drift). \getenv reads the secret from this environment. ----------
psql "$DATABASE_URL" -f /tmp/rotate-staging-web-secret.sql
echo "local fingerprint(md5-8)=$(printf %s "$SECRET" | md5sum | cut -c1-8) — must equal the fingerprint in the NOTICE above"

# --- 5. Post-rotation snapshot + independent staging-native preservation check
echo "--- post-rotation oidc_clients snapshot ---"
psql "$DATABASE_URL" -c "$SNAPSHOT_SQL"
NATIVE_AFTER="$(psql "$DATABASE_URL" -tAc "SELECT status || '|' || token_endpoint_auth_method || '|' || updated_at FROM oidc_clients WHERE client_id = 'staging-native'")"
if [ "$NATIVE_BEFORE" != "$NATIVE_AFTER" ]; then
	echo "ABORT: staging-native drifted across the rotation" >&2
	exit 1
fi
echo "staging-native preserved: status/auth-method/updated_at unchanged"

# --- 6. Authentication probes over public TLS (certified 400/401 semantics of
#        scripts/stage3-email-auth-test.mjs: secret.accepted / secret.rejected;
#        no OTP, no identity, no OIDC state — audit rows only). Secret reaches
#        node via the environment, never argv. --------------------------------
cat > /tmp/probe.mjs <<'PROBE_EOF'
import crypto from "node:crypto";
const secret = process.env.NEW_STAGING_WEB_SECRET;
if (!secret || secret.length < 32) { console.error("probe: secret missing from environment"); process.exit(1); }
const url = "https://id-staging.hapiinc.com/v1/registration/complete";
const basic = (s) => "Basic " + Buffer.from(`staging-web:${encodeURIComponent(s)}`).toString("base64");
const probe = async (auth) => (await fetch(url, {
	method: "POST",
	headers: { authorization: auth, "content-type": "application/json" },
	body: JSON.stringify({ verificationId: crypto.randomUUID() })
})).status;
const good = await probe(basic(secret));
const bad = await probe(basic(crypto.randomBytes(24).toString("base64url")));
console.log(`probe: new secret   -> HTTP ${good} (expected 400: client authenticated, evidence invalid)`);
console.log(`probe: wrong secret -> HTTP ${bad} (expected 401: rejected)`);
process.exit(good === 400 && bad === 401 ? 0 : 1);
PROBE_EOF
node /tmp/probe.mjs

echo "ROTATION-AND-VERIFICATION-COMPLETE"
