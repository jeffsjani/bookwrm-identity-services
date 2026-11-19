-- =============================================================================
-- HAPI ID V2-E Stage 3 — staging-web client-secret rotation (STAGING ONLY)
-- =============================================================================
-- Rotates the client_secret of the ONE confidential staging client 'staging-web'.
-- 'staging-native' (public, token_endpoint_auth_method=none) is never touched.
--
-- Secret format (verified against the running code, 2026-11-19):
--   * oidc_clients.client_secret stores the PLAINTEXT secret. There is NO
--     hashing at rest. Every comparison site hashes only for constant-time
--     equality, never for storage:
--       - src/oidc/OIDCService.ts  /token: constantTimeStringEqual(stored, presented)
--       - src/identity/H1ClientAuthority.ts authorizeH1Client: timingSafeEqual(sha256(presented), sha256(stored))
--       - src/routes/registration.ts authorize: same sha256/timingSafeEqual pattern
--   * Therefore a direct UPDATE with the new PLAINTEXT value is the exact
--     approved mechanism; writing any hash would break authentication.
--     (Hashed-at-rest client credentials are documented separately as a
--     production hardening requirement; out of scope for this staging rotation.)
--
-- Leak-safety design (why this file is structured in three phases):
--   * PostgreSQL logs the FULL text of any statement that raises an error
--     (log_min_error_statement defaults to 'error'). Therefore the secret must
--     never appear in the text of a statement that can fail. All fail-closed
--     guards run in Phase 1 with NO secret present; the Phase 3 mutation block
--     references the secret only via current_setting(), so its statement text
--     never contains the secret either.
--   * The secret enters the session via psql's \getenv (psql 15+ required):
--     environment variable -> psql variable -> one session-local GUC. It is
--     never placed on a command line (argv/process list), never written to any
--     file, and never echoed. Session-local GUCs are not visible to other
--     database sessions.
--   * Phase 1 fails closed if server statement/duration logging or
--     pg_stat_statements utility tracking could capture the one SET statement
--     that carries the secret.
--
-- Operator procedure (run this committed file directly — no private copy):
--   1. Verify the connection target is the Railway 'charismatic-charm' staging
--      PostgreSQL: compare the psql host/port against the Railway dashboard,
--      then run:  SELECT current_database();
--      The in-script guards below additionally fail closed on any database
--      containing non-staging OIDC clients or the BOOKWRM application.
--   2. Generate and export the new secret WITHOUT echoing it (the generation
--      command may appear in shell history; the VALUE never does):
--        export NEW_STAGING_WEB_SECRET="$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-48)"
--      Store it in the operator secret manager BEFORE running the rotation,
--      alongside the OLD secret until rollback can no longer be needed.
--   3. Run (psql 15+; requires \getenv):
--        psql "$STAGING_DATABASE_URL" -f scripts/rotate-staging-web-secret.sql
--      Then clear the variable from the shell:  unset NEW_STAGING_WEB_SECRET
--   4. If NEW_STAGING_WEB_SECRET is unset, the :'new_secret' reference below
--      stays unexpanded, the SET fails to parse, and ON_ERROR_STOP aborts the
--      run before any change (fail closed, secret-free error).
--   5. Repeat-safe: re-running with the same secret is a verified no-op
--      (besides updated_at); re-running with a new secret rotates again.
--
-- Rollback: run this same script again with NEW_STAGING_WEB_SECRET set to the
-- PREVIOUS value from the operator secret manager. Nothing else changes, so no
-- other rollback action exists or is needed.
--
-- Post-rotation verification (no secret disclosure): the NOTICE output prints
-- only length + an md5 fingerprint prefix. Compare locally with:
--   printf %s "$NEW_STAGING_WEB_SECRET" | md5sum | cut -c1-8
-- =============================================================================

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Phase 1 — fail-closed guards. This block contains NO secret, so a RAISE here
-- can never write secret material to server logs.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
	v_foreign TEXT;
	v_web     oidc_clients%ROWTYPE;
	v_native  oidc_clients%ROWTYPE;
BEGIN
	-- Log-capture guards: any of these would persist the Phase 2 SET statement
	-- (the only statement whose text carries the secret) into server logs.
	IF current_setting('log_statement') IN ('all', 'mod') THEN
		RAISE EXCEPTION 'Refusing to rotate: log_statement=% would write the secret to server logs', current_setting('log_statement');
	END IF;
	IF current_setting('log_min_duration_statement') <> '-1' THEN
		RAISE EXCEPTION 'Refusing to rotate: log_min_duration_statement=% could write the secret to server logs', current_setting('log_min_duration_statement');
	END IF;
	IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')
		AND COALESCE(current_setting('pg_stat_statements.track_utility', true), 'on') = 'on' THEN
		RAISE EXCEPTION 'Refusing to rotate: pg_stat_statements.track_utility=on would retain the secret in statement statistics';
	END IF;

	-- Staging-database identity guards (never trust client names alone):
	-- a production registry always contains clients beyond the staging pair
	-- and the BOOKWRM application; all checks fail closed.
	SELECT client_id INTO v_foreign
	FROM oidc_clients
	WHERE client_id NOT IN ('staging-web', 'staging-native')
	LIMIT 1;
	IF v_foreign IS NOT NULL THEN
		RAISE EXCEPTION 'Refusing to rotate: non-staging OIDC client "%" exists in database "%" — this is not the staging database', v_foreign, current_database();
	END IF;
	IF EXISTS (SELECT 1 FROM applications WHERE application_key = 'BOOKWRM') THEN
		RAISE EXCEPTION 'Refusing to rotate: BOOKWRM application present in database "%" — this is not the staging database', current_database();
	END IF;
	IF NOT EXISTS (SELECT 1 FROM tenants WHERE slug = 'hapi-staging' AND status = 'active') THEN
		RAISE EXCEPTION 'Refusing to rotate: active tenant hapi-staging not found in database "%"', current_database();
	END IF;

	-- Target must exist and match the certified Stage 2 staging-web shape.
	SELECT * INTO v_web FROM oidc_clients WHERE client_id = 'staging-web';
	IF v_web.id IS NULL THEN
		RAISE EXCEPTION 'Refusing to rotate: client staging-web not found';
	END IF;
	IF v_web.token_endpoint_auth_method <> 'client_secret_basic'
		OR NOT v_web.require_pkce
		OR v_web.status <> 'active'
		OR v_web.redirect_uris <> ARRAY['https://staging-app.hapiinc.com/callback']
		OR v_web.grant_types <> ARRAY['authorization_code'] THEN
		RAISE EXCEPTION 'Refusing to rotate: staging-web does not match the expected staging configuration — resolve manually (fail closed)';
	END IF;

	SELECT * INTO v_native FROM oidc_clients WHERE client_id = 'staging-native';
	IF v_native.id IS NULL OR v_native.token_endpoint_auth_method <> 'none' THEN
		RAISE EXCEPTION 'Refusing to rotate: staging-native missing or not a public client — registry shape unexpected';
	END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Phase 2 — move the secret: environment -> psql variable -> session GUC.
-- This SET is the ONLY statement whose text contains the secret; Phase 1
-- verified that no server logging can capture it, a literal-string SET cannot
-- raise a server error, and session GUCs are invisible to other sessions.
-- If NEW_STAGING_WEB_SECRET is unset, :'new_secret' stays literal, the SET is
-- a syntax error without any secret, and ON_ERROR_STOP aborts (fail closed).
-- ---------------------------------------------------------------------------
\getenv new_secret NEW_STAGING_WEB_SECRET
SET "hapi.new_staging_web_secret" = :'new_secret';
\unset new_secret

-- ---------------------------------------------------------------------------
-- Phase 3 — the rotation. This block contains NO secret in its statement text
-- (current_setting() only), so any RAISE here is also secret-free in logs.
-- DO runs in its own transaction: a RAISE rolls back the whole mutation.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
	v_secret       TEXT := current_setting('hapi.new_staging_web_secret', true);
	v_web          oidc_clients%ROWTYPE;
	v_native       oidc_clients%ROWTYPE;
	v_native_after oidc_clients%ROWTYPE;
	v_count        INTEGER;
	v_unchanged    BOOLEAN;
BEGIN
	-- Secret guard: must be a strong generated value. Deliberately never echoes
	-- the value or the GUC content in any message.
	IF v_secret IS NULL OR length(v_secret) < 32 OR v_secret LIKE '\_\_%' ESCAPE '\' THEN
		RAISE EXCEPTION 'Refusing to rotate: NEW_STAGING_WEB_SECRET missing or not a generated value of at least 32 characters';
	END IF;

	-- Re-acquire the target under lock (Phase 1 ran in a separate transaction).
	SELECT * INTO v_web FROM oidc_clients WHERE client_id = 'staging-web' FOR UPDATE;
	IF v_web.id IS NULL
		OR v_web.token_endpoint_auth_method <> 'client_secret_basic'
		OR NOT v_web.require_pkce
		OR v_web.status <> 'active'
		OR v_web.redirect_uris <> ARRAY['https://staging-app.hapiinc.com/callback']
		OR v_web.grant_types <> ARRAY['authorization_code'] THEN
		RAISE EXCEPTION 'Rotation aborted: staging-web changed between guard and rotation — fail closed';
	END IF;

	-- Snapshot staging-native to prove preservation.
	SELECT * INTO v_native FROM oidc_clients WHERE client_id = 'staging-native';
	IF v_native.id IS NULL OR v_native.token_endpoint_auth_method <> 'none' THEN
		RAISE EXCEPTION 'Rotation aborted: staging-native missing or not a public client — fail closed';
	END IF;

	v_unchanged := v_web.client_secret = v_secret;

	-- The rotation: plaintext value, exactly one row, keyed by unique client_id.
	UPDATE oidc_clients
	SET client_secret = v_secret, updated_at = now()
	WHERE client_id = 'staging-web';
	GET DIAGNOSTICS v_count = ROW_COUNT;
	IF v_count <> 1 THEN
		RAISE EXCEPTION 'Rotation aborted: expected exactly 1 row updated, got % — rolling back', v_count;
	END IF;

	-- staging-native must be byte-identical after the update.
	SELECT * INTO v_native_after FROM oidc_clients WHERE client_id = 'staging-native';
	IF v_native_after.client_secret IS DISTINCT FROM v_native.client_secret
		OR v_native_after.updated_at IS DISTINCT FROM v_native.updated_at
		OR v_native_after.token_endpoint_auth_method IS DISTINCT FROM v_native.token_endpoint_auth_method
		OR v_native_after.status IS DISTINCT FROM v_native.status THEN
		RAISE EXCEPTION 'Rotation aborted: staging-native changed — rolling back';
	END IF;

	RAISE NOTICE 'staging-web secret % in database %: length=%, fingerprint(md5-8)=%',
		CASE WHEN v_unchanged THEN 'unchanged (idempotent re-run)' ELSE 'rotated' END,
		current_database(), length(v_secret), left(md5(v_secret), 8);
	RAISE NOTICE 'staging-native untouched: updated_at=%', v_native_after.updated_at;
END
$$;

-- Clear the secret from the session before disconnecting.
RESET "hapi.new_staging_web_secret";
