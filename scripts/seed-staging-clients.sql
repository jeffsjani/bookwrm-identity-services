-- =============================================================================
-- HAPI ID V2-E Stage 2 — staging synthetic OAuth client seed (STAGING ONLY)
-- =============================================================================
-- Seeds tenant 'hapi-staging' -> application 'hapi-staging-app'
-- (HAPI_EMAIL + EXTERNAL_OIDC for Google/Apple Universal Login)
-- -> clients 'staging-web' (confidential, client_secret_basic, PKCE S256) and
-- 'staging-native' (public, token_endpoint_auth_method=none, PKCE S256).
--
-- Properties (Stage 2 corrections):
--   * Natural-key resolution: rows are found by slug/application_key/client_id,
--     never by assumed UUIDs. New rows get gen_random_uuid().
--   * Relationship + configuration verification: any existing row whose parent,
--     authentication methods, redirect URIs, grant/auth configuration or status
--     differs from the expected staging shape RAISES and aborts (fail closed).
--   * Client secrets are NEVER updated; a conflicting client never silently
--     "succeeds".
--   * Staging-only guard: aborts if the database contains any OIDC client other
--     than the two staging clients (a production registry always contains the
--     Bookwrm client, so running this against production fails closed).
--   * Secret-placeholder guard: aborts unless the secret was replaced with a
--     generated value of at least 32 characters.
--   * Single DO block: atomic; a raise rolls everything back. Re-running after
--     a successful seed is a verified no-op.
--
-- Usage: replace __STAGING_WEB_SECRET__ with a freshly generated secret
-- (e.g. `openssl rand -base64 32`) and run against the STAGING PostgreSQL only.
-- Never commit or log the replaced value.
-- =============================================================================

DO $$
DECLARE
	v_secret        TEXT  := '__STAGING_WEB_SECRET__';
	v_tenant_id     UUID;
	v_app           applications%ROWTYPE;
	v_client        oidc_clients%ROWTYPE;
	v_foreign       TEXT;
BEGIN
	-- Staging-only guard: no OIDC client other than the staging pair may exist.
	SELECT client_id INTO v_foreign
	FROM oidc_clients
	WHERE client_id NOT IN ('staging-web', 'staging-native')
	LIMIT 1;
	IF v_foreign IS NOT NULL THEN
		RAISE EXCEPTION 'Refusing to seed: non-staging OIDC client "%" exists — this is not the staging database', v_foreign;
	END IF;

	-- Secret guard: the placeholder must have been replaced with a strong value.
	IF v_secret LIKE '\_\_%' ESCAPE '\' OR length(v_secret) < 32 THEN
		RAISE EXCEPTION 'Refusing to seed: replace __STAGING_WEB_SECRET__ with a generated secret of at least 32 characters';
	END IF;

	-- Tenant by natural key.
	SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'hapi-staging';
	IF v_tenant_id IS NULL THEN
		INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
		VALUES (gen_random_uuid(), 'HAPI Staging', 'hapi-staging', 'active', now(), now())
		RETURNING id INTO v_tenant_id;
	ELSE
		IF (SELECT status FROM tenants WHERE id = v_tenant_id) <> 'active' THEN
			RAISE EXCEPTION 'Tenant hapi-staging exists but is not active — resolve manually';
		END IF;
	END IF;

	-- Application by natural keys; verify parent tenant and exact method set.
	SELECT * INTO v_app FROM applications WHERE application_key = 'HAPI_STAGING';
	IF v_app.id IS NULL THEN
		SELECT * INTO v_app FROM applications WHERE tenant_id = v_tenant_id AND slug = 'hapi-staging-app';
	END IF;
	IF v_app.id IS NULL THEN
		INSERT INTO applications (id, tenant_id, name, slug, status, created_at, updated_at,
			application_key, allowed_authentication_methods, allowed_identity_providers,
			face_setup_enabled, presentation)
		VALUES (gen_random_uuid(), v_tenant_id, 'HAPI Staging App', 'hapi-staging-app', 'active', now(), now(),
			'HAPI_STAGING', ARRAY['HAPI_EMAIL','EXTERNAL_OIDC'], ARRAY[]::TEXT[], false, '{}'::jsonb)
		RETURNING * INTO v_app;
	ELSE
		IF v_app.tenant_id <> v_tenant_id THEN
			RAISE EXCEPTION 'Application % belongs to tenant %, expected hapi-staging tenant % — refusing', v_app.slug, v_app.tenant_id, v_tenant_id;
		END IF;
		IF v_app.slug <> 'hapi-staging-app' OR v_app.application_key <> 'HAPI_STAGING' THEN
			RAISE EXCEPTION 'Application natural keys conflict (slug=%, application_key=%) — refusing', v_app.slug, v_app.application_key;
		END IF;
		IF v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL','EXTERNAL_OIDC']
			AND v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL'] THEN
			RAISE EXCEPTION 'Application hapi-staging-app allows methods % — expected exactly {HAPI_EMAIL} or {HAPI_EMAIL,EXTERNAL_OIDC}; refusing', v_app.allowed_authentication_methods;
		END IF;
		IF v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL','EXTERNAL_OIDC'] THEN
			UPDATE applications
			SET allowed_authentication_methods = ARRAY['HAPI_EMAIL','EXTERNAL_OIDC'], updated_at = now()
			WHERE id = v_app.id;
			SELECT * INTO v_app FROM applications WHERE id = v_app.id;
		END IF;
		IF v_app.status <> 'active' OR v_app.face_setup_enabled THEN
			RAISE EXCEPTION 'Application hapi-staging-app has unexpected status/face_setup state — refusing';
		END IF;
	END IF;

	-- staging-web: confidential client, client_secret_basic, PKCE S256 required.
	SELECT * INTO v_client FROM oidc_clients WHERE client_id = 'staging-web';
	IF v_client.id IS NULL THEN
		INSERT INTO oidc_clients (id, application_id, client_id, client_secret, redirect_uris, scopes,
			grant_types, response_types, token_endpoint_auth_method, require_pkce, status, created_at, updated_at)
		VALUES (gen_random_uuid(), v_app.id, 'staging-web', v_secret,
			ARRAY['https://staging-app.hapiinc.com/callback'], ARRAY['openid','profile','email'],
			ARRAY['authorization_code'], ARRAY['code'], 'client_secret_basic', true, 'active', now(), now());
	ELSE
		-- Existing secret is intentionally NOT compared and NEVER overwritten.
		IF v_client.application_id <> v_app.id
			OR v_client.token_endpoint_auth_method <> 'client_secret_basic'
			OR NOT v_client.require_pkce
			OR (v_client.redirect_uris <> ARRAY['https://staging-app.hapiinc.com/callback']
				AND v_client.redirect_uris <> ARRAY['https://staging-app.hapiinc.com/callback', 'https://id-staging.hapiinc.com/staging-console/callback'])
			OR v_client.grant_types <> ARRAY['authorization_code']
			OR v_client.status <> 'active' THEN
			RAISE EXCEPTION 'Existing client staging-web does not match the expected staging configuration — refusing (fail closed)';
		END IF;
	END IF;

	-- staging-native: public client, token_endpoint_auth_method=none, PKCE S256 required.
	SELECT * INTO v_client FROM oidc_clients WHERE client_id = 'staging-native';
	IF v_client.id IS NULL THEN
		INSERT INTO oidc_clients (id, application_id, client_id, client_secret, redirect_uris, scopes,
			grant_types, response_types, token_endpoint_auth_method, require_pkce, status, created_at, updated_at)
		VALUES (gen_random_uuid(), v_app.id, 'staging-native', '',
			ARRAY['com.hapi.staging:/callback'], ARRAY['openid','profile','email'],
			ARRAY['authorization_code'], ARRAY['code'], 'none', true, 'active', now(), now());
	ELSE
		IF v_client.application_id <> v_app.id
			OR v_client.token_endpoint_auth_method <> 'none'
			OR NOT v_client.require_pkce
			OR v_client.redirect_uris <> ARRAY['com.hapi.staging:/callback']
			OR v_client.grant_types <> ARRAY['authorization_code']
			OR v_client.status <> 'active' THEN
			RAISE EXCEPTION 'Existing client staging-native does not match the expected staging configuration — refusing (fail closed)';
		END IF;
	END IF;

	RAISE NOTICE 'Staging client seed verified/applied: tenant=%, application=%', v_tenant_id, v_app.id;
END
$$;
