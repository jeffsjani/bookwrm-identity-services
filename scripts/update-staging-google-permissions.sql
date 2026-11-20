-- HAPI ID V2-E Stage 4B — staging HAPI_STAGING application permission update
-- STAGING ONLY. Requires hapi.staging_issuer to equal the exact staging issuer.
-- Re-running is idempotent and changes no identities or OAuth clients.

DO $$
DECLARE
	v_issuer TEXT := COALESCE(current_setting('hapi.staging_issuer', true), '');
	v_tenant_id UUID;
	v_app applications%ROWTYPE;
	v_web oidc_clients%ROWTYPE;
	v_native oidc_clients%ROWTYPE;
	v_foreign TEXT;
	v_expected_methods TEXT[] := ARRAY['HAPI_EMAIL','EXTERNAL_OIDC'];
BEGIN
	IF v_issuer <> 'https://id-staging.hapiinc.com' THEN
		RAISE EXCEPTION 'Staging permission update refused: issuer marker is %, expected https://id-staging.hapiinc.com', v_issuer;
	END IF;

	SELECT client_id INTO v_foreign
	FROM oidc_clients
	WHERE client_id NOT IN ('staging-web', 'staging-native')
	LIMIT 1;
	IF v_foreign IS NOT NULL THEN
		RAISE EXCEPTION 'Staging permission update refused: unexpected OIDC client %', v_foreign;
	END IF;

	SELECT t.id INTO v_tenant_id
	FROM tenants t
	WHERE t.slug='hapi-staging' AND t.status='active';
	IF v_tenant_id IS NULL THEN
		RAISE EXCEPTION 'Staging permission update refused: active hapi-staging tenant not found';
	END IF;

	SELECT * INTO v_app
	FROM applications
	WHERE application_key='HAPI_STAGING' AND tenant_id=v_tenant_id;
	IF v_app.id IS NULL THEN
		RAISE EXCEPTION 'Staging permission update refused: HAPI_STAGING application not found';
	END IF;
	IF v_app.slug <> 'hapi-staging-app' OR v_app.status <> 'active' OR v_app.face_setup_enabled THEN
		RAISE EXCEPTION 'Staging permission update refused: unexpected HAPI_STAGING application shape';
	END IF;
	IF v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL']
		AND v_app.allowed_authentication_methods <> v_expected_methods THEN
		RAISE EXCEPTION 'Staging permission update refused: unexpected authentication methods %', v_app.allowed_authentication_methods;
	END IF;

	SELECT * INTO v_web FROM oidc_clients
	WHERE client_id='staging-web' AND application_id=v_app.id;
	IF v_web.id IS NULL
		OR v_web.status <> 'active'
		OR v_web.token_endpoint_auth_method <> 'client_secret_basic'
		OR NOT v_web.require_pkce
		OR v_web.grant_types <> ARRAY['authorization_code'] THEN
		RAISE EXCEPTION 'Staging permission update refused: staging-web configuration changed';
	END IF;

	SELECT * INTO v_native FROM oidc_clients
	WHERE client_id='staging-native' AND application_id=v_app.id;
	IF v_native.id IS NULL
		OR v_native.status <> 'active'
		OR v_native.token_endpoint_auth_method <> 'none'
		OR NOT v_native.require_pkce
		OR v_native.grant_types <> ARRAY['authorization_code'] THEN
		RAISE EXCEPTION 'Staging permission update refused: staging-native configuration changed';
	END IF;

	UPDATE applications
	SET allowed_authentication_methods=v_expected_methods, updated_at=now()
	WHERE id=v_app.id;

	SELECT * INTO v_app FROM applications WHERE id=v_app.id;
	IF v_app.allowed_authentication_methods <> v_expected_methods THEN
		RAISE EXCEPTION 'Staging permission update failed to preserve exact authentication methods';
	END IF;

	RAISE NOTICE 'Staging HAPI_STAGING methods verified: HAPI_EMAIL, EXTERNAL_OIDC';
END
$$;
