-- STAGING ONLY. Review and execute separately; this script is not run by the service.
-- Set hapi.staging_issuer to the exact staging issuer on the dedicated staging database.
DO $$
DECLARE
	v_tenant_id UUID;
	v_app applications%ROWTYPE;
	v_web oidc_clients%ROWTYPE;
	v_native oidc_clients%ROWTYPE;
BEGIN
	IF COALESCE(current_setting('hapi.staging_issuer', true), '') <> 'https://id-staging.hapiinc.com' THEN
		RAISE EXCEPTION 'Staging passkey update refused: incorrect issuer marker';
	END IF;
	IF EXISTS (SELECT 1 FROM oidc_clients WHERE client_id NOT IN ('staging-web', 'staging-native')) THEN
		RAISE EXCEPTION 'Staging passkey update refused: unexpected OIDC client';
	END IF;
	SELECT id INTO v_tenant_id FROM tenants WHERE slug = 'hapi-staging' AND status = 'active';
	IF v_tenant_id IS NULL THEN RAISE EXCEPTION 'Staging passkey update refused: tenant not found'; END IF;
	SELECT * INTO v_app FROM applications WHERE application_key = 'HAPI_STAGING' AND tenant_id = v_tenant_id FOR UPDATE;
	IF v_app.id IS NULL OR v_app.slug <> 'hapi-staging-app' OR v_app.status <> 'active' OR v_app.face_setup_enabled THEN
		RAISE EXCEPTION 'Staging passkey update refused: unexpected application';
	END IF;
	IF v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL','EXTERNAL_OIDC']
		AND v_app.allowed_authentication_methods <> ARRAY['HAPI_EMAIL','EXTERNAL_OIDC','PASSKEY'] THEN
		RAISE EXCEPTION 'Staging passkey update refused: unexpected authentication methods';
	END IF;
	SELECT * INTO v_web FROM oidc_clients WHERE client_id = 'staging-web' AND application_id = v_app.id FOR UPDATE;
	SELECT * INTO v_native FROM oidc_clients WHERE client_id = 'staging-native' AND application_id = v_app.id FOR UPDATE;
	IF v_web.id IS NULL OR v_web.status <> 'active' OR v_web.token_endpoint_auth_method <> 'client_secret_basic'
		OR NOT v_web.require_pkce OR v_web.grant_types <> ARRAY['authorization_code']
		OR v_native.id IS NULL OR v_native.status <> 'active' OR v_native.token_endpoint_auth_method <> 'none'
		OR NOT v_native.require_pkce OR v_native.grant_types <> ARRAY['authorization_code'] THEN
		RAISE EXCEPTION 'Staging passkey update refused: unexpected clients';
	END IF;
	IF NOT ('PASSKEY' = ANY(v_app.allowed_authentication_methods)) THEN
		UPDATE applications SET allowed_authentication_methods = array_append(allowed_authentication_methods, 'PASSKEY'),
				updated_at = now() WHERE id = v_app.id;
	END IF;
END
$$;
