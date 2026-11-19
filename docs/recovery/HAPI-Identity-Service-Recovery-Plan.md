# HAPI Identity Service Recovery Plan
**Date:** November 16, 2026  
**Status:** AWAITING APPROVAL  
**Priority:** P0  

---

## Overview

This plan restores the HAPI identity backend to production without code rebuild, database recreation, or identity loss.

**Strategy:** Verify Railway deployment environment, restart application service, validate OIDC endpoints.

**Scope:** Restore previous deployment (`2711ab2` or `9ac1dbc`) with existing identity database, signing keys, and OIDC client registration intact.

---

## Phase 1: Pre-Recovery Verification (Read-Only)

### Step 1.1: Confirm Database Continuity

**Action:** Connect to production PostgreSQL and verify data persistence.

**Who:** Database administrator or authorized operations team

**Command sequence:**
```bash
# Connect to Railway PostgreSQL (details from Railway console)
psql $DATABASE_URL

# Verify identity schema is present
SELECT name FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'identity%';

# Verify data exists (count subjects)
SELECT COUNT(*) as subject_count FROM identity_subjects;

# Verify Bookwrm tenant exists
SELECT id, name, slug FROM tenants WHERE slug = 'bookwrm';

# Verify Bookwrm application exists
SELECT id, name FROM applications WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'bookwrm');

# Verify OIDC client is registered for Base44
SELECT client_id, redirect_uris FROM oidc_clients WHERE application_id = (SELECT id FROM applications WHERE slug = 'base44');
```

**Expected results:**
- `identity_subjects` table exists and contains non-zero row count
- Bookwrm tenant exists
- Base44 application exists
- At least one OIDC client exists with valid redirect URIs

**Stop condition:** If any query returns empty or error, **STOP**. Do not proceed without confirming data persistence.

---

### Step 1.2: Verify Railway Configuration

**Action:** Access Railway admin console (requires authorization).

**Who:** Authorized user with Railway write access

**Items to verify:**
1. **Service details:**
   - Project: `fulfilling-spirit`
   - Service: (find service owning `identity.bookwrm.com`)
   - Git connected to: `jeffsjani/bookwrm-identity-services` (main branch)
   - Latest deployment: `2711ab2` or later

2. **Custom domain:**
   - Domain: `identity.bookwrm.com`
   - Status: Active (or verify DNS resolution)
   - SSL certificate: Valid

3. **Service environment variables:**
   - `DATABASE_URL`: Points to production PostgreSQL
   - `JWT_PRIVATE_KEY`: Present and valid PEM format
   - `HAPI_PLATFORM_SERVICE_KEY`: Present
   - `OIDC_BASE44_CLIENT_ID`: Present
   - `OIDC_BASE44_CLIENT_SECRET`: Present
   - `OIDC_BASE44_REDIRECT_URI`: Points to Bookwrm's callback endpoint

4. **Build configuration:**
   - Build command: `npm run build`
   - Start command: `npm start`
   - Runtime: Node.js v18+ (or compatible)

5. **Health check configuration:**
   - Endpoint: `/health/ready` or `/health`
   - Expected response: HTTP 200 `{"status":"alive"}`

6. **Deployment history:**
   - Last successful deployment: Oct 16, 2026
   - Any errors in logs since then?

**Stop conditions:**
- Environment variables are missing or invalid
- Database URL is unavailable
- Signing keys are missing
- Build/start commands are incorrect
- Custom domain is pointing elsewhere

---

### Step 1.3: Review Recent Deployment Logs

**Who:** Operations team

**Action:** Retrieve deployment logs from Railway for the Oct 16 deployment and any attempts since.

**Look for:**
- Application startup errors
- Database connection failures
- Environment variable load errors
- Port binding failures
- Health check failures

**Stop condition:** If logs show data loss, schema failures, or persistent configuration errors, **STOP**.

---

## Phase 2: Minimal Recovery Actions

### Step 2.1: Verify Code Commit

**Action:** Confirm the deployed commit is correct.

**Command:**
```bash
cd /workspaces/bookwrm-identity-services
git log 2711ab2 -1

# Expected output:
# commit 2711ab26f67278bcc722c8a47767b998d26449ac
# Author: jeffsjani <jeffjani@gmail.com>
# Date:   Fri Oct 16 15:33:52 2026 +0000
# Add HAPI multi-client identity foundation
```

**Decision:**
- If this is the deployed commit, proceed to Step 2.2
- If a different release (e.g., `9ac1dbc` from Oct 11) was deployed, verify that commit instead
- If main has advanced beyond the deployed commit, consider whether to redeploy main (safe) or stick with the previous release

---

### Step 2.2: Verify Build Artifacts

**Action:** Confirm the application can build.

**Command:**
```bash
cd /workspaces/bookwrm-identity-services
npm ci
npm run build
```

**Expected output:**
- No TypeScript compilation errors
- `dist/` directory populated with compiled JavaScript
- SQL schema files copied to `dist/identity/schema.sql`, etc.

**Stop condition:** Build fails. Do not proceed.

---

### Step 2.3: Run Health Check Query

**Action:** Simulate startup without actually starting the server, to verify configuration loading.

**Command:**
```bash
cd /workspaces/bookwrm-identity-services

# Verify config loads (requires DATABASE_URL, JWT keys, etc. in environment)
# This is a placeholder; actual test depends on environment availability
npm test -- tests/ConfigurationService.test.ts
```

**Expected:** Configuration loads without errors.

---

### Step 2.4: Restart Railway Service

**Action:** Trigger a manual redeploy or service restart on Railway.

**Who:** Authorized Railway user

**Method A: Redeploy existing commit**
```
Railway Console > Project: fulfilling-spirit > Service: (identity) > Deployments > Redeploy
```

**Method B: Redeploy from main**
```
Railway Console > Project: fulfilling-spirit > Service: (identity) > Git > Trigger Redeploy
```

**Method C: Restart service**
```
Railway Console > Project: fulfilling-spirit > Service: (identity) > Restart
```

**After restart, verify:**
- Deployment status changes from "Inactive" to "Active"
- Logs show successful startup
- `/health` endpoint responds with HTTP 200

---

## Phase 3: Validation

### Step 3.1: Test OIDC Discovery Endpoint

**Command:**
```bash
curl -s https://identity.bookwrm.com/.well-known/openid-configuration | jq .
```

**Expected response:**
```json
{
  "issuer": "https://identity.bookwrm.com",
  "authorization_endpoint": "https://identity.bookwrm.com/authorize",
  "token_endpoint": "https://identity.bookwrm.com/token",
  "userinfo_endpoint": "https://identity.bookwrm.com/userinfo",
  "jwks_uri": "https://identity.bookwrm.com/jwks",
  "discovery_endpoint": "https://identity.bookwrm.com/.well-known/openid-configuration",
  ...
}
```

**Accept:** Any HTTP 200 response with valid OIDC metadata.

**Reject:** 404, 502, 503, or missing required fields.

---

### Step 3.2: Test JWKS Endpoint

**Command:**
```bash
curl -s https://identity.bookwrm.com/jwks | jq .
```

**Expected response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "...",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

**Accept:** HTTP 200 with at least one public key.

---

### Step 3.3: Test Health Endpoints

**Command:**
```bash
curl -s https://identity.bookwrm.com/health | jq .
curl -s https://identity.bookwrm.com/health/live | jq .
curl -s https://identity.bookwrm.com/health/ready | jq .
```

**Expected responses:**
- HTTP 200
- `{"status":"alive"}` or similar

---

### Step 3.4: Test Diagnostics Endpoint

**Command:**
```bash
curl -s https://identity.bookwrm.com/diagnostics/oidc/base44 | jq .
```

**Expected response:**
- HTTP 200
- Status of Bookwrm OIDC client configuration
- Validation results for redirect URIs, client credentials, etc.

**Accept:** Any HTTP 200 response with diagnostic data.

---

### Step 3.5: Test Bookwrm SSO Login

**Who:** Authorized Bookwrm user

**Action:** Navigate to Bookwrm landing page and attempt OIDC login.

**Expected:**
1. Redirect to `https://identity.bookwrm.com/authorize?client_id=...&redirect_uri=...`
2. If H6.11.1 is deployed: Email/Face login chooser page
3. If H6 is deployed: Interactive chooser
4. If H4 disabled: PrivateID Face login directly
5. After login: Redirect back to Bookwrm with authorization code
6. Bookwrm exchanges code for ID and access tokens
7. User is logged in to Bookwrm

**Accept:** Successful login and authenticated session.

**Reject:** 404, 500, SSL errors, blank page, redirect loops.

---

### Step 3.6: Verify Identity Continuity

**Who:** Operations team

**Action:** Confirm existing registered users can still log in.

**Query:**
```sql
-- Count users who should be able to log in
SELECT COUNT(*) FROM identity_subjects 
WHERE status = 'active' AND email_verified = true;
```

**Test:** Log in as a known user (synthetic or existing) and verify their `sub` claim matches the HAPI identity subject UUID.

**Expected:** Sub is stable across sessions (not regenerated).

---

## Phase 4: Post-Recovery Actions

### Step 4.1: Update Documentation

**Action:** Update README, deployment guide, and incident log with recovery details.

**Items:**
- Recovery date and time
- Failure cause (configuration/startup issue)
- Recovery action (restart/redeploy)
- Validation results

---

### Step 4.2: Backup Signing Keys

**Action:** Ensure production signing keys are backed up and documented.

**Who:** Security/operations team

**Items to backup:**
- Current `JWT_PRIVATE_KEY` (encrypted, never in plaintext)
- Rotation policy
- Key recovery procedure

---

### Step 4.3: Set Up Monitoring

**Action:** Ensure ongoing monitoring is in place.

**Recommended alerts:**
- `/health/ready` endpoint returns non-200
- Deployment status is Inactive for >5 minutes
- Error rate spikes on OIDC endpoints
- Database connection failures
- Redis connection failures

---

## Rollback Plan

If recovery does not succeed or causes issues:

### Rollback Step 1: Revert to Previous Deployment
```
Railway Console > Project: fulfilling-spirit > Service: (identity) > Deployments
> Select deployment from Oct 11, 2026 (H6.11.1 Bookwrm zero-choice login)
> Click "Redeploy"
```

### Rollback Step 2: Verify Recovery
```bash
curl -s https://identity.bookwrm.com/health
```

### Rollback Step 3: Notify Users
If Bookwrm SSO was disrupted, notify users that service has been restored and they may need to re-authenticate.

---

## Risks & Mitigation

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Signing keys were lost during configuration reset | **CRITICAL** | Verify keys are present before restart; if missing, contact key recovery system |
| Database was truncated or dropped | **CRITICAL** | Verify data presence in Step 1.1; if data is gone, recover from backup |
| Configuration variables are stale or incorrect | **HIGH** | Audit environment variables in Step 1.2 before restart |
| Restart succeeds but users cannot log in (OIDC flow broken) | **HIGH** | Test with synthetic user first; check Base44 OIDC client config |
| Service starts but health checks fail (temporary issue) | **MEDIUM** | Wait 1–2 minutes; Railway may need time to stabilize connections |
| Existing sessions are invalidated (key rotation) | **MEDIUM** | Accept this as unavoidable if keys were regenerated; users can re-authenticate |

---

## Approval Checklist

Before proceeding with Phase 1 verification:

- [ ] Authorized user has access to Railway admin console
- [ ] Authorized user has access to production PostgreSQL
- [ ] Backup/restore procedures are documented and tested
- [ ] On-call support is available during recovery
- [ ] Bookwrm team is notified of potential brief downtime
- [ ] This plan has been reviewed by security and operations teams

---

## Success Criteria

Recovery is successful when:

1. ✓ `https://identity.bookwrm.com/.well-known/openid-configuration` returns HTTP 200 with valid OIDC metadata
2. ✓ `https://identity.bookwrm.com/jwks` returns HTTP 200 with public signing keys
3. ✓ `https://identity.bookwrm.com/health` returns HTTP 200 `{"status":"alive"}`
4. ✓ Bookwrm users can log in via OIDC without re-registering
5. ✓ Existing identity subjects retain their durable `sub` identifier
6. ✓ Email verification and OTP authentication work (if enabled)
7. ✓ All HAPI endpoints are reachable and responding correctly

---

## Schedule & Effort Estimate

| Phase | Duration | Notes |
|-------|----------|-------|
| Phase 1: Pre-Recovery Verification | 30–60 min | Access to Railway + DB required |
| Phase 2: Minimal Recovery Actions | 15–30 min | Mostly automated |
| Phase 3: Validation | 30–60 min | Includes manual testing |
| Phase 4: Post-Recovery | 15–30 min | Documentation + monitoring |
| **Total** | **90–180 min** | 1.5–3 hours |

**Estimated downtime:** 15–30 minutes (during restart)

---

## End Recovery Plan

**Next step:** Submit for approval from authorized operations and security teams.

**Approval from:** Operations Lead, Security Lead, Bookwrm Platform Owner
