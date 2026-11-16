# HAPI-to-Bookwrm Integration Architecture Decision
**Date:** November 16, 2026  
**Status:** DESIGN RECOMMENDATION  
**Scope:** HAPI identity backend + Bookwrm Base44 app integration

---

## Executive Summary

The HAPI identity backend is **the authoritative identity provider**. Bookwrm/Base44 is **a relying party (OIDC client)**. This relationship should be formalized and standardized to serve as the architecture template for future companion apps.

**Recommended Pattern:**

```
                    ┌─────────────────────────────────┐
                    │  HAPI Identity Backend          │
                    │ (identity.bookwrm.com)          │
                    │                                 │
                    │ · OIDC Provider                 │
                    │ · Email registration (H2–H3)   │
                    │ · Email/OTP authentication (H4) │
                    │ · Face enrollment (H5)          │
                    │ · Universal Login UI (H6)       │
                    │ · Subject & token management    │
                    │ · Signing keys & refresh tokens │
                    └────────────────┬────────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
        ┌────────▼────────┐  ┌───────▼────────┐  ┌──────▼─────────┐
        │  Bookwrm/Base44 │  │  HAPI Portal   │  │  Future Companion
        │  (OIDC Client)  │  │  (OIDC Client) │  │  Apps
        │                 │  │                │  │  (OIDC Clients)
        │ Relying party:  │  │ Relying party: │  │
        │ · Research      │  │ · Account mgmt │  │  Each registers
        │ · Calendar      │  │ · Profile      │  │  as separate
        │ · SSO login     │  │ · 2FA/Face     │  │  OIDC client
        │                 │  │ · Session mgmt │  │
        └─────────────────┘  └────────────────┘  └────────────────┘
```

---

## 1. Recommended Integration Pattern: Bookwrm as OIDC Relying Party

### Architecture

**Identity Provider:** `https://identity.bookwrm.com` (HAPI backend)  
**Bookwrm Callback:** `https://base44.bookwrm.com/auth/oidc/callback` (or equivalent)

**Registration:**
- Bookwrm/Base44 is registered in HAPI as:
  - Tenant #1 (Bookwrm)
  - Application #1 (Base44)
  - OIDC Client with:
    - `client_id`: `base44` (or similar)
    - `redirect_uris`: `["https://base44.bookwrm.com/auth/oidc/callback"]`
    - `scopes`: `["openid", "profile", "email"]`
    - `grant_types`: `["authorization_code", "refresh_token"]`
    - `token_endpoint_auth_method`: `client_secret_post` or `client_secret_basic`
    - `require_pkce`: `true` (recommended)

### Authentication Flow

1. **User lands on Bookwrm landing page**
   - No login session
   - Bookwrm detects unauthorized and redirects:
   ```
   GET /auth/oidc/authorize?
     client_id=base44&
     redirect_uri=https://base44.bookwrm.com/auth/oidc/callback&
     response_type=code&
     scope=openid+profile+email&
     state=random_state&
     nonce=random_nonce&
     code_challenge=pkce_challenge
   → Redirects to: https://identity.bookwrm.com/authorize?[same params]
   ```

2. **HAPI login UI** (hosted at `identity.bookwrm.com`)
   - If H6.11.1: Shows "Continue with Email" button (for Bookwrm, face unavailable this release)
   - If H6+: Shows Email / Face chooser
   - User authenticates via Email OTP (H4) or PrivateID Face (existing)

3. **HAPI issues authorization code**
   ```
   302 → https://base44.bookwrm.com/auth/oidc/callback?
     code=authorization_code&
     state=same_state_from_step_1
   ```

4. **Bookwrm backend exchanges code for tokens**
   ```
   POST https://identity.bookwrm.com/token
   {
     "grant_type": "authorization_code",
     "code": "authorization_code",
     "redirect_uri": "https://base44.bookwrm.com/auth/oidc/callback",
     "client_id": "base44",
     "client_secret": "base44_client_secret",
     "code_verifier": "pkce_verifier"
   }
   
   ← Response:
   {
     "access_token": "eyJhbGciOiJSUzI1NiI...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "refresh_token_value",
     "id_token": "eyJhbGciOiJSUzI1NiI..."
   }
   ```

5. **Bookwrm validates ID token and establishes session**
   - Validates JWT signature using HAPI's JWKS (`https://identity.bookwrm.com/jwks`)
   - Extracts `sub`, `email`, `email_verified`, `name` claims
   - Creates Bookwrm session cookie
   - Redirect to: `https://base44.bookwrm.com/dashboard`

6. **User accesses Bookwrm**
   - Session cookie is valid
   - User sees personalized research/calendar
   - User identity is `sub` (UUID from HAPI identity_subjects)

### Session Refresh

When ID token expires:
```
POST https://identity.bookwrm.com/token
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh_token_value",
  "client_id": "base44",
  "client_secret": "base44_client_secret"
}
← New access_token + (optionally new refresh_token)
```

---

## 2. Why This Pattern (vs. Alternatives)

### Alternative A: Embedded Identity in Bookwrm App (Rejected)

**Concept:** Bookwrm/Base44 would include identity registration, email verification, and OTP code directly in its application.

**Reject reasons:**
1. **Duplicate effort:** Code already exists in HAPI; replicating it violates DRY
2. **Subject fragmentation:** Users would have different subject identifiers in Bookwrm vs. HAPI
3. **No cross-app identity:** Future companion apps could not see the same user identity
4. **Maintenance burden:** Each app would need to replicate key rotation, database schema, verification flows
5. **Security surface:** More identity code = more security review and testing per app

### Alternative B: Identity Microservice Embedded in Bookwrm (Rejected)

**Concept:** Bookwrm would import the HAPI identity backend as a dependency/library and run it internally.

**Reject reasons:**
1. **High coupling:** Bookwrm's deployment cadence would be tied to identity changes
2. **Data fragmentation:** Each Bookwrm deployment would have its own identity database
3. **Multi-tenancy loss:** H1 architecture (tenant/application/client model) would not apply
4. **Secret sprawl:** Each Bookwrm deployment would need its own signing keys
5. **Scalability issue:** Cannot share identity across multiple Bookwrm instances/regions without synchronization

### Alternative C: API Gateway / Proxy Layer (Rejected)

**Concept:** A separate gateway service would sit between Bookwrm and HAPI, adding policy/translation.

**Reject reasons:**
1. **Over-architecture:** OIDC protocol already provides standard client/provider separation
2. **Performance:** Extra hop adds latency to every token exchange
3. **Operational burden:** Additional service to monitor, scale, and maintain
4. **Limited benefit:** Gateway cannot add value that OIDC doesn't already provide

### Recommended (Selected): HAPI as OIDC Provider, Bookwrm as Client

**Reasons:**
1. ✓ **Standards-compliant:** OIDC is widely understood and audited
2. ✓ **Clean separation:** Identity and application concerns are truly independent
3. ✓ **Reusable:** Any future companion app registers as another OIDC client
4. ✓ **Scalable:** HAPI and Bookwrm can scale independently
5. ✓ **Testable:** Each component can be tested in isolation
6. ✓ **Secure:** Standard JWT validation, refresh token rotation, PKCE
7. ✓ **Multi-tenant ready:** H1 architecture applies to all clients
8. ✓ **Session management:** Each client owns its session lifecycle independent of HAPI

---

## 3. Bookwrm Configuration Requirements

### On HAPI Side (Identity Backend)

Already handled by H1 bootstrap (`ensureBookwrmApplicationSeed()`):

```sql
-- Tenant: Bookwrm
INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
VALUES (uuid_generate_v4(), 'Bookwrm', 'bookwrm', 'active', now(), now());

-- Application: Base44
INSERT INTO applications (id, tenant_id, name, slug, status, created_at, updated_at)
VALUES (uuid_generate_v4(), (SELECT id FROM tenants WHERE slug='bookwrm'), 
        'Base44', 'base44', 'active', now(), now());

-- OIDC Client
INSERT INTO oidc_clients (
  id, application_id, client_id, client_secret, 
  redirect_uris, scopes, grant_types, token_endpoint_auth_method, require_pkce,
  created_at, updated_at
) VALUES (
  uuid_generate_v4(),
  (SELECT id FROM applications WHERE slug='base44'),
  'base44',  -- From OIDC_BASE44_CLIENT_ID
  'secret',  -- From OIDC_BASE44_CLIENT_SECRET
  ARRAY['https://base44.bookwrm.com/auth/oidc/callback'],  -- From OIDC_BASE44_REDIRECT_URI[S]
  ARRAY['openid', 'profile', 'email'],  -- From OIDC_BASE44_SCOPES
  ARRAY['authorization_code', 'refresh_token'],  -- From OIDC_BASE44_GRANT_TYPES
  'client_secret_post',  -- From OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD
  true,  -- From OIDC_BASE44_PKCE_REQUIRED
  now(), now()
);
```

**Required HAPI environment variables:**

```bash
OIDC_BASE44_CLIENT_ID=base44
OIDC_BASE44_CLIENT_SECRET=<generated_or_provided_secret>
OIDC_BASE44_REDIRECT_URI=https://base44.bookwrm.com/auth/oidc/callback
OIDC_BASE44_REDIRECT_URIS=https://base44.bookwrm.com/auth/oidc/callback  # Alternative
OIDC_BASE44_SCOPES=openid,profile,email  # Default
OIDC_BASE44_GRANT_TYPES=authorization_code,refresh_token  # Default
OIDC_BASE44_PKCE_REQUIRED=true  # Recommended
OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_post  # Recommended
```

### On Bookwrm Side (Relying Party Client)

**Configuration needed in Base44 application:**

```typescript
// src/auth/oidcConfig.ts (example)
export const oidcConfig = {
  clientId: 'base44',
  clientSecret: process.env.BOOKWRM_OIDC_CLIENT_SECRET,
  authorizationEndpoint: 'https://identity.bookwrm.com/authorize',
  tokenEndpoint: 'https://identity.bookwrm.com/token',
  userInfoEndpoint: 'https://identity.bookwrm.com/userinfo',
  jwksUri: 'https://identity.bookwrm.com/jwks',
  redirectUri: 'https://base44.bookwrm.com/auth/oidc/callback',
  scopes: ['openid', 'profile', 'email'],
  responseType: 'code',
  codeChallenge: true,  // PKCE
  discoveryUrl: 'https://identity.bookwrm.com/.well-known/openid-configuration'
};
```

**Implementation pattern (pseudo-code):**

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

// Initialize
const jwks = createRemoteJWKSet(new URL(oidcConfig.jwksUri));

// In your login route
app.get('/auth/oidc/login', (req, res) => {
  const state = generateRandomString(32);
  const nonce = generateRandomString(32);
  const codeChallenge = generatePKCEChallenge();
  
  // Store in session
  req.session.oidcState = state;
  req.session.oidcNonce = nonce;
  req.session.codeVerifier = codeChallenge.verifier;
  
  res.redirect(
    `${oidcConfig.authorizationEndpoint}?` +
    `client_id=${oidcConfig.clientId}&` +
    `redirect_uri=${encodeURIComponent(oidcConfig.redirectUri)}&` +
    `response_type=code&` +
    `scope=${oidcConfig.scopes.join('+')}&` +
    `state=${state}&` +
    `nonce=${nonce}&` +
    `code_challenge=${codeChallenge.challenge}&` +
    `code_challenge_method=S256`
  );
});

// Callback endpoint
app.get('/auth/oidc/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // Verify state
  if (state !== req.session.oidcState) {
    return res.status(400).send('Invalid state parameter');
  }
  
  // Exchange code for tokens
  const tokenResponse = await fetch(oidcConfig.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: oidcConfig.redirectUri,
      client_id: oidcConfig.clientId,
      client_secret: oidcConfig.clientSecret,
      code_verifier: req.session.codeVerifier
    })
  });
  
  const { id_token, access_token, refresh_token } = await tokenResponse.json();
  
  // Verify and decode ID token
  const { payload } = await jwtVerify(id_token, jwks);
  
  // Verify nonce
  if (payload.nonce !== req.session.oidcNonce) {
    return res.status(400).send('Invalid nonce');
  }
  
  // Create user session in Bookwrm
  const user = {
    sub: payload.sub,
    email: payload.email,
    email_verified: payload.email_verified,
    name: payload.name
  };
  
  req.session.user = user;
  
  res.redirect('/dashboard');
});
```

---

## 4. Relationship Between Components

### Identity Subject (HAPI side)

```sql
-- Table: identity_subjects
{
  id: "00000000-0000-0000-0000-000000000001",  -- Canonical subject UUID
  oidc_subject: "00000000-0000-0000-0000-000000000001",
  primary_provider: "HAPI_EMAIL",
  primary_provider_subject: "user@example.com",
  email: "user@example.com",
  email_verified: true,
  display_name: "User Name",
  status: "active",
  application_id: "00000000-0000-0000-0000-000000000002",  -- Application #1 (Base44)
  created_at: "2026-10-04T...",
  updated_at: "2026-10-04T..."
}
```

### OIDC Token (Issued by HAPI)

```json
{
  "iss": "https://identity.bookwrm.com",
  "sub": "00000000-0000-0000-0000-000000000001",  -- Matches identity_subjects.id
  "aud": "base44",
  "exp": 1700000000,
  "iat": 1699996400,
  "nonce": "...",
  "email": "user@example.com",
  "email_verified": true,
  "name": "User Name",
  "amr": ["email"],  -- Authentication method (email, face, etc.)
  "acr": "...",
  "auth_time": 1699996400
}
```

### Bookwrm Session (Bookwrm side)

```typescript
// session in browser
{
  userId: "00000000-0000-0000-0000-000000000001",  -- Same as identity_subjects.id
  email: "user@example.com",
  name: "User Name",
  authenticatedAt: 1699996400,
  idTokenExp: 1700000000
}
```

**Key invariant:** The `sub` claim in OIDC tokens **equals** the `id` in `identity_subjects`. This is the **durable subject identifier** that remains constant across sessions, logins, and even if the user's email changes (future feature).

---

## 5. Multi-App Scaling (Future)

This architecture supports additional companion apps without modification:

### HAPI Portal (Hypothetical Future App)

```
Tenant: Bookwrm
├─ Application: Base44 (existing)
│  └─ OIDC Client: base44
└─ Application: HAPI Portal (future)
   └─ OIDC Client: hapi-portal
   
   OIDC Client registration:
   {
     client_id: "hapi-portal",
     client_secret: "...",
     redirect_uris: ["https://hapi-portal.bookwrm.com/auth/oidc/callback"],
     scopes: ["openid", "profile", "email"],
     grant_types: ["authorization_code", "refresh_token"]
   }
```

### Cross-App User Identity

A single HAPI identity subject can log in to **both** Bookwrm AND the HAPI Portal:

```
User registers via HAPI Portal email:
→ identity_subjects.id: "uuid-1"
→ email: "user@example.com"
→ application_id: (HAPI Portal application)

User then logs in via Bookwrm with same email:
→ identity_subjects.id: "uuid-1" (SAME)
→ Bookwrm recognizes user, no re-registration

User gets ID token from HAPI:
→ When accessing Base44: { "sub": "uuid-1", "aud": "base44", ... }
→ When accessing Portal: { "sub": "uuid-1", "aud": "hapi-portal", ... }
```

---

## 6. Security Considerations

### OIDC Client Secret Management

**Recommendation:**
- Store in Railway environment variable (HAPI side): `OIDC_BASE44_CLIENT_SECRET`
- Store in Bookwrm environment variable (Bookwrm side): `BOOKWRM_OIDC_CLIENT_SECRET`
- Rotate every 90 days (or on suspected compromise)
- Maintain backup secret during rotation (oidc-provider supports multiple secrets)

### PKCE (Proof Key for Code Exchange)

**Recommendation:** Always enable for public clients (mobile, SPA).

**Current setting:**
```
OIDC_BASE44_PKCE_REQUIRED=true
```

### Redirect URI Whitelist

**Current:**
```
OIDC_BASE44_REDIRECT_URIS=["https://base44.bookwrm.com/auth/oidc/callback"]
```

**Future:** If Bookwrm has multiple callback endpoints (e.g., mobile, web, desktop), add each to the array:
```
OIDC_BASE44_REDIRECT_URIS=[
  "https://base44.bookwrm.com/auth/oidc/callback",
  "https://app.bookwrm.com/auth/oidc/callback",
  "app://bookwrm/auth/oidc/callback"
]
```

### Token Expiry

**Recommendation (current defaults in HAPI code):**
- Access token: 1 hour
- Refresh token: 7 days (or longer, depending on trust)
- ID token: Same as access token

### Subject Stability

**Critical:** The `sub` claim in issued tokens **must remain stable** across:
- Password changes
- Email verification status changes
- Multi-factor enrollment/disenrollment
- Application registrations
- Account recovery

**Implementation:** HAPI uses `identity_subjects.id` (a fixed UUID) as the subject. This is immutable and correct.

---

## 7. Operational Considerations

### Single Sign-Out (Future)

Currently not implemented. When/if Bookwrm needs to revoke sessions:

**Option 1:** Bookwrm deletes its own session cookie (simplest, recommended for now)

**Option 2:** Implement OIDC RP-Initiated Logout
```
Bookwrm user clicks "Log out"
→ Bookwrm deletes local session
→ Bookwrm redirects to: https://identity.bookwrm.com/logout?
  &client_id=base44&
  &post_logout_redirect_uri=https://base44.bookwrm.com/loggedout&
  &id_token_hint=[id_token]
→ HAPI logs out the user (invalidates refresh tokens, etc.)
→ HAPI redirects to Bookwrm's post_logout_redirect_uri
```

### Logout from HAPI Portal

If HAPI Portal implements logout, it should **not** automatically log out of Bookwrm (and vice versa). Each application manages its own session independently. This is the standard OIDC pattern.

---

## 8. Bookwrm Compatibility

### Bookwrm Existing SSO Integration

Bookwrm currently expects:
```
Issuer: https://identity.bookwrm.com
Client ID: (configured in Base44)
Client Secret: (configured in Base44)
Redirect URI: https://base44.bookwrm.com/auth/oidc/callback (or similar)
```

**Status:** ✓ Compatible with this plan

### Bookwrm Existing Users

Bookwrm users who registered before HAPI:
- Pre-HAPI users are stored in Bookwrm's own user table
- When HAPI is recovered and Bookwrm uses OIDC login, their email can be used to look up their HAPI identity
- **Data migration (future):** Link Bookwrm users to HAPI identities via email verification

---

## 9. Rollout & Testing

### Phase 1: Verification (Immediate)
- Confirm HAPI identity backend is online and responding to OIDC requests
- Confirm Bookwrm is registered as OIDC_BASE44 client on HAPI
- Test OIDC login with synthetic user

### Phase 2: Staged Rollout (Post-Recovery)
- Identify a small set of Bookwrm test users
- Redirect them to HAPI login
- Collect feedback on UX

### Phase 3: Full Rollout (After validation)
- Enable OIDC login for all Bookwrm users
- Optionally sunset legacy login methods (if any)

---

## 10. Recommended Decision

**Accept this architecture:**

```
Bookwrm (Relying Party) ←OIDC→ HAPI Identity Backend (Provider)
```

**Rationale:**
1. ✓ Standards-compliant (OIDC protocol)
2. ✓ Proven in production (H1–H6.11.1 releases)
3. ✓ Scalable to multiple apps (future companions)
4. ✓ Clean separation of concerns
5. ✓ Bookwrm can focus on research/calendar; HAPI owns identity
6. ✓ Existing database, keys, and subject identities are preserved
7. ✓ Minimal code changes in Bookwrm (just OIDC client library)

---

## End HAPI Integration Decision

This document recommends proceeding with the OIDC pattern and deferring any alternative architectural decisions pending production validation and user feedback.
