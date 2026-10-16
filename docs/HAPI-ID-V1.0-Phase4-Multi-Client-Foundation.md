# HAPI ID V1.0 Phase 4: multi-client identity foundation

## Authority and ownership

`IdentitySubject` is the canonical person, independent of application membership.
Its existing `application_id` remains creation provenance for compatibility, not
authentication or authorization authority. Existing IDs and OIDC subjects are
not regenerated. Missing application links are valid, including for the Face
Setup pilot identity.

An application is a product/policy boundary; an OIDC client is a protocol
registration. Multiple clients may belong to one application. Every authorization
resolves an active client, active application, and active tenant from server-side
registration. Interaction and verification artifacts remain bound to their
original client/application/tenant; changing a client binding invalidates a
pending interaction.

HAPI authenticates people. Applications independently own membership, roles,
entitlements, application data, and access decisions. Successful HAPI
authentication or a Face authenticator does not grant application access.
Roles and membership are not added to canonical identities, links, or ID tokens.

## Registry and policy

Applications persist a unique `application_key`, display name, status, timestamps,
allowed authentication methods, allowed identity providers, and Face Setup
permission. `name` is the existing display-name field. Optional presentation
metadata defines logo, primary/accent colors, support, privacy, and terms URIs.
Advanced presentation is deferred to Phase 5; branding cannot override HAPI
security or consent language.

Only the existing Bookwrm application is seeded in production, retaining its
stable application ID and using `BOOKWRM`. Its existing OIDC client is retained,
including client ID, exact redirects, client authentication, and PKCE requirement.
Suspended application/client registrations are not silently reactivated.

Bookwrm allows `HAPI_EMAIL`. `PRIVATEID_FACE` is not an enabled login method;
Face Setup remains a separate, explicitly permitted pilot, still subject to the
existing feature flags, pilot allowlist, recent email authentication, and
`FACE_AUTH_V1`. No external providers are registered or enabled.
`EXTERNAL_OIDC` and `EXTERNAL_SAML` are reserved identifiers, not implemented
federation. Direct email handoffs and Face routes enforce method policy
server-side, including the old flag-off Face fallback.

## Application account links

`application_account_links` records identity, application, external account,
status, and creation/update times. V1 permits exactly one account per
identity/application and one identity per application/account:

- `UNIQUE(application_id, external_account_id)`
- `UNIQUE(identity_subject_id, application_id)`

Reconciliation is idempotent for an identical relationship and fails closed on
either collision. It never reassigns an account or silently merges identities.
The new generic reconciliation repository is server-internal, not a public
link-creation API. Its caller must already possess authoritative continuity
evidence; a typed evidence object is not itself proof of authentication.

### Bookwrm reconciliation authority

The existing service-authenticated Bookwrm continuity endpoint is retained.
Bookwrm's trusted backend must first validate a successful HAPI OIDC result
(issuer, audience, signature, nonce/state, and PKCE/code exchange as applicable)
and resolve the confirmed locally authenticated account. Its existing verified
email-match continuity event is sufficient only when it matches that successful
OIDC identity to the confirmed local Bookwrm account; an unverified email or
browser-supplied account identifier is never sufficient.

The service credential delegates this attestation to the trusted Bookwrm
backend. HAPI does not independently verify a Bookwrm session at this legacy
endpoint. The authenticated service supplies the canonical OIDC subject and
trusted `x-bookwrm-user-id`; a body account ID must match that trusted ID.
Do not expose the service credential or this header-setting capability to a
browser. New integrations must not call reconciliation from an arbitrary
application-supplied ID, email, `login_hint`, name, or Face match alone.

The legacy `identity_account_links` table and response contract remain intact.
A transactional insert trigger mirrors future successful Bookwrm continuity
writes into the generic link and persistent audit tables. Existing rows are
copied once with their IDs, timestamps, status, and identity/account meaning
unchanged. There is no scan of identities to manufacture missing links and no
pilot identity repair.

Audits capture internal identity, application, external account, time, authority,
client/request correlation where available, and created/existing/conflict result.
Legacy insertion uses the link ID as persistent correlation; request logging
additionally records the server-configured Bookwrm client and request ID.
Generic callers supply their validated context.
Operational logs contain safe internal references and outcomes, never OTPs,
codes, tokens, secrets, PUIDs, or biometric templates.

## Custom login and provider hints

Product pages enter through standard `/authorize`; client registration determines
the application and policy, not Bookwrm-specific presentation.
`login_hint` is accepted but not consumed by the UI in Phase 4. Its contract is
presentation-only; it cannot verify/create an identity, create a link, or bypass
OTP. Normalized UI prefill is deferred to Phase 5.

All `idp_hint` requests are refused in Phase 4, even if a policy array were
populated. Future Phase 6 routing must validate the provider against the
application's allowed providers and enable the corresponding method before
provider selection. No arbitrary provider URL/query routing exists.

## Sessions, logout, and consent

HAPI SSO identity, application session/access, and authentication freshness are
separate. Sharing an authenticated person does not share application membership.
Recent email authentication is still required for Face Setup; an application
session alone does not satisfy it.

V1 recommends application-local logout by default. HAPI SSO logout is a separate
explicit action; global cross-application logout is not implemented or promised.
Existing logout behavior is retained, not expanded into single logout.

`FACE_AUTH_V1` remains HAPI identity/authenticator consent. Future application
health, research, religious-community, membership, and product consents belong
to those applications, not the HAPI authenticator-consent table.

## Deployment and compatibility

DDL is additive and repeatable: application/client metadata, generic links,
audit table, indexes, and the Bookwrm compatibility trigger. Existing tables,
identity records, authenticators, and Face ownership are not replaced.
Existing startup assignment of missing legacy application provenance predates
Phase 4; certification must confirm it will not modify production identities.

Before/after certification compares private aggregate fingerprints and counts
for identities, original links, authenticators, and Face state, plus exact client
configuration. Expected metadata changes are the `BOOKWRM` key/email-only policy,
Face Setup permission, active client status default, and deterministic copies
of existing links. Production receives no Elite+ or Pepperdine applications.

Phase 3S service authentication, constant-time confidential-client checks,
redirect fail-closed behavior, discovery, and CORS remain mandatory.
The CORS origin allowlist is not an OIDC redirect-URI allowlist; each is enforced
independently.

Phase 5 may register a real Elite+ application/client only through its separately
approved work, consume validated presentation metadata, and implement local
membership/authorization. External federation remains Phase 6. No live Face
enrollment, public Face Login, PrivateID tenant change, or legacy identity
migration is part of this foundation.
