# bookwrm-identity-services

Enterprise Identity Platform for Bookwrm.

## Overview

This service provides identity-facing API routes backed by an internal client and service layer:

- Identity API routes call `IdentityService`
- `IdentityService` delegates to `IdentityPlatformClient`
- `IdentityPlatformClient` calls the upstream identity platform with standardized errors, retries, timeout control, and request logging

## IdentityPlatformClient

Source: `src/clients/IdentityPlatformClient.ts`

Responsibilities:

- Calls upstream identity platform endpoint using `fetch`
- Sends `Authorization: Bearer <BOOKWRM_IDENTITY_API_KEY>`
- Sends JSON request payload with `version` and `action`
- Applies timeout via `AbortController` (default 5000ms)
- Performs status-based retry policy
- Normalizes all failures to `ApiError`
- Logs request metadata for every invocation

Available methods:

- `health()`
- `getIdentityContext()`
- `resolveIdentity()`
- `reverify()`
- `getSecurityContext()`
- `getPolicies()`
- `getTimeline()`
- `getNotifications()`
- `getTrustedDevices()`

## IdentityService

Source: `src/identity/IdentityService.ts`

Responsibilities:

- Provides the internal application-facing identity API
- Delegates all operations to `IdentityPlatformClient`
- Gives routes a stable dependency point (`identityService` singleton)

## Models

Sources:

- `src/models/ApiResponse.ts`
- `src/models/IdentityHealth.ts`
- `src/models/IdentityContext.ts`
- `src/models/SecurityContext.ts`
- `src/models/IdentityPolicy.ts`
- `src/models/IdentityTimeline.ts`
- `src/models/Notification.ts`
- `src/models/TrustedDevice.ts`

`ApiResponse<T>` is the generic envelope returned by client/service methods:

- `success`
- `requestId`
- `version`
- `data`

## Error Handling

Source: `src/utils/ApiError.ts`

Standardized status mappings:

- 401 Unauthorized
- 403 Forbidden
- 404 Not Found
- 408 Request Timeout
- 500 Internal Server Error
- 503 Service Unavailable

Behavior:

- No raw `fetch` exceptions are surfaced to callers
- Timeouts and network failures are normalized into `ApiError`
- HTTP failures are converted into status-aware `ApiError` instances

## Retries

Retry behavior is implemented in `IdentityPlatformClient`:

- Automatic retry for: 500, 502, 503, 504
- Never retry for: 401, 403
- Max retries: 2

## Authentication

Upstream authentication uses a bearer token:

- Header: `Authorization: Bearer <BOOKWRM_IDENTITY_API_KEY>`
- Required env var: `BOOKWRM_IDENTITY_API_KEY`

Related required environment variables:

- `BASE44_BASE_URL`
- `IDENTITY_API_PATH`
- `BOOKWRM_IDENTITY_API_KEY`

## Logging

Every client request emits a structured log entry with:

- `RequestId`
- `Action`
- `Latency`
- `Success`
- `RetryCount`

## API Endpoints

Quick reference for identity routes:

| Method | Route |
| --- | --- |
| GET | /identity/health |
| GET | /identity/context |
| POST | /identity/resolve |
| POST | /identity/reverify |
| GET | /identity/security-context |
| GET | /identity/policies |
| GET | /identity/timeline |
| GET | /identity/notifications |
| GET | /identity/trusted-devices |

## OIDC Manual SSO (Base44)

Issuer:

- `https://identity.bookwrm.com`

Configure Base44 OIDC client through Railway environment variables:

- `OIDC_BASE44_CLIENT_ID`
- `OIDC_BASE44_CLIENT_SECRET`
- `OIDC_BASE44_REDIRECT_URI` or `OIDC_BASE44_REDIRECT_URIS`
- `OIDC_BASE44_SCOPES` (comma-separated, default: `openid,profile,email`)
- `OIDC_BASE44_GRANT_TYPES` (comma-separated, default: `authorization_code,refresh_token`)
- `OIDC_BASE44_PKCE_REQUIRED` (`true` or `false`, default: `true`)
- `OIDC_BASE44_TOKEN_ENDPOINT_AUTH_METHOD` (`client_secret_post`, `client_secret_basic`, or `none`)

Base44 integration diagnostics:

- `GET /diagnostics/oidc/base44` validates the chain:
	- Base44 -> OIDC
	- OIDC -> Bookwrm Identity Services
	- Authenticated Session
- `GET /diagnostics/oidc/dashboard` returns OIDC tab data for clients, issuer, discovery, JWKS, authorization requests, tokens issued, errors, and health.

## OIDC Test Coverage

Added tests:

- `tests/OIDCDiscovery.test.ts`
- `tests/OIDCJWKSTest.test.ts`
- `tests/OIDCToken.test.ts`
- `tests/OIDCUserInfo.test.ts`
- `tests/OIDCPKCETest.test.ts`
