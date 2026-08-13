# resolveIdentity Payload Report

## Scope

Inspect `IdentityService.resolveIdentity()` and `IdentityPlatformClient.resolveIdentity()` to determine the exact JSON payload sent to the Base44 `identityAPI` for `action=resolveIdentity`, then compare it against the Base44 `identityAPI` implementation's required fields.

## Request construction (as-is, no summarization)

**`IdentityService.resolveIdentity()`** (`src/identity/IdentityService.ts`):

```ts
async resolveIdentity(privateIdUserId?: string): Promise<ApiResponse<IdentityContext>> {
    await identityCache.invalidate(`identity:${privateIdUserId ?? "default"}`);
    await identityCache.invalidate(`security:${privateIdUserId ?? "default"}`);
    await identityCache.invalidate(`policies:${privateIdUserId ?? "default"}`);
    return this.client.resolveIdentity(privateIdUserId);
}
```

It does not add or transform any fields — it just invalidates cache keys and forwards `privateIdUserId` unchanged to `this.client.resolveIdentity(...)`.

**`IdentityPlatformClient.resolveIdentity()`** (`src/clients/IdentityPlatformClient.ts`):

```ts
async resolveIdentity(privateIdUserId?: string): Promise<ApiResponse<IdentityContext>> {
    const payload = privateIdUserId ? { privateIdUserId } : {};
    return this.invoke<IdentityContext>("resolveIdentity", payload);
}
```

**`invoke()`** builds the actual HTTP request body (`src/clients/IdentityPlatformClient.ts`):

```ts
body: JSON.stringify({
    version: "v1",
    action,
    ...payload
})
```

### Exact JSON sent to `POST {BASE44_BASE_URL}{IDENTITY_API_PATH}`

When `privateIdUserId` is provided:

```json
{
  "version": "v1",
  "action": "resolveIdentity",
  "privateIdUserId": "<privateIdUserId>"
}
```

When `privateIdUserId` is `undefined` (e.g. called with no argument):

```json
{
  "version": "v1",
  "action": "resolveIdentity"
}
```

Headers sent alongside it:

```
Content-Type: application/json
Authorization: Bearer <BOOKWRM_IDENTITY_API_KEY>
```

## Base44 `identityAPI` implementation — side-by-side

| | This repo's outbound request | Base44 `identityAPI` (`action=resolveIdentity`) |
|---|---|---|
| Source location | `src/clients/IdentityPlatformClient.ts` (`invoke`) | Not present in this workspace |
| Envelope fields | `version`, `action`, `privateIdUserId` (conditional) | Unknown — no implementation, contract doc, schema, or OpenAPI spec exists in this repository |
| Required fields per Base44 | N/A | Cannot be determined — `src/adapters/` is empty, and no docs define the required field list; only mentions of the string `identityAPI` in build reports are prose, not a schema |

## Conclusion

The Base44 `identityAPI` implementation does not exist anywhere in this codebase — it is an external, out-of-repo service. There is no server code, contract test, OpenAPI/JSON-schema file, or mock implementation defining its required payload shape in this repository. A field-by-field comparison against Base44's required fields cannot be completed without access to the Base44 `identityAPI` source or its contract (in another repo, a shared schema package, or documentation).
