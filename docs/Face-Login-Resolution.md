# Face Login Resolution

Face authentication resolves a pre-existing Bookwrm user. It never creates a user, OIDC subject, or identity record.

```mermaid
sequenceDiagram
  participant P as PrivateID
  participant W as PrivateID webhook
  participant L as AuthenticatorLoginResolver
  participant A as UserAuthenticator
  participant U as Bookwrm User
  participant O as OIDC

  P->>W: SUCCESS with PUID and provider transaction ID
  W->>L: resolveLogin(privateid, transaction ID, PUID)
  L->>A: resolveAuthenticator(privateid, PUID)
  A-->>L: active authenticator and user ID
  L->>U: resolveUserFromAuthenticator(user ID)
  U-->>L: active canonical user and existing OIDC subject
  L->>L: record completed login transaction
  L-->>O: canonical user claims and existing OIDC subject
  O-->>P: authorization response
```

Unknown PUIDs fail authentication. Revoked authenticators return `Authenticator Revoked`. Inactive users cannot log in. Claims, organizations, subscriptions, and permissions remain attributes of the canonical Bookwrm user and are never read from the PrivateID webhook.