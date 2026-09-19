# PrivateID Authentication Provider

PrivateID is an authentication provider.

Bookwrm Identity owns:

- `userId`
- `oidcSubject`
- `email`
- `emailVerified`
- `displayName`

PrivateID supplies only:

- `provider = privateid`
- `providerSubject = PUID`

The existing PrivateID claim and account-creation paths are deprecated compatibility behavior. They remain in place during this stage and are not changed by the `UserAuthenticator` storage model.