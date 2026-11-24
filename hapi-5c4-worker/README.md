# Stage 5C.4 temporary worker

Local development only. No Railway service, variable, client, or production
data was changed. Production deployment and execution need separate approval.

The two pinned scripts are unchanged from local source commit
`a94cd0f573a5e19a29d04e023524f058adeb4547`:

- `scripts/provision-production-pilot.mjs`: SHA-256 `f3e5add7f236a59ca13138b980975a1c18fc7f9522023a95f06e96fca499ece8`
- `scripts/pilot-provisioning-transaction.mjs`: SHA-256 `c48989f6ca0c6102286c1defb341f799681f19386b2097263c1a0d1371baaded`

The source commit has not been verified on GitHub. Verify the source, this
worker's committed code and dependency lock, deployment triggers and build
output before any separately authorized deployment. `railway.json` must be
selected explicitly as the service config; it sets restart policy `NEVER` and
has no cron schedule. Use one replica, no public domain, the production
project and environment, and no overlapping deployment during execution.

## Secret handoff

After separate approval, an operator uses one retained immutable secret version
from an approved protected source to set the worker's sealed
`HAPI_WORKER_CLIENT_SECRET` and the Certification Console's sealed
`HAPI_CERTIFICATION_CLIENT_SECRET` individually. Never put it in commands,
logs, arguments, source files, or chat. Confirm the protected entry and sealing
workflow with synthetic data first, including any staging diffs and deployment
logs. Sealing may require creating the variable before sealing it; confirm the
value cannot be exposed during that interval. Applying Console variables may
require a separately approved deployment. The worker's secret check does not
prove the Console has received the same version. Keep the pilot suspended and
both authentication features disabled until the controlled handoff is verified.

## Worker setup

Only after separate deployment approval, give the worker its private production
`DATABASE_URL`, `OIDC_ISSUER=https://id.hapiinc.com`, the independently verified
public CA PEM as `HAPI_WORKER_POSTGRES_CA`, and the protected worker secret. The
launcher pins the CA certificate SHA-256 fingerprint and requires the private
hostname and `sslmode=verify-full` for both database connections. The CA is
temporarily written as a private local file; the client secret is not.

The service starts `start.sh`, prints `PLAN_ONLY_PASS`, and waits without
opening a database connection. Before any write, independently confirm the
backend's Email OTP and Universal Login flags are disabled, the application and
callback are approved, the Console handoff and logging policies are acceptable,
and the service ID, source, target, CA and collision state are correct. A
worker environment flag is only an operator attestation, not proof of backend
configuration. Restrict access to the worker and its runtime environment.

## Manual action and recovery

Only after separate authorization for the production write, in the temporary
worker's Railway Console set these **non-secret, process-only** values for the
manual command: `HAPI_WORKER_EXECUTION_ACK=I_HAVE_APPROVED_ONE_PRODUCTION_WRITE`,
`HAPI_WORKER_BACKEND_FLAGS_CONFIRMED=true`, and
`HAPI_WORKER_APPROVED_SERVICE_ID` equal to the independently verified worker
service ID. Then run `sh hapi-5c4-worker/manual.sh --execute-once`. Never put
the secret itself in this command. Successful execution prints
`PROVISIONING_PASS` after verifying suspended metadata and the worker's secret
against the stored hash. The launcher passes the client secret to the pinned
provisioner only over stdin, not in its arguments or environment.

The child holds a PostgreSQL advisory lock while checking for collisions and
running the transaction. Existing rows are refused, including matching ones;
this prevents an automatic repeat and leaves the pinned transaction's own
rollback and idempotency behavior unchanged. The lock coordinates only this
worker, not unrelated database clients. A concurrent external writer is still
subject to database constraints; independently restrict other writers.

On any failure or lost connection, assume the commit outcome is uncertain.
Do not delete the worker, change the secret, or retry. Once no prior child is
running, run `sh hapi-5c4-worker/manual.sh --inspect` with the same non-secret
process-only acknowledgements. Inspection takes the same lock and uses only
read-only SQL. `matching suspended client` confirms the worker's secret and
metadata; it does not confirm the Console secret. `no pilot metadata` means
no targeted rows were found at inspection time: investigate the failure and
obtain fresh approval before another execution. Any other result is a conflict
or error requiring investigation; do not retry. After independently confirming
the result and Console handoff, delete the temporary worker and its protected
variables under separate authorization. Activation is a separate operation.

## Local checks

Run `node --test hapi-5c4-worker/launcher.test.mjs`. The integration test
requires an explicitly named disposable local database and synthetic TLS
certificates via `HAPI_WORKER_TEST_DATABASE_URL`, `HAPI_WORKER_TEST_CA`, and
`HAPI_WORKER_TEST_BAD_CA`; it truncates its disposable pilot tables. It must
never be pointed at production. Tests cannot establish live Railway isolation,
secret-entry behavior, logging policy, or the Console's actual secret.