# Explicit identity and credential lifecycle — source implementation

These commands are **not authorized to execute during the implementation-only phase**. No new image, deployment, native journey, split custody, or qualification result is claimed.

## Canonical identity recipe

`IdentityRuntime.canonicalProcesses(postgres)` is a provider-less projection for the canonical compiler. It creates a dedicated `keycloak` database with separate `keycloak_migrate` and runtime `keycloak` principals on the shared PostgreSQL provider. Connections use hostname-verified PostgreSQL TLS. Offline realm import owns schema changes; a separate finalize job grants data/sequence access and sets the migration role `NOLOGIN`. The HTTPS daemon uses schema validation, no realm import, no bootstrap-admin environment, and no initial owner password. The imported owner has realm-scoped user/client management (not master-realm authority), mandatory password change, and TOTP enrollment. Signup is disabled.

The compiler must supply the explicit central client registrations through `canonicalInputs(..., clients=...)`. An empty client list does not implicitly enroll application clients or create a permissive controller client. The default endpoint remains private `https://keycloak:8443`; approved public-host integration belongs to the ingress/compiler owners.

`canonicalColdRestoreProcesses` accepts only the known migration/import/finalize jobs and the schema-validating daemon. It removes those jobs and points the daemon at shared PostgreSQL; it never generates new inputs. Other domains' initializer projections remain their owners' responsibility. Legacy private fixture realms still contain bootstrap credentials in their old serving environment and are **not** automatically relabelled safe canonical restore projections.

## Operator/controller entry point

`python3 platform/scripts/identity_secrets.py /absolute/private/request.json`

The request, credential files, CA files and custody outputs use owned, single-link mode-0600 regular files; output/journal parents are owned mode-0700 directories. Symlinks, permissive modes, duplicate JSON object keys, oversized inputs and output replacement are rejected. Credentials are never command-line arguments or printed results.

Common request fields:

```json
{
  "operation": "operator-selected-unique-id",
  "action": "onboard",
  "journalDirectory": "/absolute/private/operator-journal",
  "identity": {
    "origin": "https://keycloak:8443",
    "caFile": "/absolute/private/identity-ca.pem",
    "leafSha256": "<64 lowercase hex characters>",
    "realm": "p0v3",
    "bearerFile": "/absolute/private/operator-token",
    "introspectionClient": "identity-controller-introspection",
    "introspectionSecretFile": "/absolute/private/introspection-secret",
    "audience": "identity-controller",
    "allowedSubjects": ["<explicit enrolled operator subject>"]
  },
  "username": "synthetic-owner",
  "custodyFile": "/absolute/private/new-owner-custody.json"
}
```

The identity provider must register the introspection client/audience and grant the exact operator scopes. Introspection checks active status, exact issuer, audience, subject allowlist, expiry and required scope on every operation. Recovery-only identity is not identity-management or activation authority. All remote requests verify CA, hostname and exact leaf SHA256 **before transmitting credentials**, use bounded timeouts and bodies, and never follow redirects or retry writes.

Actions:

- `onboard`: requires `identity:manage`; creates an exact UUID subject with temporary password and both `UPDATE_PASSWORD` and `CONFIGURE_TOTP`, then reads back those requirements. Writes proposed password/subject to private custody before the potentially ambiguous create. It does not claim that the human has completed enrollment.
- `retire-subject`: exact `subject` UUID; disables that account, logs out its sessions, and reads back disabled status.
- `rotate-client`: exact internal `clientId` UUID and new `custodyFile`; requires a confidential client-secret client, generates its native new secret, stores private custody and reads back the current secret.
- `retire-client-secret`: `clientId` plus the rotation custody file; verifies the replacement is still current, deletes the native rotated-secret slot and verifies replacement survival. This is explicit retirement, not an inferred consumer reload acknowledgement.
- `rotate-bao-token`: requires `credentials:rotate`; `bao` contains `origin`, `caFile`, `leafSha256`, and `operatorTokenFile`. Supply `role`, exact `policies`, new `custodyFile`, and optional TTL (60–86400 seconds; default 3600). Native role configuration must issue orphan tokens with exactly those policies; root administrators/policies are refused. Replacement custody is retained before checking exact policy, independent orphan lease, accessor and TTL.
- `retire-bao-token`: `bao.oldTokenFile` and `bao.replacementTokenFile`, plus exact `policies`. The replacement must be distinct, independently leased, unexpired and scoped. Revoke-self uses only the old token, then verifies its denial and replacement survival. Token inputs accept either raw private token text or the custody JSON produced by rotation. No manual plaintext output extraction is necessary.

Custody files are not installed into a running immutable daemon by these commands. A consumer deployment must explicitly adopt the replacement before old-credential retirement. There is no unattended rotation timer, daemon reload claim, root bootstrap/retirement, or fabricated consumer acknowledgement.

## Explicit Bao recovery unseal

`recovery-unseal` requires `bao:recover`, `bao.sharesFile` containing `{"shares":[...]}`, and `binding` with:

- target `generation`, externally anchored `targetBundleSha256`;
- original `snapshotReceiptSha256` and target Bao `member`;
- exact `endpoint`, pinned `leafSha256`, original Bao `clusterId`.

`identity_recovery.verify_recovery` reads the actual controller generation records at the fixed production generation/runtime bases. It verifies the original snapshot receipt and source bundle, target bundle, completed generation/member import intent/results and fences, native import intent/completion markers, original retired initializer sets, and current runtime manifest/input bytes. Caller booleans are not import authority. Pre-import `recovery.check.json` remains `runtimeImported:false`; separate successful import records are mandatory. The target has no initializer processes or Bao root/share environment inputs.

Only an initialized, sealed, zero-progress Shamir target with exactly the supplied distinct-share threshold is accepted. Local lineage is rechecked before each share. An available pre-unseal cluster ID and the final unsealed cluster ID must match the expected original identity. Wrong final identity or uncertain transport leaves the operation pending and requires explicit target isolation/investigation; the command does not hold a root token to perform an automatic privileged seal. Ordinary startup and `OpenBaoRuntime.coldRestoreSpec` stay sealed. This command cannot promote/activate a recovery, replay an import, remove a maintenance fence, or resume a source.

## Failure and audit semantics

Each mutation fsyncs a hash-linked intent under a nonblocking exclusive file lock before any mutation. Success appends completion; interruption, timeout, failed readback, or partial custody leaves intent unresolved. Both the same operation ID and a new operation ID in that endpoint scope are blocked while effects remain uncertain. Read-only native reconciliation is an operator responsibility; deleting intent is not an approved retry protocol. Logs/results never include response bodies, bearer tokens, passwords or shares. The local journal is integrity-checked, not independent attestation against compromise of its owning UID. External bundle/snapshot anchors and the trusted controller UID remain part of the threat model.

## Keykeeper application lifecycle

Source adds authenticated owner-only `POST /api/items/{id}/rotate` (`{"value":"..."}`) and `/retire` (`{}`). Rotation replaces the value and clears all grants in one Bao CAS write. Retirement writes a tombstone, clears its current value/grants, and denies read/edit/share/regrant even to the owner. Historical Bao KV versions are **not physically destroyed**, and rotating a stored value does not itself rotate its external issuer credential.

Active metadata omits the new `retired` field, preserving old wire shape. Existing records decode `retired:false`; malformed values fail closed. `GET /api/items/{id}/version` requires READ. Optional positive `expectedVersion` on PUT rejects stale clients with 409 before the existing native store CAS. Existing PUT callers remain compatible. Interrupted Bao requests preserve the JVM interrupt flag and report uncertain outcome without retry.

The source adapters `acceptance/runners/keykeeper-native.py` and `human-agent-authorization-native.py` exercise real HTTPS API semantics and retained original restore records. Their helpers and recovery verifier are source-hash pinned. Browser, Keycloak, onboarding and OpenBao qualified runners are not supplied by these two native adapters. New Keykeeper endpoints require a subsequently rebuilt/pinned candidate image; historical fixture image digests have not been fabricated or changed.
