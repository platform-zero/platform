# Private delegated Matrix identity

The separate `matrix-identity-r4` deployment adds Matrix Authentication Service 1.28.0 to the private stack. At introduction this brought coverage to **27/39 selected families plus OpenBao, 51 daemons in 20 supervised deployments**; see [the current runtime inventory](private-runtime.md) for subsequent additions. This is component integration, not a completed release. **Full-stack acceptance remains 0/2.** The existing `matrix-r2` deployment and its encrypted messages were not modified.

## Implemented and exercised

- Kotlin `MatrixIdentityRuntime`: PostgreSQL, Keycloak, Synapse, MAS, private identity nginx and Element nginx; seven journalled one-shot initializers and six daemons. Immutable images, internal network, no published ports, non-root/read-only/AppArmor restrictions and private inputs use the existing audited runtime.
- Separate HTTPS origins `identity`, `auth`, and `element`, with separate private certificates. Each certificate and hostname is verified before browser launch; untrusted system-CA handshakes fail. Chromium trusts only the verified leaf public keys and requests are restricted to the three origins.
- Keycloak confidential upstream client with exact callback, authorization-code flow and S256 PKCE; direct grants and service accounts disabled. Synthetic owner and reader perform native temporary-password change and TOTP enrollment. A separate outsider fixture tests denial, not privileged onboarding.
- MAS local passwords disabled; imported usernames restricted to owner/reader, upstream subject imported explicitly, username conflict fails, email ignored for identity linking. Native database checks bind both MAS users and signed ID-token subjects to their exact upstream Keycloak subjects/provider. Neither can request administrator scopes.
- Synapse delegates authentication to MAS. Native user tokens create/join a private, non-federated room, send and read a message, and are denied the native Synapse administrator API. Invalid tokens fail. Password-only login stops at TOTP; the password grant is rejected. An authenticated upstream outsider is denied registration and is absent from the MAS user table.
- Public fixture OAuth client uses S256 PKCE; wrong verifier and authorization-code replay fail. ID-token RSA signature, issuer, audience, nonce and expiry are verified against native HTTPS JWKS.
- Element has a separate static public client. Its exact redirect allowlist includes the native `?no_universal_links=true` callback; no wildcard redirect or relaxed dynamic-registration policy was introduced.
- Actual Element native OIDC login and message readback, without injecting a client token. Native recovery-key creation is recorded privately before confirmation. Subsequent fresh browser devices use that key through Element's recovery UI. No existing encryption identity is reset.
- Actual pinned systemd restart preserves container IDs, changes daemon start timestamps, leaves initializer journal bytes unchanged and permits fresh browser/API login and readback.

The message in this probe is deliberately **not E2EE**; Element displays that fact. Recovery here proves native identity-key use, **not historical encrypted-message recovery, homeserver backup restoration or a coordinated MAS/Keycloak/Synapse restore**. The separate `matrix-r2` encrypted-message evidence does not automatically extend to this deployment.

## Evidence

Protected receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-matrix-id-53ecaaec9046`: original API/OIDC integration and restart, before native Element integration.
- `p0v3-matrix-id-ca49534d7e68`: fresh r4 password/TOTP onboarding, Element login/key setup, restart and fresh-device recovery/readback.
- `p0v3-matrix-id-96baadf3e1df`: repeat with outsider/password-grant/admin denial, exact subject binding, database required-action/TOTP checks and untrusted-CA denial.
- **`p0v3-matrix-id-a6b945eabfbe`**: latest repeat including the actual six-daemon systemd restart; native Element screenshot inspected.

Manifest SHA-256: `aa99160c327e2bf6d1d688a9698f946430fcfeb567bd4fdb0423d6f1f8f6a65b`.
Controller tree: `627a977269b0c6ab0938ea068d7d9c7b31f8d25206257ecce45f1247360480cb` (ninth pinned snapshot).
Unit SHA-256: `f0e15d7c669e79a4066a1852c4a67d56d83546330270417acdb330314344f17d`.

The latest **whole-fleet** restart still covered 18 units/39 daemons. Mastodon and delegated Matrix units were tested separately; no 51-daemon fleet restart or host reboot is claimed. Units are boot/shutdown integration, not crash watchdogs.

## Retained failures and safeguards

Earlier `matrix-identity`, `matrix-identity-r2` and `matrix-identity-r3` deployments are stopped and retained. r2 initially rejected Element's additional redirect query parameter; its failed receipts remain false. Early browser probes did not wait for a fresh TOTP timestep; the probe now journals the last attempted timestep and waits rather than replaying an OTP. Leaving the Keycloak origin is explicitly required before reporting successful upstream login.

An early r3 Element browser was closed before a recovery key was preserved, leaving that synthetic identity unverifiable on a fresh device. It was **not reset**: r3 and failed evidence were retained, and r4 was independently prepared. The current browser journals recovery material before proceeding and never selects identity-reset actions.

Effectful Python refuses optimized mode. Receipts use the fail-closed finalizer: a later error cannot retain an earlier `passed:true`. Protected partial fixture state can be explicitly resumed, but is not acceptance evidence. An orphan credential-state temporary file requires reconciliation. No credentials, TOTP seeds, OAuth tokens or recovery keys should be printed.

## Reproduction

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-matrix-identity.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-matrix-id-a6b945eabfbe \
  --supervised
```

Use the latest protected fixture after subsequent runs; it contains updated TOTP timestep and recovery state. Never omit `--fixture` on an already enrolled deployment. A fresh deployment is prepared with `runtime prepare-matrix-identity INVENTORY NEW_NAME`; changed inputs require a new name, not silent replacement.

## Implementation-only increment (runtime-unverified)

`MatrixRtcRuntime.kt` now provides a separate opt-in combined recipe using the acquired
Matrix RTC authorizer image, Synapse scoped appservice membership authorization, the
LiveKit SFU, Matrix transport discovery, and prefix-preserving WebSocket/Twirp ingress.
It preserves the existing `matrix-identity` recipe rather than rewriting its inputs.
Synapse exposes the OpenID resource without enabling general federation. MAS starts
with `--no-migrate --no-sync`; the cold-import projection retires all seven initializers
and strips Keycloak realm import/bootstrap credentials using an originally archived,
bootstrap-free runtime environment. Import verification remains the generation
controller's responsibility; this projection is not permission to boot uncopied data.

The private server name `matrix.private.invalid` does not have federated OpenID discovery
inside the current runtime DNS model. The appservice's authenticated Synapse-proxied
MSC4195 path is wired; **legacy `/sfu/get` and `/get_token` client compatibility is not
complete** until exact server-name discovery/TLS routing is integrated. No insecure TLS
bypass, global trust, public DNS or fabricated hostname alias was added. TURN, canonical
provider-less identity/database wiring, and real-domain calling remain incomplete.

The qualified Matrix feature driver now contains native delegated encrypted-room
creation, ciphertext/session backup checks, authenticated media digest readback,
original-device closure and fresh native Element recovery. RESTORE reads the exact
INSTALL room/event/session/media oracle and refuses to create a replacement fixture or
reset its encryption identity. MAS checks signed OIDC tokens/PKCE/replay, native Matrix
whoami, password/invalid-token denial and exact database subject/provider linkage.
Python invocation adapters under `acceptance/runners/` pin their helper/Java dependency,
inspect generation-owned containers and internal topology, and fail on bootstrap
replay/source-resume indicators. The WEB wrappers are **private staged probes**, not
real-domain WEB qualification. Android and LiveKit qualification adapters are absent.
These new sources have not been run against applications; historical receipts below
and above do not validate them. Coordinator-owned unit checks are requested separately.

## Remaining

Public DNS/HTTP-01/renewal, real-owner onboarding, Android, integrated Element Call/RTC authorizer/LiveKit and media-key distribution, full delegated encrypted-message recovery, coordinated encrypted application backup/restore, production key rotation, full release transactions and independent clean-install acceptance remain unfinished. Private certificates are not automatically renewed. Private fixture recovery material is not production custody.
