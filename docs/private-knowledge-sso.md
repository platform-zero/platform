# Native Keycloak → BookStack private SSO

**Cross-service component evidence, not production identity activation or full-stack acceptance. Full-stack acceptance remains 0/2.**

`knowledge-identity-r4` is a separate composite deployment: PostgreSQL, Keycloak, MariaDB, PHP-FPM and a private TLS nginx frontend. It wires two already-counted families; it does **not** increase family coverage beyond 24/39. Existing `identity-r2` and `bookstack-r3` data, credentials, inputs and units were not replaced.

## Configuration and boundaries

- `KnowledgeIdentityRuntime.kt` composes the supported immutable identity/wiki recipes with non-colliding database initialization inputs. All processes retain non-root users, read-only roots, capability restrictions, resource bounds, dedicated AppArmor and one internal-only network. There are no host port bindings.
- Native BookStack OIDC uses a confidential Keycloak client, an exact callback URI, authorization-code flow and **required S256 PKCE**. Direct password grants and service-account grants are disabled.
- The synthetic owner is explicitly bound to a fixed Keycloak subject using BookStack's supported initial-admin command. The application matches `sub`, not a forwarded username/email header. Local password login is disabled by the native OIDC auth guard.
- Standard registration settings alone do **not** close BookStack's OIDC auto-registration. A narrowly scoped native theme listener rejects `AUTH_PRE_REGISTER`; only explicitly provisioned subjects may log in. Group-to-role synchronization and remote avatar fetching are disabled.
- The synthetic Keycloak owner initially requires `UPDATE_PASSWORD` and `CONFIGURE_TOTP`. This is not enrollment of the real owner's authenticator. An additional unprovisioned IdP user tests the authorization boundary.
- `PrivateWebPki.kt` generates a per-deployment RSA CA/leaf certificate with a hostname SAN. The temporary issuer private key is discarded. PHP's native TLS client trusts only the scoped supplied CA for this fixture; no shared host trust store is changed.
- The browser wrapper verifies the actual server certificate and hostname against that CA and checks the exact leaf bytes. Chromium's exception is restricted to the exact leaf SPKI, with requests restricted to the fixture HTTPS origin; there is no blanket ignore-HTTPS-errors setting. An untrusted system CA context correctly rejects the certificate.

The fixture exposes BookStack at `https://knowledge:8443` and Keycloak through `/identity/`. The proxy strips that prefix before talking to the already-optimized Keycloak image; its public issuer URL includes the prefix. Plain HTTP on port 8080 serves only a bounded health endpoint; application paths there return 404.

**This single-origin test layout is not the intended production origin isolation.** Production IdP/application origins, public Caddy HTTP-01/renewal, backend segmentation and trust distribution still need implementation. Private certificates expire after 365 days and have no rotation automation. The existing private Keycloak recipe's backend HTTP/realm SSL setting is not claimed as production hardening.

## Actual native browser and negative journeys

`acceptance/scripts/KnowledgeSsoBrowserProbe.java` and `platform/scripts/test-private-knowledge-sso.py` exercise:

1. Actual BookStack login button → Keycloak authorization request, with S256 challenge, expected client and exact callback observed.
2. Native required password change and TOTP enrollment on a fresh synthetic identity.
3. Native token exchange and callback handling by BookStack—not a probe-injected application session or SDK shortcut.
4. Creation and readback of a book/page through the actual wiki controls/TinyMCE editor after SSO.
5. Password-only login stopping at the TOTP challenge.
6. A valid but unprovisioned IdP subject being rejected by BookStack. A database check confirms that no corresponding wiki user was created.
7. Direct local-password login with the actual bootstrap password and a valid CSRF token remaining unauthenticated; protected wiki navigation still returns the OIDC login page.
8. Missing PKCE rejected as an OAuth error without a code; an unapproved redirect URI rejected before redirecting.
9. Clean deployment restart followed by a fresh browser login, TOTP, page readback and repeated negative checks.
10. Exact external-subject binding, cleared Keycloak required actions, one stored OTP credential and unchanged initialization journal verified independently of page text.

Protected `state.json` records the synthetic changed password/TOTP secret for repeat testing. Updates use a mode-0600 temporary file, fsync, atomic replacement and directory fsync. Never print this file. Enrollment pages are not screenshot into diagnostics. The harness never resets an already-enrolled identity; repeat runs require the prior private fixture directory.

## Evidence

Receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-knowledge-sso-fe641f27e3a2` — initial integrated login/authorization/restart proof on retained `knowledge-identity-r3`.
- `p0v3-knowledge-sso-ef8508ffd54e` — adds explicit TLS, PKCE, redirect and local-password bypass negatives.
- **`p0v3-knowledge-sso-71cfb7afe2c8`** — complete successful run from a newly prepared `knowledge-identity-r4`, including fresh required actions and restart/readback.
- **`p0v3-knowledge-sso-78e026eb2694`** — repeat against the enrolled identity; explicitly reports `requiredActionsPerformedThisRun:false` rather than claiming repeated enrollment.

- **`p0v3-knowledge-sso-b343e5e54d5c`** — native SSO/authorization/readback rerun after the expanded systemd lifecycle test; passed with the enrolled identity.

The persisted wiki screenshot from the fresh run was visually inspected. Its certificate SHA-256 is `9b80b17eff5c21c604e7b798700ca0e96d838f25a9e93afd5be41f9031768c85`.

Earlier names are stopped and retained: `knowledge-identity` failed on changed build-time path settings; `knowledge-identity-r2` exposed the upstream themes symlink requiring an explicitly prepared target directory; `knowledge-identity-r3` retains successful diagnostic fixtures. No failed initializer was silently replayed or existing input file replaced.

## Reproduce and supervision

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline

# A new name creates a new private fixture, not a mutation of an existing realm.
platform/build/install/p0-v3-platform/bin/p0-v3-platform runtime prepare-knowledge-identity \
  platform/release/downloaded-candidate-inventory.json NEW_PRIVATE_NAME
python3 platform/scripts/test-private-knowledge-sso.py --name NEW_PRIVATE_NAME

# Existing enrolled fixture; no password or TOTP reset:
python3 platform/scripts/test-private-knowledge-sso.py --name knowledge-identity-r4 \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-knowledge-sso-71cfb7afe2c8
```

`p0v3-private-knowledge-identity-r4.service` is enabled/active and pins controller tree `5cb5068f4519d49ef3646861305e831d8cd08cdb1318c9f6fcc9263476c6adb5`. Existing controller snapshots were not upgraded. Boot receipt **`p0v3-boot-130e3ec9b66f`** covers all sixteen deployments/36 daemons, unchanged container IDs/journals, new start times and no repeated initialization. The host was not rebooted.

## Still missing

Whole-stack SSO/agent authorization, production origin separation, public certificates/renewal, coordinated encrypted recovery of this composite's two databases/files/keys, updates/rollback, actual owner onboarding and independent browser/Android acceptance remain unfinished. Native restart persistence and the separate Firefly/identity restore results do not prove this composite's recovery.
