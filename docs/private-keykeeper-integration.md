# Private Keykeeper identity integration

> Historical native fixture results below do not validate subsequent source changes. The explicit scoped identity/credential controller, canonical identity projection, recovery-unseal admission and Keykeeper owner-only rotation/retirement APIs are now implemented in source; see [identity and credential lifecycle](identity-credential-lifecycle.md). No new image/native journey or automatic daemon adoption is claimed. Existing non-renewing fixture leases and root custody remain unchanged.

`keykeeper-identity-r4` is a retained, private, native Keykeeper service with its own PostgreSQL, Keycloak 26.8.1 and OpenBao 2.7.2. Four serving containers and three journalled one-shots are supervised by `p0v3-private-keykeeper-identity-r4.service`. Existing identity and OpenBao deployments are unchanged.

At introduction, the fleet reached **78 declared running service containers in 26 enabled/active deployments**, covering **32/39 selected families plus OpenBao and Keykeeper**; see the [current inventory](private-runtime.md) for later additions. Keykeeper is additional to the selected 39; this does not increment that family count. **Full-stack acceptance remains 0/2.**

## Runtime and identity boundaries

- `KeykeeperRuntime.kt`, CLI `runtime prepare-keykeeper INVENTORY NEW_NAME`, and the audited private runtime create immutable-image, non-root, read-only-root containers with no added capabilities, no published ports and the dedicated AppArmor profile.
- Keycloak serves native TLS at `https://identity:8443`; Keykeeper serves native JVM TLS at `https://keeper:8443`; OpenBao serves `https://bao:8200`. No host trust-store changes or public certificate issuance occur.
- Keykeeper HTTP remains loopback-only by default. Direct non-loopback serving requires explicit OIDC mode, an exact HTTPS origin with explicit matching port, a certificate and matching RSA PKCS8 key. It never infers an origin from forwarded headers. A mismatched Host is rejected. TLS allows only 1.2/1.3.
- HTTPS browser cookies use Secure, HttpOnly, host-bound `__Host-` names, appropriate SameSite restrictions, and origin/CSRF checks. Access tokens stay server-side. OAuth state is single-use and bounded to five minutes; sessions last at most fifteen minutes. Expired attempts/sessions are pruned before capacity checks. App logout is not upstream global logout.
- A one-shot initializes a per-process, certificate-only PKCS12 trust store from the three private CAs. Its conventional `changeit` password is not a credential or encryption key. Serving processes do not receive recovery shares, root token or test-owner passwords.
- Browser login uses the public `keykeeper-human` client, exact callback `https://keeper:8443/auth/callback`, and S256 PKCE. Direct password grants and signup are disabled. Synthetic owner and outsider both complete temporary-password change and TOTP.
- The confidential machine client uses native client-credentials tokens. Keykeeper verifies signature/JWKS, issuer, audience, expiry, authorized client, admin-hardcoded HUMAN/AGENT claim, and exact allowed agent subject. Every request is introspected. An otherwise valid rogue-client token is denied.
- Keycloak 26.8.1 requires the introspecting client to be in the token audience ([upgrading guide](https://www.keycloak.org/docs/latest/upgrading/)). Two separate audience mappers provide the application audience and introspection-client audience. A single mapper chooses its client audience instead of its custom audience; neither audience check was disabled to make tests pass.
- OpenBao's KV-v2 mount requires CAS. The application token permits only its mount's metadata listing and data create/read/update; system mount administration is denied. This token can access all application records and is never distributed to agents. Human/agent record-level grants are enforced by Keykeeper.

## Actual journeys and evidence

`acceptance/scripts/KeykeeperIdentityBrowserProbe.java` and `platform/scripts/test-private-keykeeper.py` prove:

1. Native form login, password change, TOTP enrollment and later TOTP login; password alone reaches the OTP challenge without establishing a Keykeeper session. No human bearer token is injected.
2. Native UI create, reveal, edit, READ-only agent share and revoke. Values are synthetic only.
3. A real signed/introspected agent token reads the shared item through both API and the shipped CLI. Edit and onward share are denied; revoke removes access. The outsider's native browser login cannot read/list the owner's item.
4. Missing CSRF, anonymous/invalid tokens and a valid token from an unapproved client are denied. Private TLS is hostname/CA/leaf checked; default system trust rejects it. Browser SPKI allowances and allowed origins are scoped to this fixture.
5. Actual pinned systemd restart retains container IDs, changes start timestamps, preserves initialization journals and recovers the saved value and revoked permission after fresh browser login.
6. OpenBao starts **sealed** after restart. With identity operational, authenticated vault access returns 503 until the test operator explicitly unseals it. Neither the boot unit nor daemon has an automatic unseal hook. Transport readiness and active systemd state are **not operational vault availability**.
7. Native Keycloak SQL reads through its scoped application database account verify the exact owner/outsider IDs, one OTP credential each and no remaining required actions. Native Bao records verify the authenticated owner tuple, value and empty grant list after revocation.

Passing direct-restart receipt: `p0v3-keykeeper-id-a471c34cc337`. Stronger supervised receipts: `p0v3-keykeeper-id-d212536f9d86`, `p0v3-keykeeper-id-ca91bad7d48b` and latest **`p0v3-keykeeper-id-307d71a6b52f`**. The first direct journey created the record; repeats explicitly reuse it (`createdRecordThisRun:false`) rather than claiming a new creation. The fresh-login persisted-value screenshot was inspected.

- Manifest SHA256: `93b24cbc064966c610dece47dde29600c3e027a4c3303e88fb132bb86a14463d`
- Pinned controller: `605ab6c4f898e95fab15408f4a9d860e468354e51fc4ae2a3cfc79038334e209` (sixteenth retained snapshot)
- Image: `localhost/p0v3-keykeeper@sha256:b8f1a1fca2877f5bae467fb7b70ca21ef6c014925ef728e333b9ca504b92904d`
- Image ID: `29b7ef3937f29f039cc74038be1044ba44027d1341340f7c5d2ab02fefa41299`
- Offline/no-pull build receipt with retained source and distribution hashes: `p0v3-keykeeper-tls-build-5c893704f276`. This is not signed release provenance.

Repeat using the latest enrolled fixture, never an earlier bootstrap-only fixture:

```sh
python3 platform/scripts/test-private-keykeeper.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-keykeeper-id-307d71a6b52f \
  --supervised
```

Protected state stores passwords and TOTP material before confirmation, records the last used time step and waits rather than resetting counters. Ambiguous UI writes leave a durable pending marker and refuse automatic replay. Native requests do not retry writes. Optimized Python is rejected before imports/effects. A later exception makes the receipt fail; missing bootstrap completion requires manual reconciliation, not setup replay.

## Retained failures and limits

Original and r2 deployments remain stopped with failed receipts `18bad0628d04` and `9c95696c22b3`: missing introspection audience, then a single mapper replacing the application audience. r3 passed native machine bootstrap but is retained stopped, superseded by the hardened TLS/UI image. Bootstrap-only receipts deliberately have `passed:false`. Receipt `16a06ffc6e0b` retains a failed final SQL assertion: the probe incorrectly expected a bootstrap password in the serving PostgreSQL environment. The corrected query uses the scoped application account via private stdin, not newly exposed bootstrap credentials.

This is **not production custody or full-stack completion**. Root/Shamir recovery material is protected local fixture data, not split custody; root retirement, off-host escrow and coordinated identity/Bao/application restore are unfinished. The service token is a non-renewing, explicitly time-bounded 768-hour fixture lease; unattended renewal/rotation is not implemented, and expiry must fail closed rather than silently replacing credentials. Private CA issuing keys are discarded; renewal is unfinished. Sessions are process-local, not durable/HA. Public HTTPS, production owner onboarding, upstream global logout, production agent enrollment, durable tamper-resistant audit delivery, user-experience/security review, upgrades/rollback and two independent full-stack clean-install/restoration cycles remain outstanding. No host reboot or full 78-container fleet restart is claimed.

JVM gates pass; Keykeeper unit-only coverage is **576/617 lines (93.35%)**. The platform's separate gate remains above 90%, and 50 Python unit tests pass. Unit tests use fake/local transports and public disposable TLS material, never count native journeys in the coverage numerator, and do not substitute for independent acceptance.
