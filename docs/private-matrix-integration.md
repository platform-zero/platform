# Private Matrix integration — not full-stack acceptance

`SynapseRuntime.kt` and `MatrixRuntime.kt` now provision actual pinned PostgreSQL/Synapse and Element/Caddy deployments. The retained active deployment is **`matrix-r2`**, with four daemons on its own internal network and **no published ports**. The earlier standalone `synapse` deployment and failed `matrix` candidate are stopped; their data and diagnostics are retained.

This adds three running logical families (Synapse, Element and Caddy), not four: PostgreSQL was already represented. The complete private runtime now also includes [OpenSearch](private-search-integration.md), bringing the current total to **25 daemons across 22 of 39 selected families**. Full-stack clean-install/functional-restore acceptance remains **0/2**.

## Configuration and boundaries

- Synapse uses its own PostgreSQL database/role, UTF-8 encoding and C collation. Database and signing-key initialization are durable one-shots, not repeated startup scripts.
- PostgreSQL runs as UID 999, Synapse as 991, Element nginx as 101, and Caddy as 65532. Roots are read-only; state volumes and protected input files are explicit. The existing narrow Caddy `NET_BIND_SERVICE` allowance remains audited.
- Public signup, guests, federation, public room-directory access, URL previews and Synapse telemetry are disabled. The fixture server name is `matrix.private.invalid`.
- Element uses only `https://element:8443` and has custom homeservers, guest/third-party login and external integration services disabled. Nginx serves the pinned application/config and proxies Matrix API requests to Synapse.
- Caddy provides **internal-PKI HTTPS**, not public ACME. Its certificate state is persistent. No host trust store or DNS record is changed.
- The browser wrapper verifies the private CA and hostname using ordinary TLS verification, then pins that leaf certificate's exact SPKI in Chromium. It does not enable blanket ignore-HTTPS-errors. Fixture browser requests are restricted to the one Element HTTPS origin.
- All users, rooms, messages and attachments are synthetic. Credentials and the generated recovery key remain in protected receipt directories. No real owner's identity, recovery key, contacts or conversations are used.

## Executed journeys

`platform/scripts/test-persistent-synapse.py --name matrix-r2` proves:

1. Closed signup and unauthenticated denial; privileged shared-secret creation of **non-admin fixture users**.
2. Actual password login, private room invitation/join and denial of another user's unshared room.
3. Native transaction-ID deduplication, message readback, authenticated media upload/download and unauthenticated media denial.
4. Read-marker persistence and exact message/media readback after a clean database/application restart.

`platform/scripts/test-private-matrix-browser.py` creates a fresh native fixture and then executes `acceptance/scripts/MatrixBrowserProbe.java` using real Chromium inside the audited private Caddy network namespace. It proves:

1. Two native Element logins and visible persisted room history.
2. Cross-user browser messaging and actual attachment download through Element's authenticated-media service worker; SHA-256 matches the original generated payload.
3. Native recovery-key creation and confirmation for the receiving fixture user. The key is captured only into a mode-0600 file under the mode-0700 receipt directory, never printed.
4. Browser-to-browser Megolm encrypted message delivery. A separate server API inspection confirms encrypted event content and absence of the plaintext message.
5. **The exact incoming message session** exists in encrypted key backup before either original crypto device is closed. A nonzero overall backup count would not establish this.
6. Both original browser contexts are closed. A fresh context logs in, confirms its identity through Element's **Use recovery key** flow and visibly decrypts the historical encrypted message. No old browser storage, room-key file import, SDK restore shortcut or still-online original crypto device supplies the keys.

Successful full browser/key-recovery receipts:

- `p0v3-matrix-browser-2f45d58888ce`, native fixture `p0v3-synapse-26f5c37b1778`.
- **`p0v3-matrix-browser-929bf88ae378`**, native fixture `p0v3-synapse-3d50e723183f`; also includes the asynchronous-readiness regression check.

Receipts and `delivery.png`, `encrypted-delivery.png`, `recovered-delivery.png` are under `/mnt/media/p0-v3/image-acquisition-receipts/<receipt>/`. An earlier successful recovery run, `p0v3-matrix-browser-67c3c8bc560b`, still conservatively recorded key recovery as false before receipt fields were updated; it is not used as the explicit recovery receipt above.

**Encrypted room-key recovery is not an encrypted deployment restore.** These journeys recover a new client against the existing homeserver. They do not restore PostgreSQL, media, signing keys or Caddy state onto an isolated replacement server, nor prove off-host protection. The private recovery-key file itself is not an encrypted backup.

## Failures and corrections

- Caddy required an explicit `/usr/bin/caddy` entrypoint. The failed candidate was retained and a new immutable preparation name used.
- Podman's `HostConfig.CapAdd` is relative to its default capability set. Runtime audits now require exact final `EffectiveCaps` and `BoundingCaps`, including rejection of missing and extra capabilities, rather than treating `CapAdd` as the final set. All twelve active deployments passed re-audit.
- Native Element recovery setup first opens Encryption settings; the actual create-key action is inside that dialog. The confirmation input requires the displayed grouped key format. No real user's recovery policy was altered while discovering this flow.
- Readiness explicitly polls **resolved Boolean results**, not the existence/truthiness of a Promise. A browser regression returns asynchronous false before true and requires both evaluations. It is integration evidence, not unit coverage.
- Token retrieval uses the authenticated Matrix client's API; the probe does not assume the token is directly readable from a particular localStorage key. Tokens stay inside the fixture browser for same-origin API requests.
- Closing the old devices before confirmed key upload caused genuine historical-message decryption failures. Those failed receipts remain retained; the corrected test waits for the specific backed-up session.
- Repeated diagnostic password logins reached Synapse's real HTTP 429 rate limit. The server limit was not disabled. A scoped clean restart of the private deployment cleared the diagnostic run's in-memory limit; failed fixture receipts were retained. Repeated probes are not unlimited-load tests.

## Reproduction

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
INVENTORY=platform/release/downloaded-candidate-inventory.json

# Existing identical preparations are preserved; changed recipes require a new name.
$CLI runtime prepare-matrix "$INVENTORY" matrix-r2
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/matrix-r2.json
python3 platform/scripts/test-private-matrix-browser.py --name matrix-r2
```

The browser wrapper normally creates fresh fixture users. Do not reuse an already crypto-enrolled fixture as though it were first enrollment. Separate `runtime prepare-synapse INVENTORY NAME` supports the headless homeserver recipe.

Latest platform unit coverage: **2542/2742 lines, 92.71%**. Platform, Keykeeper and acceptance check gates pass, as do nine Python unit tests. Browser journeys are not counted as unit coverage or independent acceptance.

## Current source-only recovery safety changes

The standalone SFU encrypted-restore probe no longer resumes the source immediately
after export or from a `finally` block. It retains the source fence through target
functional checks, verifies unchanged source IDs/start timestamps/configuration, stops
the target and reads back its exact owned stopped containers **before** attempting
source resume. Timeout or failure retains explicit reconciliation requirements;
cleanup never grants resume authority. The successful path checks that the resumed
source does not contain the target-only ephemeral room. It no longer reports the old
simultaneous-network or divergent-running-room assertions after changing this order.
`matrix_recovery_safety.py` provides the fail-closed predicates with focused unit-test
source. No recovery probe was executed for this increment.

The Synapse, Matrix and LiveKit recipe objects now expose exact cold-restore projections
to the generation controller. These retire recognized initializers only and preserve
source signing keys, media, TLS state and configuration; Kopia still owns encrypted
storage and verification. A projection alone does not perform import or authorize boot.
The new delegated E2EE driver and private-origin qualified adapters are described in
[the identity source increment](private-matrix-identity.md#implementation-only-increment-runtime-unverified).
Native adapter registration and whole-cohort import integration are owner-applied
handoffs, not results of running these sources.

## Still missing

[A separate LiveKit SFU](private-rtc-integration.md) now passes native browser E2EE media, wrong-key denial and isolated encrypted configuration recovery. It is not integrated Matrix calling. MAS/OIDC integration, Keycloak owner/agent identity wiring, Matrix RTC authorizer/Element Call, official Android journeys, public Caddy HTTP-01/renewal, encrypted isolated homeserver restoration, coordinated release update/rollback and the remaining selected products are unfinished. [Private boot/shutdown units](private-boot-supervision.md) have since been installed and exercised; actual shared-host reboot recovery remains untested. These implementation-authored component probes do not supply independent approval or increment the required **0/2** full-stack cycles.
