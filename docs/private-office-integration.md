# Private Seafile / ONLYOFFICE integration

## Implementation-only update (not new runtime evidence)

The callback guard now binds replay identity to the canonical authenticated callback body rather than JWT bytes. Reissuing a token with a different lifetime cannot replay that same operation. Double-encoded traversal, backslashes, control bytes and non-string download URLs are rejected. A boolean native `error:false` is not accepted as integer `error:0`, and a failed durable completion returns 503 rather than reporting a successful save acknowledgement.

**Ledger upgrade is deliberately fail-closed:** existing `office-callback:` token-keyed rows cannot be safely mapped to semantic operations without retained bodies. Any such row prevents callback admission; no automatic deletion, migration or uncertain-save replay is provided. Existing deployments must remain unchanged until explicit offline reconciliation/migration is implemented and authorized. Fresh ledgers use `office-callback-v2:` keys. The earlier native receipts below do not validate these changed bytes.

`SeafileRuntime` and `OfficeRuntime` expose provider-less `applicationSpec`/`applicationInputs` for canonical composition. The caller must provision the exact scoped MariaDB databases/principal and cache endpoint; removing embedded providers alone is not central-provider/TLS integration. Their `coldRestoreSpec` functions retire known bootstrap jobs, preserve data/cache/ledger volumes, and remove root bootstrap credentials. D03 must verify exact compiler equality and the complete cold import before selecting these projections. Memory-first unsaved editor sessions remain ephemeral.

The new `acceptance/runners/seafile-native.py` performs actual native API upload/download, reader sharing/revocation and outsider denial with invocation-bound fresh intent and source-oracle readback. It does not claim desktop sync conflict, browser/mobile coverage or controller restore isolation. Unsupported required assertions are false. No native operation was executed during this source update.

`files-office-r7` adds native ONLYOFFICE CE **10.0.0, build 169** editing to a separate Seafile CE 13.0.28 deployment. It does not modify the existing `seafile-r4` data or claim that its restore adapter supports this composite.

At this milestone, private coverage reached **32/39 selected families plus OpenBao, 74 declared running service containers in 25 supervised deployments**; see the [current runtime inventory](private-runtime.md) for later additions. These are component counts, not completed production services. **Full-stack acceptance remains 0/2.**

## Native runtime and immutable assets

`OfficeRuntime.kt` and `runtime prepare-office INVENTORY NEW_NAME` compose the existing five-container private Seafile recipe with:

- Native ONLYOFFICE DocService and its **embedded converter** in one container.
- Native nginx serving image-baked editor assets and signed cache downloads over `https://office:8443`.
- A journalled office-state initializer and a durable callback ledger initialized with the Seafile schema.

All seven serving containers use immutable image digests, non-root users, read-only roots, dropped capabilities, the dedicated AppArmor profile, explicit volumes and private networking. No host ports, physical media, existing workspaces or real owner documents are exposed. The Seafile backend already contains its loopback-coupled Seahub/Go-fileserver pair; declared container counts are not an OS-process census.

**CE 10 uses the upstream memory-first runtime.** The separate converter binary explicitly reports that conversion is embedded, and this CE image does not use the external PostgreSQL/RabbitMQ path. The corrected recipe removes those unused dependencies rather than changing license/edition checks. [Upstream memory-first implementation](https://github.com/ONLYOFFICE/server/commit/b65db6cf1594d5875be4c0c47697f9f4bbb4d5eb) and [CE changelog](https://helpcenter.onlyoffice.com/docs/installation/docs-community-changelog.aspx) provide context; actual runtime behavior and native edits were tested.

`images/onlyoffice/Containerfile` builds offline from the acquired platform-pinned upstream image. It invokes the shipped font/theme generation and API cache-template generation once at build time. Serving processes do not modify installed software. Generated `api.js`, `AllFonts.js` and `font_selection.bin` are checked and hashed. Upstream branding, binaries and license notices are retained; `images/onlyoffice/LICENSE.upstream` preserves the packaged copyright/license text. No licensed feature or limit is bypassed.

Current immutable build:

- Base: `docker.io/onlyoffice/documentserver@sha256:bff1a9fd46f2b79ada776fd0447c3fccf66cbf44c1996ec9316efa8ac4ee3fd5`.
- Runtime: `localhost/p0v3-onlyoffice@sha256:48011079cf6ea448bf71cd88cd8f6e750750638163a3fa0f9ef541e625ede0cf`.
- Image ID: `f6e0ea5288868f314c57a0dd67af7a2d32955ed67876e889df36858be359acf8`.
- Build evidence: `p0v3-office-build-4bc54d566526`.

This is an engineering candidate, not a signed release artifact or a bit-for-bit reproducible-build claim. Earlier image `fonts-1` remains retained. Use a new build tag for changed inputs; do not overwrite the recorded tag.

## Callback and download security

Inspection of the pinned Seafile callback found that setting `ONLYOFFICE_JWT_SECRET` alone does **not** authenticate that native save handler. The composite therefore mounts `runtime/office-callback-guard.py` as explicit Django middleware before the unchanged native callback.

The guard:

1. Requires HS256 authentication, canonical base64url, unique JSON fields, integer issue/expiry times and a bounded lifetime.
2. Requires **`operation: callback`**, rejecting editor/conversion token scope. CE 10 emits a purpose-bound body token even when `outbox.inBody=false`; that native format is supported, as is the purpose-bound header envelope.
3. Binds the signature to the callback body, including JSON value types. Boolean/numeric substitutions are rejected rather than relying on Python's permissive dictionary equality.
4. Restricts saved-file/history URLs to private HTTPS `office:8443/cache/files/`, rejects traversal and never disables certificate validation. Browser and server use separate, scoped private trust; no host trust-store changes are made.
5. Durably records `pending` in a separate SQLite ledger **before** invoking the native handler. A successful native result is recorded `done`. Completed duplicates receive the same success response without replay; pending/uncertain duplicates return 409, including after restart. Missing/unusable ledger state fails closed, never silently recreates the ledger. Pending records remain for explicit reconciliation.

The ledger is application-owned state, not tamper-proof storage against a compromised backend. It does not make two databases one transaction. A native save committed just before ledger completion fails must remain pending rather than being replayed. Native callback retries are disabled in this fixture; failed saves must not be mistaken for success. Expired tokens are rejected before ledger lookup.

Seafile's callback logger is disabled to avoid logging bearer download URLs. Native DocService diagnostics may contain tokens on failed callbacks and remain protected fixture data; never publish those logs. Office download links retain nginx's native `secure_link` signature/expiry checks. Unsigned conversion and unsigned cached-file requests are denied. AI proxying is disabled; the browser/network fixture permits no public providers or plugin-store activity. Production plugin/egress policy still needs review.

## Actual product journeys

`platform/scripts/test-private-office.py` and `acceptance/scripts/OfficeBrowserProbe.java` verify:

- Native password login, library creation and upload of a generated minimal DOCX. No host document is used.
- Native Seafile document navigation into the ONLYOFFICE iframe, visible editor controls and actual canvas keyboard editing. No injected browser tokens or editor-model mutation is used.
- Native save/close callbacks, followed by independent Seafile download. The resulting ZIP's `word/document.xml` contains the unique text entered with the keyboard, and document bytes changed.
- A separate native reader login opens the same document with read-only controls. Attempted keyboard editing/save does not change the downloaded bytes. Outsider access is denied; later unsharing denies new Seafile reader access. Immediate invalidation of already issued bearer URLs or an open editor session is not claimed.
- Private CA/hostname/exact-leaf verification and normal-system-trust refusal for both origins.
- Unsigned callback, wrong-purpose token, changed body, JSON type substitution and forbidden callback-download origin denial. No metadata service request is performed.
- A signed synthetic status callback with an unknown fixture key returns the native error result and remains pending. Its replay is denied both before and after restart. This is an uncertainty test, not a fake successful document save.
- Actual pinned systemd restart of all seven serving containers: same IDs, changed start times, unchanged initializer journal, and exact saved document/reader permission readback afterward.

Owner-edit and reader-view screenshots were inspected. JVM checks and 45 Python unit tests pass; the platform JVM unit-only gate reports 3369/3652 lines (92.25%). The final live audit found exactly 25 enabled/active units and 74 running containers, zero published ports, no active maintenance records and all earlier office revisions stopped. Native browser probes use exact SPKI allowances, bounded private origins, a pinned Chromium binary, no proxy, and disabled downloads. Optimized Python is rejected before effects. No ambiguous browser edit/upload is retried; subsequent runs create new synthetic libraries.

## Evidence and supervision

Latest passing receipt: **`p0v3-office-a7db57627181`** under `/mnt/media/p0-v3/image-acquisition-receipts/`.

- Manifest SHA-256: `93008d6bec29862245deee446dfab9e51e5d3bdd02691277c5820d49d64e714e`.
- Unit: `p0v3-private-files-office-r7.service`.
- Pinned controller tree: `f84b69eb195a932f469309bb8eff74164001db3efe7d36db9e37438cf7dba25a` (fifteenth snapshot).
- Earlier r6 supervised receipt `p0v3-office-0b6ec17c7272` remains valid historical evidence for its tested scope. Its unit/controller `8e31c2823cab244a8f0001b8da0ebd77b99fdf2ddafca7030edcd43d43f61036` is retained but disabled/stopped; r7 tightens type-exact body binding.
- `p0v3-office-afcc7cebb724` passed the earlier unsupervised lifecycle; r5 receipt `p0v3-office-039409d11b09` proved the first native edit/save, before durable ledger hardening.

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-office.py --supervised
```

This adds a separately tested seven-container restart, **not** a new 74-container fleet restart or shared-host reboot.

## Retained revisions and limits

`files-office` and r2–r6 remain stopped, with data/diagnostics retained:

- Original recipe incorrectly assumed the external database/broker runtime and enabled inbound IP filtering, making health checks return 403. The native converter's memory-runtime notice exposed the compatibility mismatch. RabbitMQ 4.2.9 was acquired/pinned as a candidate and remains unused by the corrected CE recipe; it is not claimed as another completed family.
- r2: nginx interpreted an unbraced URI followed by the signing secret as one variable. r3 fixes the variable boundary.
- r3 / failed receipt `p0v3-office-1e72dc9232ae`: missing generated `api.js`; the upstream ships `api.js.tpl`. Immutable build `fonts-2` runs the shipped template generator.
- r4 / `p0v3-office-c1e076246d36`: the guard initially expected a header/wrapped token, but native CE 10 emits a purpose-bound body token. r5 supports the verified native envelope without disabling JWT checks.
- `p0v3-office-7d0adfeee4cf`: the probe clicked the canvas under its event overlay. It now waits for the loading mask to disappear and clicks the native event canvas, without forcing through overlays.
- `p0v3-office-72780ce4040a`: the probe expected a literal “Viewing” label; the native read-only UI instead exposes File/View/Plugins without editing controls.
- `p0v3-office-69c152a32a2a`: the legacy conversion endpoint returned XML when no JSON response was requested. The probe now explicitly requests JSON and requires the native invalid-token error.

**Memory-first does not mean crash-durable editing.** Only documents already saved back to Seafile are covered by persistence checks. Unsaved sessions, active-job draining, crash/power-loss behavior, coordinated composite encrypted recovery, upgrades/rollback, public HTTPS/renewal, production Keycloak onboarding, spreadsheets/presentations, coauthoring/conflict journeys, mobile clients and independent acceptance remain unfinished. PID-1 forwarding and systemd lifecycle integration are not queue quiescence or watchdogs. The standalone Seafile recovery adapter deliberately rejects this composite rather than discarding office state or replaying initializers.
