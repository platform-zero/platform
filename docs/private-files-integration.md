# Private Seafile integration

`seafile-r4` adds native Seafile CE 13.0.28 file storage, browser upload and authenticated sharing. At introduction, private component coverage reached **31/39 selected families plus OpenBao, 67 declared long-running service containers in 24 supervised deployments**; see [the current runtime inventory](private-runtime.md) for subsequent additions. Full-stack acceptance remains **0/2**.

## Runtime

`SeafileRuntime.kt` and `runtime prepare-seafile INVENTORY NEW_NAME` configure:

- MariaDB with three application databases and a database-scoped account. Remote root and anonymous database accounts are removed; root authentication remains local.
- Authenticated, deliberately ephemeral Valkey cache.
- Native `seaf-server` with a shared private RPC volume.
- Seahub/Gunicorn and the native Go fileserver in one supervised failure group. They retain the upstream loopback coupling: Seahub's internal fileserver address is fixed to localhost. This is **two native servers in one declared backend container**, not two independently supervised runtime entries.
- Native nginx with private TLS, image-baked static assets, and explicit Seahub/fileserver routes.

All five serving containers use pinned images, non-root users, dropped capabilities, read-only roots, the dedicated AppArmor profile, private networking and no published ports. No host files, workspaces or physical media are mounted.

Three durable one-shots initialize MariaDB, import the pinned upstream's shipped schemas into verified-empty application databases, and create synthetic identities through native `ccnet_api`. The schema importer follows the native installer's statement splitting without importing its root-writing setup module. It does not invent database tables or insert fake application records. Partial initialization is retained, not replayed. Serving processes do not receive `users.json` or the fixture account passwords.

The C server uses an explicit private ccnet directory and the previously tested signal-forwarding init resource. `runtime/seafile-web.py` coordinates its two native children, stops the sibling if either exits, propagates failure, and fails shutdown if SIGKILL becomes necessary. It **does not restart children** and is not a crash watchdog or write-freeze mechanism. Four unit tests cover group termination, child exit, failed startup, optimized-Python refusal and forced shutdown.

Signup and web-based configuration changes are disabled. Mail uses Django's dummy backend. SeaDoc, AI, WebDAV and ONLYOFFICE are disabled. No automatic upgrade, garbage-collection wrapper, host-log acquisition or owner-data import is run. Application data/configuration volumes remain writable as needed by the native application; this is not tamper-proof policy storage.

## Verified journeys

`platform/scripts/test-private-seafile.py` and `acceptance/scripts/SeafileBrowserProbe.java` exercise:

1. Native password authentication for synthetic owner, reader and outsider; anonymous and invalid-token library API denial. Native SQL checks verify absent anonymous/remote-root accounts, successful application authentication and denied application access to the system privilege table.
2. Native library creation and a **37,888-byte synthetic binary upload**, followed by byte-for-byte native fileserver download. SHA-256: `092fb58f19330f08d3c966d2df26bada37057d1e696896452915cf48d1807bfb`.
3. Reader download-link and upload denial before sharing; read-only user sharing; reader download success but upload denial; outsider denial.
4. Actual Chromium form login, native library navigation, native **Upload Files** menu/file chooser and upload of `browser.txt`. The probe waits for the successful upload response to finish and for the library-table entry—not merely the upload-progress label. Independent API download verifies the exact browser-uploaded bytes.
5. Actual pinned systemd restart: same container IDs, new start times and unchanged initializer journal. Fresh browser login/listing and native downloads verify persisted binary/text content and sharing permissions; the reader remains unable to upload.
6. Native unsharing through the dedicated shared-library endpoint. The reader loses listing/download-link access while the owner retains the original bytes. No library is deleted to simulate revocation.

Private CA, hostname and exact leaf are checked; the ordinary system trust store rejects the private certificate. Chromium uses a scoped SPKI allowance, private-origin request restrictions, no proxy, disabled browser downloads, and the already pinned browser binary. Passwords are passed privately, never injected as browser tokens or printed. The final screenshot was inspected.

Seafile's generated download URLs are bearer capabilities. This does **not** prove immediate revocation of an already issued download URL, public/password-protected share-link policy, or encrypted-library recovery. The tested library is not an E2EE library. A service restart is not a backup restore.

## Evidence

Protected receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-files-9985fb4c8ca6`: native API upload/download, sharing denial/revocation and clean restart.
- `p0v3-files-a2ea9cf0cd16`: adds actual browser login/upload/readback.
- `p0v3-files-bf5018497e7d`: actual pinned systemd restart, completed browser-upload observation and expanded permission denial.
- **`p0v3-files-4655e56c349c`**: latest supervised component pass, additionally verifying native database privilege boundaries.

Manifest SHA-256: `475f08c85b7618dd87847debcb88cae6e0de590afd7f7424aa9b542755454f7a`.
Certificate SHA-256: `45acaeccee467a642c2a79997c410cd9397c5088f6d1991c00db4cea45140d76`.
Controller tree: `8ce06500bd74ee4579cd8c399872efe4668614076167c7a4b3f3b6c24f239029`, the thirteenth pinned snapshot.

This unit was exercised separately. No new complete-fleet restart, shared-host reboot, independent review or full-stack acceptance is claimed.

## Coordinated encrypted recovery

`SeafileRecovery.kt`, CLI `runtime prepare-seafile-restore INVENTORY RECOVERED_DIRECTORY NEW_NAME`, and `platform/scripts/test-seafile-encrypted-restore.py` now implement and exercise the exact CE recipe's coordinated recovery. This is not the single-daemon generic restore adapter.

The source's pinned unit is disabled/stopped before entering a durable, generation/input-bound backup fence. Only the already initialized MariaDB dependency closure is staged. With the runtime lock held, every other declared container is confirmed stopped. One native `mariadb-dump --single-transaction` captures **ccnet_db, seafile_db and seahub_db**; the stopped state volume supplies block/object storage, application configuration and native file state. All protected deployment inputs, including signing/TLS/database credentials, are included. No system privilege database is imported. A fresh MariaDB bootstrap creates the database-scoped service account before importing application databases.

Capture rejects non-regular/non-directory tar members (including symlinks and sockets), unsafe paths and excessive size/count. The state tar is bounded at 128 MiB for this synthetic fixture; this is not a large-production-data backup implementation. The source tree and immutable inputs are rechecked before releasing the fence. Ephemeral Valkey cache and the separate RPC socket volume are deliberately **recreated**, not archived. Active browser sessions are not a recovery claim.

Native Kopia encrypts the protected capture, verifies 100% of snapshot files, rejects an incorrect repository password using a fresh configuration, and exports into a separate directory. Every exported file and the archive tree must match the capture's checksums. Only exported bytes are imported into a new deployment with its own volumes and internal network. Target import is also fenced and locked; all three application databases must be empty before SQL import. The adapter replaces schema/user seeding with read-only table/identity checks. It never creates replacement users or regenerates credentials to make recovery pass.

Missing/incomplete, foreign and symlinked completion records are denied. Both file and database completion records are checked independently; a dangling in-progress symlink is tested while both completion records are otherwise valid. These records bind the source manifest, not a unique snapshot: the harness's exported manifest/hash verification provides the snapshot-byte binding. Ordinary apply is independently rejected under both source and target maintenance fences.

The actual recovered product journeys verify:

- Native authentication and exact binary/browser-uploaded text downloads.
- Recovered read-only reader sharing and outsider/upload denial.
- Fresh Chromium login and native library listing before and after restart, without injected browser tokens. The recovered screenshot was inspected.
- A pre-snapshot marker file recovers; the current run's post-snapshot source file does not.
- Target-only native uploads remain absent from the source; source-only files remain absent from the target, including after both restart.
- Same container IDs/new start timestamps across target stop/start and actual source systemd restart, with unchanged initializer journals.
- TCP denial from the target namespace to source HTTPS, Seahub, fileserver, MariaDB and cache ports.

**Security reconciliation remains necessary before production cutover.** The probe deliberately revokes the source reader's share after capture. The isolated restored snapshot retains the earlier read-only grant, proving point-in-time permission recovery—not claiming that old grants are safe to republish. The target is stopped after verification, never publicly routed or enabled at boot. Source sharing is left revoked. Neither source changes nor application jobs are replayed outward.

Latest receipt: **`p0v3-files-restore-6d7fcdbf253c`**. Snapshot `k8ebe76798f275f1b5409a92f58e9e77b`; exported manifest SHA-256 `b3cc35275a77f6a1d9fc174c5de1411dcd776284e267cce0926baddef4c8f2cb`. Earlier component passes `457b8f800962` and `e2ce7b39c8d3` are retained. None is independent or full-stack acceptance. Repositories, exports and diagnostics are local protected fixture data, **not off-host escrow**.

```sh
python3 platform/scripts/test-seafile-encrypted-restore.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-files-4655e56c349c
```

Each run adds unique synthetic files to the existing fixture library; it never overwrites or retries an ambiguous upload. Interrupted operations retain fenced/partial state rather than replaying initializers. Unknown fence generations are never released; safe stop is attempted before cleanup reports failure. Seven client unit tests cover optimized-Python refusal before imports, private-origin/header restrictions, exact-leaf/TLS rejection and connection cleanup, response-size bounds, native-token validation, no upload retry and read-before-compensation for uncertain share cleanup. Cleanup observes the reader's native library list before deciding whether to revoke the fixture share; it does not blindly retry an uncertain DELETE.

## Retained failures

`seafile`, `seafile-r2` and `seafile-r3` are stopped with their data and diagnostics retained:

- Importing the native setup module tried to create `/opt/seafile/conf` on the immutable root. The subsequent recipe uses the same shipped schema files with an empty-database guard instead.
- The C server defaulted to an unwritable home ccnet directory; an explicit `-c /state/ccnet` and matching environment fixed this.
- Native API workflows passed on r3, but PID-1 signal handling forced exit 137. Receipt `p0v3-files-06ccce97f752` remains failed. r4 adds signal forwarding and passed actual stop/start.

Failed browser receipts also remain failed. They exposed an unnecessary Playwright browser-download attempt (blocked by the private network), the native welcome overlay, incorrect upload controls, and a progress-label/readiness race. The final probe disables driver downloads, dismisses the native overlay, uses the actual file chooser and waits for completed server upload and library listing. No counters were cleared and no ambiguous file upload was automatically retried; each subsequent run created a new synthetic fixture.

## Reproduction and unfinished scope

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-seafile.py --supervised
```

Each run creates a new synthetic library, verifies it and revokes only its own reader share. Existing fixtures are retained. Credentials remain in protected deployment inputs; optimized Python is refused before effects.

A [separate ONLYOFFICE composite](private-office-integration.md) now passes native DOCX editing, authenticated callbacks and supervised persistence. It does not alter this deployment or inherit this adapter's recovery claim. Broader office-format/active-session/composite recovery, whole-release/off-host recovery and security-state reconciliation, application upgrades/rollback, production Keycloak onboarding, public HTTPS/renewal, Android/desktop synchronization, quota/version/conflict/large-file journeys, public-share policy, off-host recovery and independent acceptance remain unfinished. Synthetic local accounts are not real-owner password-change/TOTP enrollment. The single-daemon restore adapter is not applicable to this multi-process deployment.
