# Private Firefly III integration

**Actual component evidence, not a complete financial-service release. Full-stack acceptance remains 0/2.**

`firefly-r2` now runs immutable Firefly III 6.7.9 with separate PostgreSQL 17.11, PHP-FPM and nginx. There are no published ports, real bank connections, bank imports, public routes or outbound mail. All financial records are synthetic.

## Deployment

`FireflyRuntime.kt` and `runtime prepare-firefly` implement:

- Dedicated PostgreSQL database and role; durable database, storage and cache volumes.
- Journalled database creation, file preparation, Laravel migrations/seeding, Firefly upgrades, Passport keys and configuration cache.
- Separate non-root PHP-FPM/nginx processes (UID/GID 33), read-only roots, dropped capabilities, dedicated AppArmor profile, internal network and bounded resources.
- Generated protected application/database keys and fixture credentials; environment inputs are immutable on repeated preparation.
- Production application mode with debug disabled. The upstream **testing-only** `system:create-first-user` command is not used. The synthetic first account was registered through the native browser UI, not inserted directly into application tables.
- Native PHP execution through nginx readiness rather than a static-file-only health response.

The initial `firefly` deployment failed when nginx tried its default read-only log/cache paths. It is stopped and retained. `firefly-r2` explicitly places nginx logs and temporary request directories under `/tmp`.

Boot/shutdown supervision is installed and enabled. Its root-owned controller tree is `7c5ba70e11b4fa39ff04f4739731ac98cd453742d397db42494d17a4f8b81b67`; previous deployment units were not silently upgraded.

## Actual financial browser workflow

`acceptance/scripts/FireflyBrowserProbe.java`, driven by `platform/scripts/test-private-firefly-browser.py`, runs a fresh Chromium in the audited nginx network namespace, drops host UID/GID, uses a fresh temporary profile, restricts traffic to the fixture origin and never prints the fixture password.

The test performs:

1. Anonymous financial API access denied with HTTP 401.
2. Native synthetic-user login (and native registration/onboarding when the application is initially empty).
3. Native creation of a unique EUR asset account with a €100.00 opening balance.
4. Actual account autocomplete selection and native withdrawal creation for €12.34 to a unique synthetic merchant, with rules and webhooks disabled for the submission.
5. Visible transaction readback plus authenticated native API checks for the exact source, destination, type and decimal amount. API readback supplies the session's native CSRF header; a bare fetch correctly receives 401.
6. Exact €87.66 account balance checked in both the API and actual UI.
7. Clean deployment stop/start, unchanged initialization journal, and a **fresh browser and fresh login** repeating the transaction and balance readback.

Two UI readiness problems were exposed rather than treated as application passes: native Shepherd guidance could steal focus during form fills, and transaction inputs appeared before autocomplete listeners were installed. The probe now dismisses guidance using native controls, checks all financial form values before submitting, waits for the actual combobox initialization and obtains its menu from `aria-controls`. Failed synthetic fixtures and diagnostics are retained. No SDK state injection or fabricated financial response is used.

Passed receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-firefly-browser-e1c199f2af5f`
- **`p0v3-firefly-browser-ca4e6f06740a`** — includes dynamic autocomplete-menu lookup

Each contains protected logs, `transaction.png`, `account.png`, `persisted-account.png` and `receipt.json`. The recovered-by-restart screenshot was visually inspected. This is **restart persistence**, not backup restoration.

The expanded systemd lifecycle receipt **`p0v3-boot-4ca5250adfa9`** covers all fourteen deployments/28 daemons, including Firefly: same container IDs, new start times and unchanged initialization journals. The shared host was not rebooted.

## Reproduce

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
platform/build/install/p0-v3-platform/bin/p0-v3-platform runtime prepare-firefly \
  platform/release/downloaded-candidate-inventory.json firefly-r2
python3 platform/scripts/test-private-firefly-browser.py
```

Reusing prepared inputs is idempotent; changing a recipe requires a new deployment name rather than silently replacing existing inputs. Browser runs add only synthetic financial fixtures. Optimized Python is rejected before effects because the harness uses safety assertions.

## Encrypted, isolated functional recovery — now exercised

`FireflyRecovery.kt`, `runtime prepare-firefly-restore`, and `scripts/test-firefly-encrypted-restore.py` now implement and exercise recovery of the database **and** application files/keys/configuration:

1. Create a real native financial browser fixture. Verify the source's installed boot unit binds the exact manifest, then disable/stop only that unit before maintenance.
2. Enter a [durable maintenance fence](private-maintenance.md) permitting only `postgres` staging; verify normal apply is denied. Use `runtime stage-private MANIFEST postgres` to start only PostgreSQL and its already-initialized dependency closure. All other processes must be stopped/absent. Hold the deployment lock while capturing a consistent custom-format `pg_dump`, both file volumes, protected inputs, source manifest and fixture metadata.
3. Create an encrypted Kopia snapshot, verify 100% of files, export into a new private directory, and check every exported file against a manifest included in the snapshot. Recheck frozen container identity/start state and the initialization journal, stop staged PostgreSQL and release the matching fence generation before resuming the source unit.
4. Prepare a new, separately networked target using **only recovered inputs**. Stage a fresh database/role, run actual `pg_restore`, and restore file volumes under UID 33. Reject unsafe archive entries (links, traversal, duplicate paths, special files or privileged modes); compare restored contents and modes before clearing incomplete markers.
5. Do not rerun Laravel migrations, seeds, file initialization or Passport key generation. The restore recipe instead checks completion markers, recovered keys and restored user data before starting PHP/nginx. Markers are operational gates, not cryptographic archive proof.
6. Verify the original transaction and exact €87.66 balance through a fresh native browser and native authenticated API. Create new native financial records on the restored service, including a restart/readback. Prove source-after-snapshot records are absent in the target, target writes are absent in the source, and target-to-source HTTP TCP access is blocked.
7. Stop the restored deployment after verification. The original source boot unit is enabled/active again. No shared-host reboot occurs.

Passed receipts:

- `p0v3-finance-restore-9ee1ab9af4c9`, snapshot `k9343b534111ac9c9ee6b49b9f4c0c34e`
- `p0v3-finance-restore-3b0b19f2cf3d`, snapshot `k63cd155c90456bf0c1d2b7864ba21cca`
- **`p0v3-finance-restore-c1ab069467dc`**, snapshot `kacd20637d3411b75f5db2dc2206cfb70`, with durable source fencing, native restored readback `p0v3-firefly-browser-b1e0185b3517` and new restored writes `p0v3-firefly-browser-e3ac185e7d8d`; target stopped

The second run's restored browser receipt is `p0v3-firefly-browser-2254825a0f3f`; its recovered-balance screenshot was visually inspected. Both target deployments remain stopped. Encrypted repositories and protected plaintext exports/recovery credentials are retained locally, **not off-host**.

```sh
python3 platform/scripts/test-firefly-encrypted-restore.py
```

The browser wrapper also supports `--name RESTORED_NAME --verify-fixture PRIVATE_FIXTURE_DIRECTORY`. Verification-only mode explicitly does not claim that it performed a restart. These two component recovery runs do **not** increment full-stack acceptance.

## Remaining release work

No off-host recovery, cross-user authorization journey, owner Keycloak SSO, production onboarding, recurring-job execution, public HTTPS, transactional upgrade/rollback, independent acceptance or complete financial-product release is claimed. The array mailer and isolated private network are staging boundaries, not production mail configuration. The recovery adapter currently accepts the exact supported Firefly source recipe, not arbitrary PostgreSQL applications or an already-modified restore recipe. Whole-stack coordination and schedules remain unfinished.
