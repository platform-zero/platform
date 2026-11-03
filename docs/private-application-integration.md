# Persistent application integration and encrypted Forgejo restore

This extends [the private Kotlin runtime](private-runtime.md). It is actual execution against downloaded, pinned images, **not a full-stack release or independent acceptance approval**. Public ports, external mail, federation and outward posting remain disabled.

## Applications now running

- **Forgejo 17.0.1**, deployment `forgejo-r2`: non-root, read-only root, persistent SQLite/repositories, generated bootstrap credentials, registration/SSH/mail/federation/Actions disabled. A journalled one-shot performs initial migrations and creates the private bootstrap administrator. Normal restarts never recreate that account.
- **Planka 2.2.1**, deployment `planka-r3`: its own PostgreSQL database/role, persistent uploads, explicit one-time database migrations/seeding, no implicit reseeding on daemon restart. Outgoing HTTP is directed to a closed local proxy port in addition to the internal-only network. The private instance has explicit **synthetic-test-only** terms; the probe checks their exact content and SHA-256 before acknowledging them. It does not accept the upstream default end-user template for the owner. Production terms, owner onboarding and SSO are not implemented. This candidate uses upstream's Fair Use License, not an assertion of OSI-open-source licensing.
- **MariaDB 10.11.19 and Memcached 1.6.45**, deployment `sql-cache`: non-root MariaDB initialization/bootstrap is a durable one-shot, root is password protected and restricted to its local socket, anonymous accounts and nonlocal root records are removed. Memcached has UDP disabled and intentionally does not persist cache entries.

Their Kotlin recipes are `ForgejoRuntime.kt`, `PlankaRuntime.kt` and `SqlCacheRuntime.kt`. Private input directories/manifests remain beneath `/mnt/media/p0-v3/runtime-deployments/`. No credentials are printed by preparation. The original unsuccessful `forgejo`, `planka` and `planka-r2` deployments are stopped/exited and their diagnostic state retained.

## Real bugs caught

- Forgejo requires its HS256 JWT signing key to decode to **32 bytes**. A 64-character hex string decoded as base64 produces 48 bytes and made Forgejo attempt to rewrite its read-only configuration. Preparation now generates raw URL-safe base64 of 32 random bytes, with a regression assertion.
- Planka's production logger defaults to `/app/logs`, which is not writable under a read-only root. Its file sink now writes to `/tmp/planka.log`; console logging remains available.
- Java's default HTTP/2 upgrade behavior failed the Planka readiness request while HTTP/1.1 clients succeeded. Native private HTTP readiness now explicitly uses HTTP/1.1; the same retained deployment then passed.
- Planka rejects hyphenated login usernames even though its seed code accepted one. New preparation uses `p0v3_bootstrap`; probes authenticate with the configured bootstrap email.
- Both web frontends use implicit form-submit buttons. Chromium journeys submit through an actual Enter key action rather than assuming an explicit `type=submit` attribute.

## Executed journeys

### Forgejo

```sh
python3 platform/scripts/test-persistent-forgejo.py --name forgejo-r2
```

Receipt `p0v3-forgejo-e6881498308f` proves:

1. A generated **non-admin** user creates a private repository.
2. Actual Git CLI commit/push succeeds; credentials are supplied through the process environment, not URL/command-line arguments.
3. An issue and comment are created through the application API.
4. Clean stop/restart preserves user login, Git commit/content, issue and comment.

The test isolates client Git configuration and disables client hooks; it neither changes the operator's Git configuration nor uses an unrelated repository.

### Planka

```sh
python3 platform/scripts/test-persistent-planka.py --name planka-r3
```

Receipt `p0v3-planka-14f20617128f` proves project → board → active/closed lists → card → comment → card move, followed by clean restart, a new login and exact application-data readback. The card remains in the Done list with its comment.

### MariaDB and Memcached

```sh
python3 platform/scripts/test-persistent-sql-cache.py
```

Receipt `p0v3-sql-cache-eb0ed65a95df` verifies passwordless root rejection, removal of anonymous/nonlocal root records, an InnoDB committed row surviving restart, a rolled-back row remaining absent, and actual Memcached set/get protocol operations before and after restart. The cache is correctly cold after restart; it is not presented as durable user data.

## Encrypted, isolated Forgejo restoration

```sh
python3 platform/scripts/test-forgejo-encrypted-restore.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-forgejo-e6881498308f
```

Latest successful receipt: **`p0v3-forgejo-restore-afc71d5ea5da`**; snapshot root **`k28a5f4d07d999840bac6373715757f6f`**. The earlier run `p0v3-forgejo-restore-a3c2bbd497fc` also passed; the later run additionally encrypts and checks the source manifest.

The real sequence is:

1. Audit the source runtime and require its Forgejo image to match the immutable inventory selection.
2. Cleanly stop the application and hold its POSIX lock (interoperable with Java's runtime lock) throughout the snapshot. Check that its container identity/start timestamp remain unchanged and that it stays stopped.
3. Snapshot the application volume, private configuration/credentials and source manifest into a password-protected Kopia repository. Helpers have no network and run as UID 1000 with dropped capabilities.
4. Verify **100% of snapshot files**, then export the snapshot to a fresh volume. Exported manifest bytes must exactly match the source manifest.
5. Resume the source and make a **source-only Git write after the snapshot**.
6. Recover configuration/credentials from the Kopia export. `runtime prepare-forgejo-restore` creates a distinct restore recipe without database/admin initialization; `runtime provision-private` allocates owned staging resources without creating or starting processes.
7. Copy application bytes from the **Kopia export**, not the source, into the initially empty target volume. Compare the recovered trees before starting the restored application. The restore check rejects missing data or an incomplete-copy marker.
8. Start on a different internal network. A TCP probe from the restore to the source application must fail.
9. Log in as the original regular user, read back Git content and database-backed issues, prove the source-only change is absent, make a restore-only Git write, and prove the source is unchanged.
10. Stop/quarantine the restored runtime. Keep its volumes, encrypted repository, private recovery material and receipts.

This is **not an off-host backup**. Kopia passwords, private recovered configuration and plaintext export volumes remain locally protected for recovery/diagnostics. The restore-specific recipe and staging primitive are not a completed generic `ReleaseEffects` backup/update/rollback backend.

## Actual Chromium, including after restoration

`acceptance/scripts/PrivateApplicationBrowserProbe.java` runs pinned Playwright 1.55.0 with real Chromium. The Python wrapper enters only the audited application network namespace, then drops to the invoking UID/GID. The browser maps only the fixture hostname, blocks other origins, and uses a fresh context. It performs native form login and visible application readback, not injected API authentication.

Successful browser receipts:

| Application | Deployment | Receipt |
|---|---|---|
| Forgejo | `forgejo-r2` | `p0v3-browser-a92b3e2eec8e` |
| Planka | `planka-r3` | `p0v3-browser-b9ed5dcedcad` |
| Restored Forgejo, first restore | `frestore-a3c2bbd497fc` | `p0v3-browser-38880cc7d3f7` |
| Restored Forgejo, manifest-bound restore | `frestore-afc71d5ea5da` | `p0v3-browser-8acf989596d9` |

```sh
python3 platform/scripts/test-private-application-browser.py forgejo \
  --deployment frestore-afc71d5ea5da \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-forgejo-e6881498308f \
  --stop-after

python3 platform/scripts/test-private-application-browser.py planka \
  --deployment planka-r3 \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-planka-14f20617128f
```

Private screenshots were inspected: the restored Forgejo issue/comment and Planka's card/comment/Done state are visibly rendered. These remain **component** receipts. Planka/MariaDB encrypted restore, all-product public-domain browser/Android journeys, owner SSO, the remaining families and full-stack release operations are still unfinished. **Full-stack acceptance remains 0/2.**
