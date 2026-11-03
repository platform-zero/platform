# Private BookStack integration

**Actual component evidence; not public activation or independent full-stack acceptance. Verified full-stack count remains 0/2.**

`bookstack-r3` runs immutable BookStack v26.09.2 (LinuxServer `ls294`) with separate MariaDB 10.11.19, PHP-FPM 8.5 and nginx. All processes are non-root, capability-free, read-only-root, resource-bounded and confined by the dedicated AppArmor profile/internal network. There are no host port bindings or unrelated host changes.

## Implementation

- `BookStackRuntime.kt` and `runtime prepare-bookstack` prepare dedicated database/role credentials, application encryption key and synthetic administrator password under protected immutable inputs.
- MariaDB bootstrap, file preparation and migrations/admin setup are durably journalled one-shots.
- The upstream supported `bookstack:create-admin --initial` command replaces the default administrator **before web startup**. It is invoked through Laravel with the protected environment password rather than a password-bearing command line. Its result and absence of `admin@admin.com` are checked. This is a synthetic administrator, not owner Keycloak onboarding.
- PHP/nginx run as UID/GID 911. nginx receives only its config and uploads mount—not database credentials, application configuration or administrator password. The administrator password is absent from the normal PHP environment.
- Native `STORAGE_TYPE=local_secure_restricted` is configured; no attachment-upload authorization journey is claimed yet. Registration defaults are disabled. Mail uses the array transport. Public HTTPS and SSO are not configured.
- Readiness requests the actual Laravel `/login` route, not just a static asset.

Retained earlier deployments:

- `bookstack` failed because creating a nested uploads mount before seeding left a parent directory root-owned. It is stopped; its failed initializer was not replayed.
- `bookstack-r2` initialized successfully after the long migration completed; it is stopped and retained. `bookstack-r3` uses the explicit restricted-storage configuration rather than changing the earlier prepared inputs.

The migration exposed a 120-second **wait observer** timeout even though the initialization container continued and exited successfully. The runtime now permits five bounded read-only wait observations for a long initializer. It never restarts/replays that initializer on timeout. Exhausting the bound retains the running job and durable journal for reconciliation; unit tests cover both continuation and exhaustion.

## Actual native browser journey

`acceptance/scripts/BookStackBrowserProbe.java` and `platform/scripts/test-private-bookstack-browser.py` use the cached pinned Chromium/Playwright, disable browser downloads, restrict traffic to the fixture origin, audit the deployment and enter only its network namespace while dropping host UID/GID.

The browser:

1. Proves the upstream default `admin@admin.com` / `password` login is denied.
2. Logs in with the generated synthetic administrator credential.
3. Creates a unique book, chapter and page using native controls and the actual TinyMCE editable iframe.
4. Reads the saved page content and finds it through native header search.
5. Proves a fresh anonymous browser is redirected to login and does not receive the private page content.
6. After a clean stop/start, logs in from a fresh browser, repeats page readback/search/anonymous denial, and confirms the initialization journal was unchanged.

Passed receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-wiki-browser-9a910f833498` — creation and restart/readback
- **`p0v3-wiki-browser-5d2ff4f3fbec`** — additionally verifies native search before and after restart

Screenshots/logs are private. The persisted-page screenshot was visually inspected. Failed diagnostic attempts and their synthetic drafts remain retained. No existing owner documents were imported or modified.

## Boot supervision and reproduction

The enabled/active unit is `p0v3-private-bookstack-r3.service`. It pins controller tree `89061fb049f867b3a28c62e1209328ef9a6931ad2fdd487829a6c106688d12e5`. Earlier units were not silently upgraded.

Expanded boot receipt **`p0v3-boot-d8dd2b3a360e`** covers all fifteen deployments/31 daemons: same container IDs, new start times, no repeated initializers and unchanged journals. The shared host was not rebooted; this is not a crash watchdog.

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
platform/build/install/p0-v3-platform/bin/p0-v3-platform runtime prepare-bookstack \
  platform/release/downloaded-candidate-inventory.json bookstack-r3
python3 platform/scripts/test-private-bookstack-browser.py
```

## Separate native SSO integration

[The `knowledge-identity-r4` composite](private-knowledge-sso.md) now proves native Keycloak-to-BookStack OIDC/PKCE, required password change/TOTP, exact subject binding and unprovisioned-user/local-password denial. It uses separate databases and has not changed this standalone deployment's credentials or authentication mode. Production origin separation and whole-stack SSO remain unfinished.

## Remaining release work

Encrypted coordinated MariaDB/configuration/files recovery, functional attachment authorization, multi-user permissions, owner SSO, production mail/public HTTPS, transactional updates and independent acceptance remain unfinished. The storage tree contains upstream links into the configuration volume; do not blindly apply the financial regular-file-only archive adapter to it. Restart persistence is not backup restoration.
