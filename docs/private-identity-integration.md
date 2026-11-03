# Private identity integration: executed, not full-stack acceptance

Run `python3 platform/scripts/test-private-identity.py` from the workspace root. This creates and removes uniquely named containers in the dedicated rootful v3 store. It never binds a host port, touches production realms or modifies another Podman store. Database volumes, encrypted repositories and private diagnosis/recovery files remain under the v3 namespace. Plaintext logical-dump staging files are retained mode 0600 in mode-0700 receipt directories; these are not off-host backups.

## Actual software and startup fixes

- PostgreSQL 17.11 uses the acquired selected-platform digest and UID/GID 999:999. Initialization runs separately, creates a SCRAM-authenticated application role/database, and permits only the dedicated internal subnet in `pg_hba.conf`.
- Keycloak 26.8.1 is built offline from the pinned base in `images/keycloak/Containerfile`, with PostgreSQL, health and metrics enabled at build time. Optimized image ID: `345177fdf5102c9a0b017e1ef0eb409a0020c74ee4feaca82b1389758de041e1`; manifest digest: `sha256:ff264e6231948cf3b879dc3d08f89cbdd0dbef24c044ef1c4dcd71f571b77c1e`. The harness resolves the local build tag to its image ID and records that ID; this is not yet a signed release artifact.
- Containers have read-only roots, dropped capabilities, no-new-privileges and dedicated writable mounts/tmpfs. Keycloak runs as UID 1000. Imported fixture credentials are newly generated per run and never printed.
- The realm is an isolated test fixture: HTTP enabled, a loopback callback and password grants enabled for the denial check. It is **not** the production HTTPS realm or a recommended production client policy.

## Exercised behavior

1. Reject a direct token grant for the unenrolled fixture user.
2. Follow real Keycloak HTTP login forms with cookies, state and S256 PKCE.
3. Complete both mandatory actions, regardless of Keycloak's ordering: change the temporary password and enroll TOTP.
4. Verify no authorization callback occurs before both actions finish; exchange the resulting authorization code for tokens.
5. Check the database has no remaining required actions and exactly one OTP credential.
6. Take a consistent `pg_dump -Fc`, then mutate only the disposable source database to detect restore cross-contamination.
7. Store the dump in a new encrypted Kopia repository, verify 100% of files, restore it into a distinct export volume and byte-compare it with the original dump.
8. Restore that **Kopia-restored** dump into a new, initially empty PostgreSQL database. The source-only mutation must be absent from the restore and still present in the source.
9. Start a second Keycloak without realm import on a **different internal network**. The probe client is dual-attached with IP forwarding explicitly disabled; application servers are not dual-attached.
10. Verify the restored network cannot open the source Keycloak cluster port. Verify the restored identity still denies password-only grants and successfully logs in using the changed password, original TOTP secret and a new PKCE flow.

The default form driver uses Python HTTP requests and HTML parsing, not a browser engine. Its TOTP implementation has RFC 6238 SHA-1 vector unit tests.

## Actual Chromium journey

`python3 platform/scripts/test-private-identity.py --chromium` instead executes `acceptance/scripts/IdentityBrowserProbe.java` using the cached Playwright 1.55.0 and actual Chromium executable. It navigates the rendered Keycloak login page, changes the temporary password, verifies that the enrollment QR is visible, enters TOTP, completes the authorization callback and exchanges the PKCE code. After the encrypted restore, a new browser context logs in with the changed password and original TOTP secret. Password-only token grants are rejected in both cases.

The browser runs in the uniquely named probe client's network namespace via `nsenter`, dropping back to the invoking UID/GID before Java starts. No host port is published. The fixture client has forwarding disabled; source and restored application servers remain on separate internal networks. Chromium requests are limited to that run's Keycloak hostname and the loopback callback. Only disposable fixture credentials are used. Browser scratch directories are private and deliberately short to avoid Chromium's Unix-socket path-length limit.

Successful actual-browser runs: `p0v3-identity-25e54fbf6860` and `p0v3-identity-0f77b72e30a6`. The latter also captures the real login pages before any credentials are entered, plus post-authentication callback pages. Screenshot files and credential state are retained privately under each receipt directory. Neither run involved a public domain, Android, a token-verifier integration or an independent reviewer. They remain component evidence, not full-stack clean-install attempts.

## Failure found and corrected

An encrypted-restore run (`p0v3-identity-7df6d772aeec`) failed readiness because database-backed JGroups discovery records caused restored Keycloak to attempt joining the still-running source cluster. Merely using different database volumes was insufficient. Earlier same-network restore runs are not acceptable isolation evidence, even when login passed.

Separate internal networks corrected this. The successful encrypted run `p0v3-identity-8a0c4c3ba1a3` was followed by `p0v3-identity-438633b0683c`, which additionally checks source-cluster TCP isolation and disables client forwarding. The latter's restored snapshot object is `bf10f6ea7b57e6ce1dcd4c8c4fad7c3b`. Full private receipts are beneath `/mnt/media/p0-v3/image-acquisition-receipts/`. Failed runs remain `passed:false`.

**Full-stack clean-install acceptance is still 0/2.** These are directly executed component checks, not independently reviewed full-stack installs.
