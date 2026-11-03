# Private ERPNext integration

`erpnext-r7` adds native ERPNext 15.124.3 integration. At introduction this brought coverage to **29/39 selected families plus OpenBao, 61 running daemons in 22 supervised deployments**; see [the current runtime inventory](private-runtime.md) for subsequent additions. This is private component coverage, not completion of ERPNext's production journeys or the whole release. **Full-stack acceptance remains 0/2.**

## Runtime

`ErpNextRuntime.kt` prepares an isolated MariaDB instance, authenticated Valkey cache and persistent queue, Frappe/Gunicorn backend, Socket.IO, worker, paused scheduler, and private TLS nginx frontend. All eight daemons use pinned images, non-root users, read-only roots, dropped capabilities, the dedicated AppArmor profile, internal networking and no host port bindings.

Four durable one-shots initialize MariaDB, initialize site configuration, run the native Frappe installer with the ERPNext app, and retire the temporary database installer account. Repeating application startup does not rerun these jobs. Native database checks verify that the installer account and remote root accounts are absent. Bootstrap administrator/database credentials are not mounted by serving Frappe processes; native site configuration retains the application's database credential as required by Frappe.

The configuration initializer mounts the new sites volume at an empty alternate path to avoid Podman's image-directory copy-up. The native installer then runs in the normal bench/sites layout. Narrow writable sites, bench-config/lock and log volumes support native behaviour without writable application roots. The baked assets link is created once; the upstream entrypoint's repeated asset deletion/relinking is not used.

The scheduler process is present but `pause_scheduler=1` intentionally prevents unattended scheduled jobs. No SMTP transport or bank connection is configured, no real business data is imported, and no external job delivery is claimed. Developer mode, server scripts and telemetry are disabled. Queue functionality is tested separately with an actual native asynchronous customer-count job executed as the fixture owner.

## Verified journeys

- Native browser login; initial company/chart-of-accounts/system-manager setup through the supported setup-wizard HTTP API. This is **not browser completion of every setup-wizard step**, real-owner enrollment, Keycloak SSO or TOTP onboarding.
- Actual Customer quick-entry/full-form authoring and Save in the browser.
- Native REST creation of a non-stock synthetic service and a **draft** quotation, two units at AUD 12.34, with server calculation and browser readback of AUD 24.68. No invoice submission, ledger posting, payment, stock movement, tax correctness or real transaction is claimed.
- Fresh login and the same business-record readback after restart, with no initializer replay. Per-phase action records distinguish initial setup/creation from repeat readback.
- CSRF-less mutation denial, anonymous quotation-read denial, and an authenticated low-privilege Website User's quotation-read denial. That native ERP role is not an additional Portal deployment.
- Actual authenticated Socket.IO connection and native `doc_update` delivery after a synthetic quotation-terms edit. The native callback uses the explicit internal backend address, not an untrusted private HTTPS loopback.
- Foreign Socket.IO Origin rejection using a separate Engine.IO polling connection over verified private TLS. Supplied Origins are preserved. Only absent Origin headers receive the fixed private-origin fallback needed for native same-origin polling; foreign origins are not rewritten into trusted ones.
- Private CA/hostname/leaf checks before Chromium launch and rejection by the ordinary system trust store. Browser HTTP requests are restricted to the private ERP origin and downloads are disabled. The final quotation screenshot was inspected.
- Actual pinned systemd restart: unchanged container IDs, new daemon start times, continued native browser/API/realtime/queue operation, and unchanged initializer journal.

The image lacks an init binary. The reviewed `runtime/process-init.py` resource forwards termination to the child process group for Node/bench services, preserves exit status, reaps exited children and does not restart processes. Unit tests cover normal exit, native signal handlers, unhandled signal status, invalid invocation and optimized-Python refusal. **This is not queue quiescence or a crash watchdog**; the lifecycle probes finish their queued job before stopping services.

## Evidence

Protected receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-erp-5b914d7845a1`: r5 native company/customer/quotation/queue and clean restart, before realtime verification.
- `p0v3-erp-fba0841f664b`: r5 repeat with authenticated Website User denial and explicit per-phase action records.
- `p0v3-erp-ec8b07b26ac5`: fresh r7 setup and record creation, realtime connection and restart; first-phase creation flags are true and second-phase flags false.
- `p0v3-erp-7d727a14a339`: r7 repeat adding native realtime delivery and foreign-Origin denial.
- `p0v3-erp-eb61f4c8ec33`: actual eight-daemon systemd restart and all denial/delivery/queue/readback checks.
- **`p0v3-erp-d1ffc7c2c5b8`**: latest supervised repeat, additionally verifying the native scheduler reports inactive and telemetry is disabled.

Manifest SHA-256: `25589cc2922ee9c2bd54eb06b33f56cb153163d7d2ceca4316c802535c933e6a`.
Certificate SHA-256: `a2d2479feb7b0fdfa270461284160cd57c889c350de29790696c5163c28b1fac`.
Controller tree: `afa06bafd78ad227bbc75e8d32c8aa7d1afe839a1fceda89285a6096aa2faa9e` (eleventh pinned snapshot).

This unit was restarted separately. The latest complete fleet restart still predates the newer Mastodon, delegated Matrix, SearXNG and ERP units; no 61-daemon fleet restart or shared-host reboot is claimed.

## Retained failures

`erpnext`, `erpnext-r2`, `erpnext-r3`, `erpnext-r4`, `erpnext-r5` and `erpnext-r6` are stopped and retained, with their data and diagnostic evidence. They were not silently replaced or their failed initializers replayed.

- Initial volume copy-up triggered the empty-state guard.
- An alternate installer working directory exposed the native `/logs` assumption; configuration and native installation were split into separate jobs.
- A missing writable bench-config lock directory caused installation to exit nonzero after schema creation; that partially initialized instance was retained rather than relabelled successful.
- r4's Node/scheduler PID-1 shutdown required SIGKILL (137). Its native business checks did not constitute a passing lifecycle receipt. The signal-forwarding revision subsequently exited cleanly.
- Realtime testing exposed the missing internal callback address and then absent Origin on same-origin polling. r7 fixes both without disabling TLS verification or overwriting supplied foreign Origins.
- Browser Quick Entry/Full Form transitions required waiting for the modal to close and targeting the visible page action rather than its hidden Save button.

Failed receipts remain failed, including `p0v3-erp-24e4b39bb215` (r4 lifecycle), `p0v3-erp-f4ed28732dcc` (r5 realtime), and the r6 realtime attempts. The fail-closed receipt finalizer prevents an earlier sub-pass from surviving a later failure.

## Reproduction

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-erpnext.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-erp-d1ffc7c2c5b8 \
  --supervised
```

Preparation: `runtime prepare-erpnext INVENTORY NEW_NAME`. Never omit `--fixture` when reusing an already configured site. Passwords and fixture state stay in owner-only files; never print them. Test setup uses synthetic identities, not human consent to ERPNext terms or production accounting configuration.

## Implementation-only recovery source (2026-11-03; runtime-unverified)

`ErpNextRecovery` now provides guarded preparation of a fresh `erprestore-*` target. It accepts only the exact compiled ERP recipe, preserves the six state volumes, and replaces site/database provisioning with source-bound import-marker checks and native read-only SQL checks. It never invokes site installation, schema migration, user creation or installer deletion. Serving MariaDB no longer mounts root/installer environment inputs in this target. A separate one-shot verifies the scoped database grants and that the original installer credential cannot authenticate; transport failure is not accepted as authentication denial.

The read-only `runtime/erp-restore-check.py` validates the restored site identity, application list, scheduler/server-script/telemetry safeguards including site-local overrides, and all sites/config/log markers. It permits only the exact compiled image asset symlink and rejects arbitrary links, hardlinks and special entries. This does not relax the archive importer's separate link policy. Cache and queue startup require their own completion marker; MariaDB requires its restored schema/storage before startup.

`BusinessApplicationRecovery.coldRestoreSpec("erpnext", compiled)` separately supplies the whole-generation daemon-only projection after authenticated cold import. It retires all four initializer processes and lifts their provider-readiness dependencies onto serving processes. Neither API captures, encrypts or imports data; the coordinated Kopia importer and exact archived/compiler equality remain mandatory. Shared CLI registration is supplied to the coordinator as an integration patch, not assumed applied here.

Focused Kotlin and Python unit tests are written and requested from the coordinator. No build, service operation or recovery journey was executed by this implementation delegate. All earlier evidence above predates this source and does not validate it.

## Remaining

End-to-end coordinated MariaDB/sites/files/config/queue encrypted recovery, safe schema upgrades and rollback, actual posted accounting/inventory/purchasing journeys, attachments/PDFs, role-specific business authorization, production SSO/onboarding, scheduled work and mail, public HTTPS/renewal, Android, off-host recovery and independent acceptance remain unfinished. The existing regular-file-only restore adapters must not be applied blindly to ERPNext's asset links and multi-process state.
