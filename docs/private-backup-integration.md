# Native private Kopia repository service

**Later integration:** [Kopia-backed canonical generation recovery](kopia-generation-recovery.md) now uses separate pinned networkless workers and fresh repositories to back up and restore the seven-product cohort. [Routine backup lifecycle](routine-kopia-backup.md) now also quiesces/captures/resumes a new canonical source under operation-bound leases, with native interrupted-controller isolation and post-snapshot database exclusion evidence. Schedules and full-release coverage remain unfinished. The historical long-lived fixture described below remains unchanged; its synthetic source was not replaced.

`backup` is an immutable, non-root, private Kopia **0.23.1** deployment with one guarded repository initializer and one serving container. It mounts only its own repository/configuration volumes and an immutable **synthetic 72-byte fixture**, not host files, other deployments, logs or owner content. Native HTTPS UI/API authentication and CSRF checks remain enabled. RPC access, snapshot actions, automatic image/version checks and persistent file logging are disabled. Kopia's own repository maintenance is not a whole-stack backup schedule.

This brings private component coverage to **34/39 selected families plus OpenBao and Keykeeper**, with **81 declared running service containers in 28 supervised deployments**. This is not a completed installation: **full-stack acceptance remains 0/2**.

## Implementation and evidence

- `src/main/kotlin/net/datamancy/platform/KopiaRuntime.kt`: CLI `runtime prepare-backup INVENTORY [NAME]`, private random repository/admin/control credentials, distinct initialization environment, private single-origin PKI, guarded empty-volume initialization, pinned processes and resource bounds. Readiness checks repository access; the native probe separately verifies HTTPS availability and functionality.
- Image: `docker.io/kopia/kopia@sha256:83d8bc7bce313dd8b2c17771b5f3f804e18e79ad7d7cc6bc994ff5872374794d`.
- Manifest SHA256: `b0dc7d91e90ba90e3a946c99eb9f28a50428818a55a07b05267fc46dc3f724b1`.
- `scripts/test-private-backup.py`: exact CA/hostname/leaf checking before sending Basic credentials, bounded responses, native session/CSRF exchange, anonymous/invalid-password/missing-CSRF denial, and native control-user denial at the UI API.
- Direct passing receipt: `p0v3-backup-bbb0cbbf1ff3`, explicitly reusing a previously created snapshot.
- **Fresh native snapshot + supervised restart pass: `p0v3-backup-1dfba839cf09`**, explicitly `createdSnapshotThisRun:true`.
- Latest supervised repeat: **`p0v3-backup-54e2de30265b`**, explicitly reusing that snapshot; missing CSRF is rejected on both GET and POST.
- Snapshot manifest `89d722e5cd209155c6e606ce98b421ed`; restored file object `f32c066b820a1d281820bd0ddeadd3b5`; restored SHA256 `537ba76149f3c08865288d74fed715da5e43ba937cb35015b8e5ab2b96674aee`.
- Controller tree `d5b5c06a49b9b5f0cc61f3f54148a488b92efa6f0edd753e79596ea2e75954b3` (eighteenth retained snapshot), unit `p0v3-private-backup.service` enabled/active.

The serving API creates/schedules a real native snapshot. A separate **networkless** Kopia process mounts the encrypted repository **read-only**, with neither server configuration nor the original source file, verifies 100% of snapshot files, restores into a newly labelled volume, and compares the exact plaintext bytes. An independent configuration with an incorrect repository password is rejected. The server then actually restarts with the same container identity, a changed start timestamp, unchanged initializer journal and unchanged snapshot records. This is native API/CLI evidence, not a Chromium journey or independent review.

## Repeat safely

```sh
python3 platform/scripts/test-private-backup.py --supervised
```

The default repeat observes existing snapshots and restores them into a new isolated export. It does not silently submit another snapshot. The explicit `--create-snapshot` operation was used once for the fresh passing receipt: its durable exclusive intent remains under `/mnt/media/p0-v3/backup-probe-state/`. **Do not remove or replace that intent to repeat a potentially ambiguous upload.** A second invocation with that flag refuses replay. Intent files are private, bounded, fsynced before HTTP and outside the immutable runtime input directory. All receipts/credentials/diagnostics remain protected.

## Retained failures and reconciliation

The first probe (`p0v3-backup-db4b94497d24`) successfully created a directory-source snapshot but incorrectly queried the snapshot listing without its native source filter; it timed out and remains failed. Native listing requires the exact `host`, `userName` and `path` filter. A second probe (`p0v3-backup-5ee9c520c422`) was correctly rejected by the runtime because the probe had placed its action intent among immutable runtime inputs. The intent was explicitly moved, **without changing its bytes**, to `backup-probe-state/backup-original-directory.intent`; SHA256 `0f56e1c1542605142e418d5e8d3d03bdb61e1680a9b8b28f829e7a9e7663a9ff`. The runtime's strict input-directory audit was not weakened. A further retained failure (`p0v3-backup-2d7c560cc145`) occurred before the wrong-password check could run because the isolated client's cache environment had not been set; its client now uses a private temporary cache. None of these failed receipts is reported as a completed pass.

## Validation

Final read-only fleet audit: 28 enabled/active units, exactly 81 running declared containers, no published ports or active maintenance records. The metrics recovery target remains stopped and not boot-enabled. Platform, Keykeeper and acceptance JVM checks pass; all 58 Python unit tests pass. Platform JVM unit-only coverage is **3522/3818 lines (92.25%)**. No full-fleet restart was performed.

## Boundaries

The administrator is a generated private **Basic-auth fixture**, not real owner password/TOTP onboarding or production SSO. UI/control credentials are not delegated agent credentials. The server has its repository encryption password; production custody, credential rotation, least-privilege clients and off-host key escrow remain unfinished. No complete repository/server-disaster recovery, remote storage, whole-stack capture schedule, application write/egress freeze, rollback, public HTTPS renewal, host reboot or crash watchdog is claimed. Existing component recovery harnesses still have their own repositories; they were not silently migrated into this server.
