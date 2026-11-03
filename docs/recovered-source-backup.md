# Private recovered-source backup continuation and runtime-lock admission

## Current status correction

**Qualification remains 0/2.** The legacy lock failure described below was subsequently followed by a successful isolated-store chain **before** the current unit-only implementation phase. Preparation receipt `p0v3-store-v2-3e8fe7c26117` established the canonical-v2 file-lock store without renumbering the host-shared pool. Historical source `q-d50f3ef29556` restored to `q-025b9ab96555`; its installed timer captured `cap-d7c9a23bc8b8`, and the newer snapshot restored to `q-9cca7c8f2b5e` with retained boundary/oracle checks. Import-kill scope `q-ab45313642fd` passed its scoped isolation checks. Tamper scope `q-02d58ff35358` has no completed receipt and remains unresolved.

These are seven-product, artifact-bound engineering results, not full-stack cycles or validation of subsequent source changes. The earlier failed scopes/history remain failures. Project-created fixtures are not permanently protected assets; no runtime cleanup/reconciliation is authorized during the [current implementation-only phase](implementation-only.md). Whole-release recovery, weekly functional restore, retention and promotion remain unfinished.

## Earlier increment and retained legacy failure

The earlier increment below implemented backup of a running private Kopia-restored canonical cohort, exercised that scheduled backup natively, and closed a newly discovered runtime-capacity admission gap. It did not promote a restore target into public/site authority.

## Implemented continuation contract

`FoundationRestore` now compiles daemon-only definitions idempotently for the canonical `canonical-core` / `forgejo` / `sql-cache` cohort. A source that already carries Kopia recovery lineage must match those exact compiled daemon-only definitions and exact remaining runtime inputs. Archived initializers, bootstrap-only credentials and retired migration declarations cannot be reintroduced. Legacy capsule-restored sources are not silently opted into this path.

A running recovered source can use the existing `generation-kopia-backup` command and installed daily scheduler only when:

- Its immutable bundle contains supported Kopia lineage, no inherited site ownership and no assembly/clean-install relabelling.
- The original `restore-import` intent/outcome is complete and correctly bound.
- `recovery.source.json`, `recovery.check.json`, parent bundle identity, member fingerprints and retired-initializer declarations agree with that lineage.
- Every member has the expected import intent/result and both native import markers bind the exact receipt digest and runtime fingerprint.
- Members are running/unfenced, with no permanent isolation history, uncertain snapshot or incomplete prior backup.

Import proof is rechecked before capture, while all frozen member locks are held, and before member resume. The runtime additionally refuses incomplete import markers when claiming/releasing a backup lease. A successful backup resumes only its own source and does not create initialization ledgers for daemon-only imports. Clean-install staging remains refused.

Restoration from the newer snapshot preserves private lineage without inheriting site ownership. Controller records, ancestry, custody and source-oracle receipts remain retained dependencies; this is not standalone disaster bootstrap or complete promoted-generation authority rebinding.

## Native execution and limits

Evidence package: **`p0v3-recovery-chain-engineering-e887bb3339d3`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

On the **pre-lock-admission controller artifact**:

1. `p0v3-generation-2cffe8ddbd07` passed fresh seven-product installation/workflows, installed daily timer capture/resume, duplicate-slot refusal, local failure alerting and retirement. Snapshot: `cap-65276a429202` / native `094aee5da534d8190d472866eeb82f4e`.
2. `p0v3-generation-restore-9803621bca2e` failed in the client oracle: a new snapshot-row variable collided with existing notification/SQLite row variables. The source/repository were unchanged and the failed target was retired. The receipt remains failed. The correction uses a separate `snapshot_rows` variable and adds a unit that executes the actual readback function with fake native responses.
3. Fresh `p0v3-generation-restore-d50f3ef29556` passed historical restoration/readback/restart, then ran its **own installed daily timer** without receiving site authority. A synthetic row written before this new backup survived source resume. Import markers were unchanged, initialization ledgers remained absent, and clean staging was still refused. Its new snapshot is `cap-deafad8221c3` / native `2fc5352a03a908c87bfa47dcc3367f98`. A further row was written after capture to provide an exclusion oracle. The test timer was suspended/disabled before source retirement.
4. `p0v3-generation-restore-70aa48bb87fd` attempted to restore that newer snapshot. Native verification and the core member import completed, but allocation stopped at the next member when the dedicated Podman lock pool was exhausted. Controller isolation and linked stop-only reconciliation retained all three target fences. No target daemon was started and the source/repository were unchanged. This target remains failed and is never replayed.

Consequently, the newer point has native capture/verification evidence but **not successful full-cohort functional restoration**. Its before/after-write expectations are retained, not declared verified. The two snapshots are not two full-stack qualification cycles or two functionally verified release points.

## Newly enforced object-lock capacity

Podman 5.4.2 reports `host.freeLocks = 0`. The dedicated store contains **1,227 containers and 821 volumes: 2,048 persistent lock-using objects**, including retained stopped objects. Stopping a container does not free its object lock. RAM and disk admission alone cannot prevent this failure.

`RuntimeLockBudget.kt` now requires a numeric free-lock observation from the exact dedicated graph/run roots. It accounts for:

- Declared target containers and volumes, including initialization processes during clean staging.
- Two retained native Kopia observe/restore workers for restoration, or conservatively three workers for capture/repository initialization.
- **Four additional transient helper locks**.

Stage admission rejects insufficient locks before its action intent or native resource creation; restore admission rejects before its target namespace is created. Routine backup checks before claiming/stopping members; capture rechecks before allocating a capture namespace. Missing or foreign capacity observations fail closed. Memory/disk safety floors are unchanged. No store is filled deliberately to test this guard.

The **final controller artifact** passed native refusal-only probe `p0v3-lock-admission-b3870211962d`: the same valid newer snapshot was submitted for a fresh target, the CLI returned typed `InsufficientRuntimeLocks`, and no target generation/runtime namespace was created. Container and volume inventories were unchanged. This is capacity-refusal evidence, not a passing restore.

The final guard changes controller bytes. Earlier native continuation results remain bound to their earlier artifact; they are **not transferred into a final-artifact recovery-chain pass**.

### Safe continuation boundary

The observed rootful shared-memory pool is `/dev/shm/libpod_lock`. Installed Podman documentation requires renumbering after changing `num_locks` and warns about concurrent Podman processes. No in-place renumbering, shared configuration change, retained-object deletion, protected restart, workload eviction or default-store fallback was performed.

Next engineering work must establish a demonstrably isolated capacity remedy—for example an explicitly bound new store epoch with independent locking, verified artifact transfer and non-overlapping network/resource ownership—before further allocating live generations. Existing stores, fixtures, failed scopes, fences, repositories and credentials must remain intact. This is an engineering dependency, not a request for human approval.

## Validation

| Repository | Passed unit tests | Unit line coverage |
|---|---:|---:|
| Platform | 252; 4 opt-in integration skips | 5,891/6,451 = 91.32% |
| Acceptance | 46 | 807/820 = 98.41% |
| Keykeeper | 26 | 576/617 = 93.35% |
| Worklane | 142 | 11,842/13,112 = 90.31% |

**133 Python tests passed.** All seven final controller files matched a complete rebuild. Unit tests cover the full modelled capture/restore/rebackup/re-restore chain, exact daemon compatibility, missing/foreign import history, bootstrap/site-authority refusal, retired-source refusal and lock-capacity denial before namespaces or leases. Modelled chain success is explicitly not native chain success.

Protected fleet: **33 deployments / 109 declared daemons** unchanged. All prior **141 fence hashes** remain unchanged; **153 fences** are retained. No public activation, RSS publication, shared-host reboot or historical-fence release occurred.

### Repository/custody bootstrap actuator — subsequent source-only increment

`KopiaGenerationStore.bootstrapRepository(repository, custody, operation, originalReceipt, expectedCustodySha256)` can recover the controller's binding to an **existing** repository using externally anchored original receipt and custody hashes. It never creates a repository, rotates credentials, rewrites a snapshot ID/pin, manufactures a functional restore result or grants promotion. Pinned networkless read-only Kopia workers observe the exact original manifest/root identity and perform full-file verification. Only then are bootstrap completion and repository binding written. An uncertain attempt retains its durable intent and refuses replay; custody bytes are unchanged. Snapshot staging now verifies copied staging bytes as well as original input bytes before upload.

This actuator reconstructs repository control state only. It does not invent missing generation staging/import journals or claim complete standalone controller disaster recovery. A restore still needs the authenticated original bundle and exact imported-generation lineage. `KopiaRetentionAuthority`/`retain` signatures are unchanged; scheduling and production reference census are supplied by the separate maintenance controller. No native operation was performed for this increment.

Complete controller disaster bootstrap, public promotion, remaining canonical provider/client closure and the two complete unchanged-candidate cycles remain unfinished; consult current controller status for separately implemented weekly/reference-safe maintenance.
