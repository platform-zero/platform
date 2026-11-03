# Coordinated daily backup and weekly functional restore

## Current implementation-only increment (2026-11-03)

New source implements `WeeklyRestoreSchedule`, `NativeWeeklyRestoreBackend`, `WeeklyFunctionalVerifier`, `RecoveryReferences` and `RecoveryReferenceOperations`. No native scheduler, restore, retention, service or installation command was run for this increment; older evidence below does not validate this changed source.

- Daily schedule remains **03:00 UTC**. Weekly units render **Sunday 04:00 UTC**, persistent latest-slot-only catch-up, deterministic operation/target IDs, eight-hour budget, no automatic restart or timeout resume. Unknown/failed prior slots block every later slot. History is bounded without deleting evidence.
- Weekly production flow uses the held-source runtime API: durable source leases/quiescence/Kopia capture; fresh reviewed `WHOLE_RELEASE` cold projection/import; start only initializer-free imported targets; execute pinned semantic readback adapters; isolate target; observe isolation; resume source only through `resumeHeldSourceAfterIsolation`, which keeps target locks held throughout source resume. Unsupported recipes fail closed rather than being relabelled whole-release recovery.
- An immutable functional plan binds the exact candidate, every original ownership capability, program hashes, exact assertions and independently retained original fixture oracles. Root-owned HEADLESS/NATIVE readback adapters use the Acceptance semantic protocol; health checks or successful exits alone are insufficient. Backup scheduler adapters cannot recursively invoke themselves. Missing/tampered adapter coverage is checked before source maintenance. This does **not** replace official-client/browser qualification.
- `RecoveryReferences` is a private append-only hash-linked reference ledger. Bootstrap conservatively protects every existing point. Rollback/import/qualification/activation/weekly/unknown references are monotonic: completion, interruption or elapsed time never retires them. Native retention holds the ledger lock through Kopia selection/deletion/readback; uncertain deletion poisons further mutations. Lock order is generation → reference ledger → repository. Ordinary reference writers release their ledger lock before effects.
- After the second successfully evaluated and safely resumed weekly point, the scheduler invokes the existing native Kopia retention actuator. Kopia supplies **seven daily/four weekly** selection; reference protection and at least **two functional points** are additional mandatory retention rules. Snapshot IDs and original pins are never rewritten. Old receipts remain evidence even when a native snapshot is tombstoned.
- `scripts/install-weekly-restore-schedule.py` installs the immutable controller before invoking pinned enrollment and installs only the three exact generation-scoped weekly unit names. Optional activation is explicit. Original daily installer behavior is unchanged.

New CLI source integration is coordinator-owned and now registered in `Main.kt`: `weekly-restore-enroll INVENTORY BINDING_JSON FUNCTIONAL_PLAN_JSON`, `weekly-restore-units|tick|suspend|alert GENERATION BINDING_SHA`, and `generation-kopia-retain INVENTORY GENERATION BUNDLE_SHA OPERATION_ID`. The exact owner-applied patch is recorded in delegation handoff files; CLI registration alone is not native validation.

The real Acceptance `backup-restore-native.py` adapter exercises fresh installed timer-originated slots, binding denial, live source/target audit, reference-authorized native retention, and an explicitly authorized private-copy inventory-integrity failure/OnFailure alert. It leaves faults and unknown outcomes retained. It requires two prior independently verified points rather than fabricating them or advancing clocks.

Remaining integration/runtime prerequisites: RSS worker exclusion across the complete maintenance window; reviewed full-cohort projections and real application readback plans/artifacts; root-owned adapter packaging; actual unit checkpoints and later authorized native validation. Unregistered reference writers must not select a snapshot outside the reference authority. Explicit reference retirement/compaction is intentionally absent, so old references conservatively keep extra points. Qualification remains **0/2**.

## Historical daily-only implementation and native evidence

The new canonical seven-product cohort can now enroll an **installed daily systemd timer that invokes the Kotlin quiesce/Kopia/resume controller**. It does not schedule direct snapshots of live databases. This is integrated recovery engineering, not a complete release scheduler or either full-stack qualification cycle: **0/2**.

## Implemented operations

```text
python3 scripts/install-generation-backup-schedule.py --activate INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA

release backup-schedule-enroll INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CONTROLLER_TREE_SHA OWNER_UID
release backup-schedule-units SOURCE_Q BINDING_SHA
release backup-schedule-tick SOURCE_Q BINDING_SHA
release backup-schedule-alert SOURCE_Q BINDING_SHA
release backup-schedule-suspend SOURCE_Q BINDING_SHA
```

Enrollment requires either a new, running, ownership-bound canonical installation with successful staging or an explicitly validated private Kopia recovery with complete import lineage/markers. Both require no permanent isolation or uncertain Kopia submission. The actual backup repeats its eligibility and consistency checks under the generation-operation lock. [Recovered-source continuation](recovered-source-backup.md) does not promote a target into site/public authority; it also documents the newly discovered object-lock capacity barrier and the incomplete native chained restore.

`GenerationBackupSchedule.kt` owns the daily slot ledger, invocation identity, source binding and failure barriers. `PinnedBackupController.kt` validates the entire root-owned controller tree, modes, hashes, declared files and its own JAR origin before job effects. `GenerationRuntime.checkBackupSource` provides read-only enrollment preflight; `backupKopia` remains the production backup implementation. Python installs units and drives native tests; it does not implement backup consistency.

### Installed units and artifact boundary

Each fresh scope owns exactly these names:

```text
p0v3-backup-<q>.timer
p0v3-backup-<q>.service
p0v3-backup-<q>-alert.service
```

The service runs as the private runtime owner, not root, and calls a pinned distribution under `/mnt/media/p0-v3/runtime-supervision/releases/<tree-sha>/`. The existing guarded rootful Podman transport is unchanged. No shared trust, sudoers, sysctl or networking settings are modified. The installer refuses conflicting root files and records installation/activation intents and outcomes; partial enrollment is retained rather than regenerated.

The timer has `OnCalendar=*-*-* 03:00:00 UTC`, `Persistent=true`, and an initial `OnActiveSec=5s` trigger after enrollment. Jobs use Java 21, a 512 MiB JVM heap ceiling, an eight-hour outer budget, `Restart=no`, and process-only signalling. A timeout is not permission to resume a source or discard an unknown operation. The existing worker limits and **16,384 MiB RAM / 10,240 MiB disk headroom floors** are unchanged.

### Durable due-slot behavior

`<generation>/backup-schedule/` contains:

- `binding.json`, `enrolled.json`: exact generation/bundle/inventory/controller/owner/enrollment-time binding.
- `inventory.json`: a separate private, hash-bound copy; the original inventory is never edited.
- `schedule.lock`: held throughout the coordinated operation.
- `slots/<UTC-date>/intent.json` and `result.json`: single-use invocation records.
- `failure.alert`: a latched local failure signal, also emitted through the scoped unit's journal.
- `suspended`: an irreversible no-op barrier; it does not remove prior failure evidence.
- Installer intent/outcome records for the three owned unit files and timer activation.

A capture ID is deterministically derived from the binding and daily slot. Repeating a completed slot is read-only. After downtime, one invocation executes **only the latest due slot**, never a burst of missed snapshots or invented historical data. Actual snapshot creation remains at current native Kopia time. Clock rollback, malformed history, unknown outcomes and failed backup/resume block new submissions, including submissions for later dates.

The schedule lock prevents overlapping jobs in that scope; the existing generation lock serializes actual generation effects across scopes. A successful scheduled result requires a correctly bound native snapshot and successful source resume, not merely a zero process exit. The ledger and existing backup history are bounded at 128 operations; exhaustion fails closed rather than deleting evidence. Retention/compaction remains unfinished.

`OnFailure` invokes only the pinned local alert operation. Outcome-write failure still attempts the independent alert. This is **local durable/systemd alerting**, not proof of external notification delivery. Unknown slots are not automatically retried or declared reconciled. The existing backup stop-only reconciliation remains distinct from schedule acknowledgement/promotion.

## Native evidence and retained corrections

Package: **`p0v3-scheduled-backup-engineering-15ba70cac406`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

| Native scope | Receipt |
|---|---|
| Fresh install/workflows, installed timer firing, duplicate tick denial, inventory-integrity refusal/local alert, resumed-source readback and later database write | `p0v3-generation-43d01cb65469` |
| Timer-created snapshot restored privately; historical readback, later-write exclusion and restart | `p0v3-generation-restore-4087c30536a4` |
| Fresh backup-controller SIGKILL, boot/new-ID refusal and stop-only isolation regression | `p0v3-generation-9dac5386dd30` |

Scheduled source: `q-43d01cb65469`; capture: `cap-b610d3e3e3bf`; native Kopia snapshot: `679d601e7137cbe69dc22c92124a1985`.

The first scheduled invocation was triggered by the installed timer's initial activation event, **not a manual service start**. The calendar definition is installed and the UTC/catch-up logic is unit-tested; no claim is made that a 03:00 wall-clock event, host reboot, multi-day outage or weekly timer was observed.

After that successful backup, the probe deliberately changed only the schedule's private inventory copy. Starting the same service then failed before allocating a new slot; the `OnFailure` unit wrote the local alert, and another tick was refused. The changed copy and failure signal remain retained. The original inventory, snapshot and source application state were not modified by this fault. The timer was then disabled and the schedule suspended before source retirement; no test timer is left firing against a retired scope. Unit files and immutable controller artifacts remain retained, not deleted.

Corrections retained:

1. Focused units exposed Kotlin serializer inference for `SortedMap`. Canonical descriptor encoding now explicitly uses `Map<String, FilePin>`; no native effects preceded that correction.
2. The first native probe (`p0v3-generation-2f026e2a0da2`) failed because it queried the service's historical timestamp **after disabling the timer**, allowing systemd to garbage-collect the inactive service. Its receipt remains failed; its source is retired and timer disabled/suspended. The corrected test observes invocation metadata while the timer remains referenced, then disables it. The passing native scopes above are fresh executions, not relabelled results.

## Validation and boundaries

| Repository | Passed unit tests | Unit line coverage |
|---|---:|---:|
| Platform | 249; 4 opt-in integration skips | 5,827/6,385 = 91.26% |
| Acceptance | 46 | 807/820 = 98.41% |
| Keykeeper | 26 | 576/617 = 93.35% |
| Worklane | 142 | 11,842/13,112 = 90.31% |

**127 Python tests passed.** All seven controller distribution files matched an unchanged full rebuild. Unit coverage includes UTC boundaries, deduplication, bounded catch-up, interruption/lost acknowledgement, failed resume, result-write failure, clock rollback, history corruption/bounds, artifact origin/modes/bytes, partial enrollment and irreversible suspension.

Protected fleet: **33 deployments / 109 declared daemons** unchanged; all prior **129 fence hashes** unchanged; **141 fences retained**. The actual controller-kill test retained unknown outcomes and leases. No shared-host reboot, public activation, RSS publication, historical-fence release or protected-workload eviction occurred. The real acceptance manifest still fails with **158 gaps**.

Still missing: installed weekly functional restore and its source/target maintenance coordination; reference-safe Kopia retention and two fully verified release points; public restored-generation promotion and a complete final-artifact native rebackup/re-restore chain; complete scheduler/control-plane recovery bootstrap; full-release provider/identity/client wiring and capacity; transactional update/rollback; and two frozen-candidate complete cycles. Restored targets do not inherit enrollment or live scheduling authority. Same-host encrypted storage is not off-host durability.
