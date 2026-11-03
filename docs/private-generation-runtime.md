# Private generation controller

`GenerationRuntime.kt` now executes a **real private, rootful, multi-deployment lifecycle** through `PrivateDeployment`. This is an implemented part of the live controller, **not the complete `ReleaseEffects` backend**, canonical 39-family assembly, coordinated backup, update/rollback, public cutover or release qualification. Full-stack cycles remain **0/2**.

## Typed preparation update

[Typed assembly](typed-generation-assembly.md) now prepares and seals selected members through 34 registered existing Kotlin recipe variants, with primary-ownership conflict checks and input/state consumer declarations. Its latest additional native run is `p0v3-generation-f4dc52665920`. There are now eight retained stopped member deployments across four engineering runs; the three earlier runs below remain historical evidence for their own implementation hashes.

## Native component restoration

The [foundation-generation restore adapter](foundation-generation-restore.md) now authenticates the exact recovered cohort, retires initializer definitions, imports fresh owned volumes under retained fences and verifies re-exported state. A native five-service historical-data/restart proof passed after two retained failed attempts. This is not whole-release restoration or either full-stack cycle.

## Cold capture update

[Generation-bound encrypted cold capture](generation-cold-capture.md) now exports declared volumes and exact configuration under all member locks, after checking clean stopped states and initializer completion. It authenticates the complete capsule and payloads without starting or unfencing the source. This is not an isolated functional restore, and it does not count toward the full-stack cycles.

## Boundary and immutable inputs

- Only fresh `q-<12 lowercase hex>-<member>` namespaces, under the existing dedicated v3 runtime store, are admitted. Existing named proof deployments cannot be adopted into this interface.
- An owned private request specifies a candidate-descriptor digest, members/dependencies and disk reservation. The helper generates these inputs itself; no operator-authored lock or human approval is needed.
- `generation-seal` records exact manifest bytes' digests, exact input-file digests, runtime fingerprints and the sealed process definitions. The resulting bundle digest must be supplied to later commands. The candidate-descriptor digest is a bound reference, **not qualification or signature verification**.
- Input fingerprints retain the previous runtime encoding. Generation-bound fingerprints are compared **inside each runtime lock, before Podman effects**. Staging additionally rechecks live manifest bytes between members. Pristine allocation is rechecked under the member lock, so a cooperating controller cannot allocate between group preflight and start and be silently adopted.
- Sealed definitions allow isolation of other members when a live manifest has drifted. Each affected runtime still validates its actual input fingerprint and resource ownership; drift is not silently repaired.
- Private directories, owner-only single-link regular input files, canonical paths, bounded records, exclusive creation, fsync and a cross-generation lock protect controller records. Existing intents/results are never overwritten.

All members and pinned images are audited before the first allocation/start. Existing resources, prior owner/job metadata or maintenance fences disqualify a pristine stage. There is no automatic image acquisition/build, volume deletion, public port publication, boot enrollment, route modification, outbound activation or maintenance release.

## Capacity

Memory reservation is the sum of each member's daemon limits plus its largest serial initializer limit. Admission preserves at least **16 GiB currently available memory** and **10 GiB free disk**, in addition to candidate reservations. Disk requests must reserve at least 1 GiB per declared volume. Active/inconclusive generation reservations are included; arithmetic is overflow-checked. Declared policy can increase these floors, not lower them.

A previous successful isolation result alone cannot release a reservation: its linked history, exact member set, actual fences and current non-running states are rechecked against the sealed definitions. Stale or corrupt isolation evidence blocks admission. Retained stopped volumes still consume space reported by the filesystem.

This is serialized **admission accounting**, not a host-wide memory guarantee, filesystem quota, aggregate cgroup limit or protection from arbitrary future shared-host pressure. It does not authorize evicting any protected workload. Resource sizing for the complete stack remains unfinished.

## Actions, failure and reconciliation

```text
platform release generation-seal PRIVATE_REQUEST_JSON
platform release generation-audit Q_GENERATION_ID BUNDLE_SHA256
platform release generation-stage Q_GENERATION_ID BUNDLE_SHA256
platform release generation-isolate Q_GENERATION_ID BUNDLE_SHA256
platform release generation-reconcile-isolation Q_GENERATION_ID BUNDLE_SHA256 \
  R_RECONCILIATION_ID ORIGINAL_ISOLATION_INTENT_SHA256
```

- Audit performs native inventory/image checks; runtime/control lock metadata may be created, but no daemon/data mutation is requested.
- Stage is single-use. Group and member intents precede effects. Missing readiness, failure and interruption cannot become success. Ordinary failure records the failed stage and attempts reverse-order fencing/stopping of **only that generation**. Fatal errors or failed persistence leave unresolved intents rather than green results.
- Isolation records its own intent/result and retains all fences. It never starts/reinitializes anything. A failed/incomplete isolation can be reconciled with a new `r-<12 hex>` identity and the exact original intent digest. The original intent and any failed outcome remain unchanged; the new record links to them. Corrupt history cannot be bypassed.
- Reconciliation is restricted to ownership-checked, repeatable **stop/fence operations**. It does not authorize retrying uncertain application writes, migrations or initialization. Stage cannot be replayed after reconciliation.
- Interrupt status is restored after failure persistence/cleanup. Unit interruption tests do not establish privileged process-tree containment, host-crash recovery or application quiescence. Isolation observes stopped/fenced resources; it is **not** a coordinated application-consistent snapshot or proof that every possible external operation has settled.

Source changes require a fresh staging candidate; do not edit or remove old intents to force reuse. There is deliberately no un-fence/restart shortcut in this generation API.

## Executed native engineering evidence

`platform/scripts/test-private-generation.py` creates fresh synthetic foundation and SQL/cache members, seals them, stages them through Kotlin, executes native workflows and retires them behind retained fences. Its subprocess environment excludes ambient provider credentials. Optimized Python is rejected before imports/effects.

1. **`p0v3-generation-2bbd1065a3fc`** — normal stage/workflows/isolation. Bundle `a871c10d571eef48460e64653e14f6ca35de19fbf6d7a35dfe2588d8e796350c`.
2. **`p0v3-generation-1ee876af9999`** — updated implementation plus simulated isolation-intent interruption and native linked reconciliation. Bundle `c07073ec2089178b7a6ec8b4322e59d124099d06c39b08c6c1e55e054a5a4877`.
3. **`p0v3-generation-60f5b527cd1b`** — latest implementation, including the under-lock pristine recheck, native workflows and simulated-boundary reconciliation. Bundle `b72146f0defe500fa2f0ce66ae9793b048b70c8a091d7788773ace3b65e7b856`.

All three exercised PostgreSQL, Valkey, ntfy, MariaDB and Memcached: native writes/readback, clean restarts, durable PostgreSQL/Valkey/ntfy/MariaDB state, MariaDB authentication/rollback checks, and Memcached's intentionally cold restart. Container identities and initializer ledgers were preserved. The original protected fleet's deployment manifests, container IDs/start times and fence hashes remained unchanged.

The second and third runs injected a pending isolation intent **in their own fresh scopes** and verified ordinary replay rejection before reconciliation. They **did not kill a process, reboot the host or simulate power loss**. Earlier receipts remain evidence for their specific implementation hashes, not retroactively for later code.

All six member deployments are retained stopped/fenced, with no boot units. The protected fleet remains **33 enabled/active deployments and 109 declared running daemons**. There are six additional generation fences; the seven previously retained fences remain untouched.

**Three five-service engineering runs are not full-stack install/restore cycles.** No encrypted restoration, Android journey, public HTTPS, RSS activation or complete transaction qualification occurred here. The canonical release/site/credential model, typed complete-product adapters, `ReleaseEffects` integration, scheduled recovery, real acceptance matrix and final two cycles remain open.
