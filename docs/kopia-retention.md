# Native Kopia retention actuator — implementation-only status

This source is **runtime-unverified**. No native retention, reconciliation, backup, restore, container operation or timer change was executed in this increment. Full-stack qualification remains **0/2**.

## Implemented

`KopiaGenerationStore.retain` is a real confined-worker actuator using the existing pinned Kopia image, dedicated runtime store, repository binding and separate custody. It is not another backup engine and is not an ungated deletion CLI.

- Snapshot creation, restoration and retention now share an owned private repository control lock.
- A mandatory `KopiaRetentionAuthority` callback must keep reference writers excluded throughout the operation. It supplies the exact retained receipt census, a reference-head digest, all protected snapshot references and IDs backed by successful functional-restore evidence. There is no permissive default authority.
- The actuator rejects unknown capture outcomes, incomplete repository initialization, changed custody/images, existing retention uncertainty, fewer than two functionally verified points, and incomplete/duplicate/foreign receipt/native inventories. Inventory is bounded at 128 snapshots and 1 MiB; exceeding that bound refuses rather than truncating or deleting evidence.
- A canonical `retention.pending.json` claim is persisted before policy effects. A different operation ID cannot bypass an unknown attempt.
- Kopia sets and computes the calendar policy: seven daily, four weekly, two latest, no hourly/monthly/annual extras, and no suppression of identical snapshots. Kotlin does not implement calendar snapshot selection. Missing native retention reasons fail closed, including Kopia's case where policy evaluation logs an error but list exits successfully.
- Kotlin adds protection for every active reference, the two most recent functionally verified points, all native policy-retained snapshots and any extra native pin. Original capture pins must still be present.
- Complete observed inventories must match retained recovery receipts. A second observation must match before deletion. Only exact manifest IDs selected by Kopia's policy and not protected by those extra constraints are passed to `snapshot delete --delete`. Potential manifest/root-ID ambiguity is rejected. No source-wide deletion, broad expiration or forced blob garbage collection is issued.
- Durable plans and per-worker intents precede effects. Readback must show precisely the expected retained IDs with unchanged contents, timestamps and pins. Successful completion is persisted before the exact pending claim is removed. Failure, timeout or interruption leaves the claim in place; there is no automatic retry.
- `observeRetention` writes observation-only reconciliation evidence for an unchanged, partially deleted or completely deleted planned set. Protected or foreign changes refuse. It never resends deletion, removes the pending claim, resumes a source or declares an unknown worker terminated. Each observation has its own exclusive namespace.
- Worker calls now reject preexisting interruption and preserve interruption thrown by the command adapter.

### Why not unpin and expire?

In Kopia **v0.23.1**, `snapshot pin` calls `UpdateSnapshot`, which saves a new manifest and deletes the old manifest ID. Unpinning retained snapshots would invalidate immutable recovery receipts, original snapshot references and qualification evidence. Existing captures therefore retain their original pins and IDs. Explicit deletion removes only eligible expired manifests after reference protection; it does not rewrite survivors.

The source behavior checked read-only for this implementation is:

- [snapshot manifest update](https://github.com/kopia/kopia/blob/v0.23.1/snapshot/manager.go)
- [snapshot list and native retention reasons](https://github.com/kopia/kopia/blob/v0.23.1/cli/command_snapshot_list.go)
- [retention flags](https://github.com/kopia/kopia/blob/v0.23.1/cli/command_policy_set_retention.go)
- [exact-ID deletion and root fallback](https://github.com/kopia/kopia/blob/v0.23.1/cli/command_snapshot_delete.go)

## Still incomplete — not merely runtime validation

The whole-release controller must implement and register the **complete production reference authority**, including rollback predecessors, restore/import lineage, activation/qualification evidence, scheduled operations and uncertain outcomes. It must serialize reference creation with deletion and verify functional outcomes rather than accept caller-supplied IDs or a boolean. `KopiaRetentionProtection` is an internal trusted-controller contract, not user authorization.

Until that integration exists, no public CLI or scheduled job calls this actuator. The tests supply an explicitly synthetic authority. Weekly Sunday 04:00 UTC functional restoration, target isolation/source-resume coordination, its eight-hour budget and installed supervision remain unfinished. Observation evidence alone is not an uncertainty-clearance procedure; safe completion/termination of an unknown worker must be established by the controller before any future release of the pending claim.

This increment does not implement metadata segmentation, custody/controller disaster bootstrap, the complete release dispatcher or whole-stack canonical assembly.

## Unit evidence

Offline Java 21 / cached Gradle:

```text
./platform/gradlew -p platform check jacocoTestReport --offline
287 tests; zero failures/errors/skips
6,523 / 7,182 lines = 90.82%
```

Log: `/tmp/p0v3-retention-platform-unit.log`.

Tests use test-owned temporary directories and fake `RuntimeCommands` only. They cover guarded retention, preservation of extra pins and referenced/verified points, policy failure, malformed native identity/metadata, inventory races, ambiguous IDs, uncertain deletion, read-only reconciliation, interruption, and cross-operation locking/pending fences. Other repositories were unchanged in this increment and were not redundantly rerun. Native/integration tasks remain excluded, not counted as passes.
