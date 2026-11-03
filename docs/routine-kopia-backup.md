# Journaled canonical-source Kopia backup and resume

The controller now runs **quiesce → native Kopia capture → guarded source resume** for a new, running ownership-bound canonical cohort. This closes the earlier requirement to retire a source before every capture. It is still seven-product engineering, not full-release completion: **qualification 0/2**.

**Later integration:** [Installed coordinated daily backup](scheduled-canonical-backup.md) now invokes this lifecycle through a pinned controller, with native timer firing, duplicate-slot denial and local failure alerting. Weekly functional restore and reference-safe retention remain unfinished. The source scopes and historical evidence below remain retained.

## Implemented boundary

```text
release generation-kopia-backup INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA FRESH_CAP
release generation-backup-reconcile SOURCE_Q SOURCE_BUNDLE_SHA CAP FRESH_R EXPECTED_BACKUP_INTENT_SHA
```

The supported cohort remains `canonical-core`, `forgejo`, `sql-cache`: **seven products / seven daemons / three member deployments**. The ordinary cold capture and restoration interfaces remain available. No timer, public route, outbound publication, boot unit or Bao unseal is installed by these commands.

A routine backup requires:

- An exact compiled ownership-bound clean installation with successful staging, or a private Kopia recovery with fully validated import history/markers; all members must be running/unfenced.
- No permanent isolation intent, uncertain Kopia submission, reused capture namespace, or unfinished/failed previous routine backup.
- Existing headroom floors: **16,384 MiB RAM / 10,240 MiB disk**. Capture allows for the bounded staging copies and a 1,024 MiB worker; resume rechecks the full generation reservation plus protected headroom.
- Complete initializer ledgers; backup never finishes or replays bootstrap work. Resume must not recreate missing runtime resources.

[Private recovered-source continuation](recovered-source-backup.md) now supports the restricted Kopia recovery path without relabelling its `restore-import` origin or missing site ownership. It passed scheduled backup on an intermediate artifact; the next native chained restore encountered object-lock exhaustion and remains failed/fenced. The final controller adds lock-capacity admission, with native refusal-only evidence. Public promotion, standalone control-plane recovery and a complete final-artifact native continuation chain remain unfinished.

## Operation sequence

`GenerationRuntime` holds the existing generation-operation lock. Under each member's audited runtime lock it:

1. Persists an operation intent under `backups/<cap>/intent.json`.
2. Acquires a `runtime.backup` lease on every member before stopping any member. Each lease binds generation, operation, bundle digest, member name and runtime fingerprint.
3. Creates its own temporary backup fences and stops members in reverse dependency order.
4. Holds all frozen member locks throughout the existing native Kopia capture/verification path.
5. Rechecks capacity and immutable inputs, releases only the temporary fence for the member being resumed, and starts members in dependency order.
6. Verifies the complete running cohort, then releases operation leases and records success.

Every claim/quiesce/capture/resume/release phase has a durable intent and completion record. The operation lease remains present across the otherwise dangerous interval between temporary fence removal and startup. Ordinary runtime mutations, including the `boot-apply` command, are denied during that interval. Read-only audit/status remains available.

A running source has not been permanently retired by a successful routine backup: no ordinary `isolate` outcome is fabricated to authorize temporary capture. Its capacity reservation remains active throughout.

## Failure and interruption

Caught failures retain the failed backup result and independently attempt reverse stop/fence isolation. Failure to write the backup result does not skip isolation. Thread interruption is handled separately and restored after cleanup.

A killed controller leaves an unknown outcome, not an invented failure/success receipt. New backup IDs cannot bypass it. Explicit reconciliation verifies the original backup-intent digest and **only stops/fences** the source. It preserves original intents/outcomes, existing leases, custody and snapshots. It never resumes the source, recreates credentials or resubmits a snapshot. Corrupt inputs/leases can still make isolation inconclusive; such a result blocks passage and is not permission to release a fence.

Completed backups are not accepted as interruption-recovery authority. A source with permanent isolation history cannot be restarted by submitting another backup operation.

## Native evidence

Package: **`p0v3-routine-backup-engineering-c5362b51267c`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

| Operation on the final controller | Receipt |
|---|---|
| Fresh install, workflows, routine backup, source resume/readback, post-snapshot write, retirement | `p0v3-generation-17a755c2ca29` |
| Native Kopia restore, historical checks, post-snapshot exclusion and restart | `p0v3-generation-restore-19108169331f` |
| Fresh install, actual backup-controller SIGKILL after quiescence, denied boot/new-ID attempts and stop-only reconciliation | `p0v3-generation-a1614fdb535b` |

Successful source: `q-17a755c2ca29`; capture: `cap-0b81829544e7`; native Kopia snapshot: `112c0b43fb312089b3b757a26a20819f`.

After the successful backup, the same source containers resumed and historical Git/issue/comment and Planka project/card/list/comment checks passed. Initializer ledgers and container identities were unchanged. A synthetic PostgreSQL row written **after** capture was present on the resumed source and absent from the restored target both before and after restart. This is one database post-snapshot exclusion case, not comprehensive exclusion across all application/crypto state.

The fault client signalled only its launched controller PID after matching process start identity, waited for observed native children to settle, then sent SIGKILL. All three ordinary boot attempts were refused. A fresh backup ID was refused before allocating its operation directory. Reconciliation stopped/fenced all three members while retaining leases; the original backup outcome remains unknown. No host reboot/power-loss test or systemd boot enrollment occurred.

Earlier artifact-bound native passes (`18162aace729`, `627383af7f76`, `e15934154280`) remain retained. Review then added explicit missing-resource refusal during resume and lease refusal during pristine admission. The final native scopes above were repeated fresh on the changed controller, not transferred from earlier receipts.

## Validation and protected resources

| Repository | Passed unit tests | Unit line coverage |
|---|---:|---:|
| Platform | 236; 4 opt-in integrations skipped | 5,640/6,175 = 91.34% |
| Acceptance | 46 | 807/820 = 98.41% |
| Keykeeper | 26 | 576/617 = 93.35% |
| Worklane | 142 | 11,842/13,112 = 90.31% |

Python helper suite: **123 passed**. All seven final controller distribution files matched an unchanged full rebuild. Unit cases include claims, stop/export/capacity/resume/release failures, missing resources/initializer records, foreign/partial leases, interruption, result-persistence failure, unknown outcomes and stop-only reconciliation. Worklane used only its dedicated local unit toolchain, with no remote lab gate or `dist/` publication.

The protected **33 deployments / 109 declared daemons** and all prior **111 fence hashes** are unchanged. **129 fences** are retained, including earlier artifact scopes. Successful routine operations released only their own temporary fences; successful test sources and restore targets were subsequently retired. Interrupted sources retain their operation leases and stopped-state fences. No public activation, RSS publication, historical-fence release or historical Bao access occurred.

## Remaining completion work

Installed weekly jobs and complete functional restore scheduling; reference-safe retention; complete final-artifact recovered-source continuation and public promotion; broader provider/application/client integration; metadata/ACL/xattr/rootless-home recovery; credential lifecycle; full transactional update/rollback; and two frozen-candidate complete qualification cycles remain unfinished. The real acceptance manifest remains empty and fails closed. Same-host encrypted recovery is not off-host durability.
