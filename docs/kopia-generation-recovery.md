# Native Kopia recovery for the canonical cohort

Kopia now backs up the actual seven-product canonical application cohort, not just the older synthetic fixture. This is an integrated recovery increment, **not whole-release completion or either full-stack qualification cycle: 0/2**.

## Division of responsibility

- **Kopia** supplies encrypted repository storage, native snapshot/object identities, deduplicated storage, content verification and restoration. The controller does not wrap a custom encrypted capsule inside Kopia.
- **Kotlin** selects the exact compiled cohort, audits sealed inputs and ownership, holds all stopped member locks during export/capture, binds snapshot receipts to source definitions and imports only compatibility-checked daemon definitions into fresh fenced targets.
- Native Python clients exercise historical workflows and fault boundaries; they are not the production backup engine.

The existing long-lived `backup` Kopia fixture and all historical repositories/capsules remain unchanged. New operations run pinned **Kopia 0.23.1 worker containers**, with no public UI or listener, no network, non-root UID/GID, read-only root filesystem, dropped capabilities, AppArmor, 1 GiB memory limits, and immutable `--pull=never` images. A separate always-running backup daemon is not required for these CLI operations.

## Implemented interfaces

```text
release generation-kopia-capture INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CAP
release generation-kopia-restore-canonical-core INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CAP FRESH_TARGET_Q
```

The exact supported cohort is `canonical-core`, `sql-cache`, `forgejo`: seven logical application/provider products, seven daemons, three deployment members. Kopia workers are counted separately.

Source capture currently requires a completed clean-install stage and **already verified stopped/fenced isolation**. It never stops a protected historical deployment, releases a source fence or restarts a source. Capture checks preserve the 16,384 MiB memory and 10,240 MiB disk headroom floors, reserve a 1,024 MiB worker allowance, and conservatively allow three bounded payload copies on disk.

New repository layout:

```text
release-generations/<source-q>/kopia-store/repository/
release-generations/<source-q>/kopia-store/repository.binding.json
release-generations/<source-q>/kopia-captures/<capture-id>/
kopia-custody/<source-q>.env
```

Paths are under the dedicated `/mnt/media/p0-v3` tree. Repository custody is private and separate from repository bytes, and bound by digest. Same-host custody is **not off-host durability or protection from host root**.

Each snapshot contains exact source bundle/specification/configuration/key/initializer-ledger files and declared volume exports. Repository bytes and custody are never recursively included. The manifest, exact file hashes and source fingerprints are checked again after restoration. Capture plaintext staging and scratch exports are removed only after native verification succeeds; private restored plaintext remains retained in the fresh recovery target for validation/evidence.

## Consistency, isolation and failure behavior

- All member locks stay held through cold export, Kopia snapshot submission and 100% file verification. Stopped, clean daemon state and complete initializer journals are mandatory.
- Repository initialization and each worker have exclusive fsynced intents before effects. Partial initialization cannot regenerate credentials.
- A pending snapshot marker is retained across failed/unknown submission or verification. A different capture ID cannot bypass it; automatic uncertainty reconciliation is **not implemented**.
- Native snapshot metadata must match the declared source, file/byte/directory bounds, zero symlinks and zero failed entries. Restoration re-observes the native snapshot-to-root-object binding before mounting writable output.
- Restore workers mount the repository read-only and only a dedicated fresh output scratch directory—not the controller journal, live source or runtime input directories.
- Native restoration precedes strict payload/tar validation and exact compiled import. Bootstrap-only inputs/jobs are retired; source site authority is not inherited. The target remains stopped/fenced until the explicit native client exercises it.
- `GenerationBundle.recoverySourceKopia` records native lineage. Kopia receipts are not fabricated `CapsuleVerification` records; capsule archive hash fields remain empty/null on this path. The native import's source digest binds the Kopia receipt rather than claiming a custom ciphertext archive exists.
- Existing v1 capsule operations and default bundle serialization remain compatible.

## Native evidence

Engineering package: **`p0v3-kopia-generation-engineering-5de472d1c4c9`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

Final-controller source: `q-196418c7e989`, bundle `5c2220a45c6f5f64930cbbf48005d0da6ede8a9c8d6da09f88f6e64c91494a67`.

| Operation | Receipt |
|---|---|
| Fresh canonical install/workflows/restart/retirement | `p0v3-generation-196418c7e989` |
| First native Kopia snapshot and wrong-password/replay denials | `p0v3-kopia-capture-b6304f8d583a` |
| Second snapshot; existing repository/custody reused without initialization | `p0v3-kopia-capture-572dff2e1b99` |
| First snapshot historical restore/restart, after the second snapshot existed | `p0v3-generation-restore-ad7d6e35462a` |
| Second snapshot historical restore/restart | `p0v3-generation-restore-6e5d14497736` |
| Actual controller SIGKILL after partial volume import | `p0v3-import-interruption-a79ea7da1bb8` |
| Caught fresh-target scratch-tar tampering after partial import | `p0v3-import-interruption-d326fb6eb087` |

Native snapshot IDs: `fc79abc0b7610e6e6d87993b06fe92e0` and `b94ea615f113216a400ae4886a3bac10`. Each contains 27 declared payload files / 176,416,011 plaintext bytes, plus its manifest. Both refer to the same stopped source state; this does **not** prove post-snapshot exclusion or changing live generations.

Historical Git commit/README/issues/comments, Planka project/card/list/comments, PostgreSQL/Valkey/ntfy, MariaDB transactions and Memcached's declared ephemeral lifecycle passed. Restored application TLS, nonprivileged runtime roles, retired migration principal, foreign-database/plaintext/DDL/network denials and anonymous access denials also passed. No fixtures were recreated and no initializers replayed.

Earlier artifact-bound passes (`e725f3d73124`, `fe13740f7f5e`, `d62fad741b3d`) are retained separately. After adding stricter native metadata bounds and early pending-snapshot refusal, all final native scopes above were run fresh. They were not transferred to the changed controller.

The final unchanged full rebuild matched **all seven distribution files**. Unit gates:

| Repository | Passed unit tests | Unit lines |
|---|---:|---:|
| Platform | 230; 4 opt-in integrations skipped | 5,470/5,980 = 91.47% |
| Acceptance | 46 | 807/820 = 98.41% |
| Keykeeper | 26 | 576/617 = 93.35% |
| Worklane | 142 | 11,842/13,112 = 90.31% |

Python: **122 passed**. Unit tests cover lost snapshot acknowledgements, blocked resubmission, partial initialization, changed custody/artifacts/native metadata, transport-specific lineage and unchanged legacy paths. Lost acknowledgement is a **unit fault**, distinct from the actual native partial-import kill. No Worklane remote lab/release gate or `dist/` publication was run.

All **18 retained Kopia workers** from this increment were independently inspected: exited successfully, non-root, networkless, no published ports, read-only root filesystem. The protected **33 deployments / 109 declared daemons** and all previous **90 fence hashes** are unchanged. **111 fences** are now retained. No public activation, RSS publication, boot enrollment, protected restart or source restart/unfencing occurred.

## Still required

[Journaled source quiesce/capture/resume and boot-command exclusion](routine-kopia-backup.md) now pass for a new canonical installation, with actual controller-kill stop-only reconciliation and a database post-snapshot exclusion check. That subsequent increment does not resume any historically fenced source from this document.

[Installed canonical daily scheduling](scheduled-canonical-backup.md) subsequently passed actual timer firing and historical restoration of its snapshot, with pinned controller identity, duplicate-slot refusal and local failure alerts.

[Private recovered-source backup](recovered-source-backup.md) subsequently passed an installed timer capture/resume without site promotion on an intermediate artifact. Its next chained restore hit object-lock exhaustion and remains incomplete. The final controller rejects insufficient lock capacity before allocating a new target; this refusal is not a passing restore.

Still missing: a complete final-artifact native continuation chain and promoted-source authority; installed weekly functional restore; reference-safe retention and at least two full-release functionally verified recovery points; uncertainty reconciliation; full custody/rotation/Bao policy; all remaining application/client adapters; live update/rollback; two complete release cycles.

This increment retains the existing strict tar metadata scope and bounded payload limits (1 GiB per file/export, 8 GiB total, 4,096 files). It does not establish segmented full-release exports, POSIX ACL/xattr/nanosecond/rootless-home recovery, broader attachments/crypto recovery, standalone disaster bootstrap, or off-host durability. Those bounds must be deliberately extended and verified before broader state is admitted—not bypassed to claim completion.
