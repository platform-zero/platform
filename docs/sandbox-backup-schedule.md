# Opt-in, bounded two-sandbox backup schedule — evidence and limits

**Scope:** Only the already pinned, locally preloaded [ntfy](ntfy-sandbox.md) and [PostgreSQL](postgres-sandbox.md) sandboxes. No catalog expansion, production path, default Podman store, systemd user timer, daemon, background service, account change, route or retention deletion. The two module executors retain separate private rootless Podman stores. The scheduler writes only `/mnt/media/p0-v3/backup/sandbox-schedule` plus the existing v3-only `ntfy-fixture` and `postgres-fixture` backup namespaces, and checks owner-only directories and marker before proceeding.

## Deterministic schedule and failure policy

`module sandbox-backup due` is an **explicit invocation**: at most one UTC hourly slot is processed. Re-invoking the same slot is a no-op. `module sandbox-backup two` is an explicitly invoked, foreground bounded test loop: a 3-second test cadence, **at most two successful slots**, 120-second polling window (an in-flight slot is not preempted); then the process exits. The opt-in real integration test invokes the same bounded runner twice. There is **no unattended trigger installed**. To make hourly operation unattended, a separately reviewed caller would have to invoke `due`; nothing in this change installs or alters such a timer. An owner-only file lock serializes slot executions. Successful slot receipts are write-once per slot **by this runner** (`h<base36-UTC-slot>.ok`; not protected against their owner editing them) and record SHA-256 for each module's backup. An interrupted or failed slot leaves `<id>.started` and any module backups untouched: **all later slots are blocked pending manual inspection**, not silently retried or overwritten. No snapshots or restored data are deleted by the runner.

For each due slot, the runner publishes/reads a unique topic on ntfy's **127.0.0.1:18486**, asserts the fixed PostgreSQL fixture row `1:first`, stops only primary ntfy for a consistent on-disk SQLite snapshot and **restarts it in a `finally` block**, then obtains the PostgreSQL online MVCC `pg_dump -Fc`. It verifies both manifests before opening **distinct isolated restored targets**. On restored ntfy at **127.0.0.1:18487**, it reads the message from before the snapshot and publishes/reads a new one. On restored PostgreSQL it reads the original row, writes `2:restored`, reads both rows, and confirms the primary still has only `1:first`. It stops/removes **only its restored containers** on success or verification failure; the integration test separately stops/removes the two primary sandbox containers afterward. This is functional verification for two fake test datasets, not stack acceptance.

## Actually executed, 2026-10-30 UTC

The real opt-in `SandboxBackupRealIntegrationTest` was executed **twice after the final primary-container health guard** (plus two earlier successful invocations). Each invocation's bounded runner completed **two** due slots: four new independently verified receipts under the final code, eight retained after the agent run. An independent rerun of the same opt-in test added two more verified slots (ten retained in all). The test checked that each receipt named both manifests, the pre-snapshot ntfy message survived isolated restore and remained readable on the restarted primary, PostgreSQL's restored row existed and a new row remained isolated from primary, then verified no retained sandbox container/loopback listener after test teardown. The private owner-only `0700` schedule directory and `0600` owner marker remain available; backup files and receipts were retained, with no retention deletion:

| Due slot | ntfy `cache.db` SHA-256 | PostgreSQL `backup.dump` SHA-256 |
|---|---|---|
| `h9vwts3` | `a7528d065c612ea6548c73c06f10876db976b6e82bdf200390a496ee8623b797` | `6fc517b8e97531452f03b7c8a0ce4f8a4d0d7a449db6b5b22697441692bd1d12` |
| `h9vwtse` | `2df4f86525141b6cc55a6802d33d17a8ee89b0fa9e94f32d3409a3302453ca24` | `7b63f9fe2970cd0cf6bf32c8db0b99d055b43f6ddffe7718f8d0be12a41a9434` |
| `h9vwtsv` | `37153d40316fdc1b93b6b214f1709b15976fe670be5a130865ad8dbb3a2caea9` | `70d8212b55e4250f57fea8230c4937392a535ff7a6ecd6b049bb88d20b7372ac` |
| `h9vwtt5` | `ffba9b16be70aa24085c11992bf00798a160e467b4b2c2119c3583d816dee45c` | `13de32ce50939e79a32b1042d912007bbbee545d728a99eec783af40ba562b6a` |
| `h9vwtvm` | `ef8bd1cc761892e0d1ae113def181a352004f85f1f18cb58a913212751a3d9a8` | `d36a5be5e6e33cc4ea204e58f2d89ada0618ee51db0491ef6053061cd5ed78d0` |
| `h9vwtvw` | `975c3d874d228b13aa939f196e53fab4f85222acb1c779c91a7a32d14b152fcc` | `19fb94bb66715ba0ba180d1a0b2d34a0bf3af54c8c43fe1ca5c2271cc29508cc` |
| `h9vwtwb` | `edbab404aa8c44688711df65a7b312d5d9f107297368ee910f06479ab3416255` | `1c6f3fa5106a57777cc8d4bf81d397b353856f8281e45d9a8b0db0dbdc9b7d38` |
| `h9vwtwk` | `9f07d0208eda5107bc4bdd51aa5b7997333cfdc2f83fad0e3618079f9e85a6ca` | `b98d10e8ef601bcb3d9cdda9c20927a1c4030523a8d1a14f76fc9ac6656376a7` |
| `h9vwtyd` | `214a09923e556a158fca46980e7033f9354db2f8b82c66161290ea5ba76af4cc` | `45e70e63cab290835e7b755adfd2f7be13c3f8df27fd845a0a9d354d53fe1335` |
| `h9vwtyn` | `b6a68aa909136f64e0d2cdff57441f9b05a3d63b75f9ccd2ccd0f60d80bf63c6` | `c900983d701643b3449ec88c4cae5dd9dadc1585cc0a43d1970d8d31ffe899f3` |

Run the real test only when both immutable image digests are preloaded in their **different** isolated stores, both primary loopback ports are free, and both existing roots have been reviewed as owner-only:

```sh
P0V3_SANDBOX_BACKUP_INTEGRATION=1 JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user ./gradlew test --tests 'net.datamancy.platform.SandboxBackupRealIntegrationTest' --offline --rerun-tasks
```

Ordinary `clean check` is **offline**: fake module backends exercise due/idempotent slots, bounded waiting, SQLite snapshot failure/restart, PostgreSQL partial backup failure, corrupt hash refusal, isolated functional failure/cleanup, incomplete-slot blocking and no retention deletion. The real integration test is deliberately skipped unless opted in. These ten due slots were all in the dedicated test cadence, **not** eight wall-clock hourly backups. This is a synchronous, manually triggered bounded scheduler, **not** a durable always-on automatic timer; time-based backup beyond these bounded foreground test slots has not been proven. No global PostgreSQL roles/databases, ntfy authentication, cross-module data dependencies, external routes, full-stack install, general production scheduler or long-term recovery policy have been validated. Full-stack acceptance remains **0/2**.
