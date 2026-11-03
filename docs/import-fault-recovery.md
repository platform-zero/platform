# Import failure isolation and scoped process-interruption proof

The foundation restore controller now owns failure isolation. A caught import/preparation exception records a failed import outcome and separately attempts reverse-order, ownership-checked stop/fencing of **every** target member. A failure to write the import outcome does not skip isolation. Neither path restarts a member, releases a fence, regenerates missing inputs or retries an import.

If preparation failed before valid inputs exist, affected members cannot be audited/fenced normally. Isolation is then recorded as incomplete, not invented as successful. Fatal JVM/process loss leaves the original import intent unresolved. The existing stop-only isolation/reconciliation API can establish a retained safe boundary without rewriting that unknown import outcome.

The acceptance client checks for an existing isolation intent before cleanup: it links a new `generation-reconcile-isolation` attempt instead of overwriting or replaying the original isolation action.

## Executed native fault cases

Both cases used the already retired source `q-f4dc52665920` and authenticated capsule `cap-c938db00fc81`. Neither source was started, unfenced or modified. Only new owned target namespaces were used.

### Actual controller process kill

Receipt: **`p0v3-import-interruption-30dc9387020b`**.

Target: `q-30dc9387020b`, bundle SHA-256 `23f72b8b6b94fe272e0880e85df62e8e6687016b17af315470b5b7a90a416b7a`.

The probe waited until the first imported PostgreSQL volume reached re-export/readback, then stopped the fresh controller JVM with SIGSTOP. It verified that member completion and the group outcome were still absent. It waited for its observed native descendants to finish, then sent SIGKILL **only to the controller PID it launched**. It did not kill rootful children or a host-wide process group.

Verified afterward:

- The real controller exited due to SIGKILL; this was not a fabricated pending-intent simulation.
- Original group/member import intents remained byte-identical.
- Import completion and the group import outcome remained absent; uncertainty was not converted into failure or success retrospectively.
- Ordinary startup, maintenance release, import replay and clean-install staging were refused.
- Stop-only isolation succeeded; no target daemon had been created.
- The source, protected fleet and all earlier fences were unchanged.

Retained fences: foundation `515e4771-26b5-4325-b8c9-e28c6abdc5a6`; SQL-cache `fd866fb3-4fed-4b38-af5f-c38c40a622de`.

This is **not** a host reboot/power-loss test, a filesystem-exhaustion test or a general guarantee of detached-descendant containment. It demonstrates the observed scoped import boundary and its refusal/reconciliation behavior.

### Caught integrity failure after partial import

Receipt: **`p0v3-import-interruption-0a0097d19b3e`**.

Target: `q-0a0097d19b3e`, bundle SHA-256 `4f271aa414712a7dc9fc4354eeaaa97063e0354cdeb91810088f2b2c3fb19887`.

At the same early readback boundary, the probe paused the fresh controller and waited for observed native descendants to settle. It changed **only the candidate's recovered ntfy tar**, recording before/after hashes; it did not alter the encrypted source capsule or original deployment. It then continued that same in-flight controller attempt.

The under-lock authenticated-hash check refused the changed future input. The controller exited unsuccessfully and, **without client cleanup assistance**, recorded successful isolation of both members, including the unattempted SQL-cache member. Startup and replay were refused. A subsequent explicit stop-only reconciliation preserved the original isolation result byte-for-byte. No target daemon was created.

Retained fences: foundation `ea32aa7a-7778-4daa-b99b-b62b6d451784`; SQL-cache `31f49f13-9c3b-4071-a114-fbfbaa69b949`.

A passing fault-probe receipt means the expected failure was rejected and contained. It does not make this target a successful restore.

## Earlier positive regression and unit evidence

The updated controller also passed a fresh native five-service restore/readback/restart run: **`p0v3-generation-restore-592c86bc0638`**, target bundle `2e64315b833b1b5a1db1a3c2b240a543975cddf86982072ed8979d8b47b1f44f`. That target was retired; its foundation fence is `f0b4df4c-1b0c-4363-bfab-aa32a654742e` and SQL-cache fence is `0bc7e280-5ee7-4b85-8598-38de49edd5c8`.

Unit tests cover failed-outcome persistence, reverse-order isolation, partial cleanup failure, linked reconciliation without import replay, interruption-flag preservation and preparation failures without credential regeneration. One initial unit run exposed a defective shared fake binding: capacity admission opened a retired scope and replaced the singleton fake's target binding. The test factory now models the real backend's separate per-instance binding. The failed log is retained; no production ownership guard was weakened.

Probe: `platform/scripts/test-import-interruption.py`, with `--fault kill` (default) or `--fault tamper`. It uses fresh identities, private logs, durable intents, bounded waits and explicit Java 21; optimized Python is refused before effects.

## Reproducible final artifact and fresh repeats

A later full rebuild changed the controller JAR hash. The earlier receipts above remain historical evidence of their recorded artifact; they were not relabelled as testing the rebuilt bytes. Platform archive tasks now disable file timestamps and use reproducible entry order. Two complete unchanged offline rebuilds produced **all seven identical distribution files**, including controller JAR SHA-256 **`9cc84438a17bc747d0d023b5ce4236a016c74e09d22c7c380f23736c10eadc40`**.

A read-only controller copy and both build hash manifests are retained in **`p0v3-import-fault-engineering-d0e0aba6cfd6`**. On that final artifact, three further fresh native runs passed, without subsequent artifact changes:

| Scope | Receipt / target suffix | Bundle SHA-256 |
| --- | --- | --- |
| Actual controller SIGKILL | `p0v3-import-interruption-8b2d60808a74` | `0c77d1ed16549ff87215b0ca3613f6ac37f41b6b06f7252b0f845bff25229641` |
| Caught candidate-input integrity failure | `p0v3-import-interruption-fc4ba896cdb4` | `451f689d83e1f20f8acdfaad375b280a8a7b46a73285bcaa51dd8aa6be816ad2` |
| Native five-service restore/readback/restart | `p0v3-generation-restore-f22a7f08bbac` | `ef42494175790e8110023dea75859382f0ec462f6bb70101be4a1cd7b0457630` |

All six additional member fences are retained. Native fault receipts record the runner hash and full distribution hashes; these are engineering integrity records, not an independent or whole-release qualification attestation.

Final unit gates: platform **194 passed / 4 opt-in integration skipped**, **4915/5402 = 90.98%** Kotlin unit lines; acceptance **36 passed**, **667/679 = 98.23%**; Keykeeper **26 passed**, **576/617 = 93.35%**; Worklane **142 passed**, **11842/13112 = 90.31%**, run outside a Herdr pane without remote lab access or dist publication. Python **111 passed**. The real incomplete acceptance manifest still exits 1 with **62 missing/invalid checks**.

The protected fleet remains **33 enabled/active deployments / 109 declared running daemons**. The retained fence census is now **35**. These component fault checks and positive regressions are not whole-release qualification. The completion counter remains **0/2**, with no public activation.
