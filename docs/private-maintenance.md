# Durable private-runtime maintenance fences

**A controller safety primitive, not a global write/outbound freeze or complete release backend. Full-stack acceptance remains 0/2.**

`RuntimeMaintenance.kt` and `PrivateDeployment` now provide persistent maintenance across controller invocations. The control record is bound to the complete immutable deployment/input fingerprint and a unique operation generation. It records `backup`, `restore` or `update`, plus at most one explicitly permitted staging target.

## Contract

- `maintenance-enter` validates/audits the complete deployment under its exclusive lock, writes a mode-0600 checksummed record through a fsynced temporary file and atomic rename, fsyncs the directory, **then** stops processes in reverse dependency order.
- If stopping fails, the record remains. Retrying the same reason/target resumes stopping with the same generation; a different operation is refused.
- Record presence blocks ordinary `apply-private`, boot apply and provisioning. Staging is allowed only for the exact recorded target and dependency closure, with every selected initializer already completed. It cannot initiate/replay setup under maintenance.
- A fence with no staging target permits no process startup.
- `maintenance-status` reports the operation intent. **It does not prove quiescence** after an interrupted enter; callers must verify process state before touching data.
- `maintenance-leave` requires the matching generation and all processes stopped. It removes and fsyncs the record; it never starts applications.
- Corrupt/foreign records and incomplete temporary writes block startup. Current-controller stop remains available to quarantine processes even with a corrupt/pending maintenance record. No automatic repair or force-release is provided.
- Application input filenames may not occupy the reserved `runtime.*` control namespace. Maintenance records are excluded from application fingerprints and are not included in application backup inputs.

## Commands

```sh
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
M=/mnt/media/p0-v3/runtime-deployments/DEPLOYMENT.json

$CLI runtime maintenance-enter "$M" backup postgres
$CLI runtime maintenance-status "$M"
$CLI runtime stage-private "$M" postgres
# Normal apply/boot apply is refused while this record exists.
# Hold the deployment lock while performing external dump/archive work.
$CLI runtime stop-private "$M"
$CLI runtime maintenance-leave "$M" EXACT_RETURNED_FENCE_ID
# Applications are still stopped; explicitly resume the audited boot unit afterward.
```

For a fully stopped backup, omit the staging target. IDs are operation generations, not credentials or substitutes for filesystem ownership/security checks.

## Pinned-controller compatibility

Existing installed controllers are **not silently upgraded**. Older pinned controllers reject the new record as an unexpected runtime directory entry, so they fail closed rather than starting the application. They do not understand maintenance staging and may also refuse their old stop path while a record is present. Use the current audited controller to quiesce/release; disable an existing boot unit before entering maintenance, and release the fence before reenabling that pinned unit.

This compatibility behavior was exercised against the actual older controller `60aee905f1ae5bfad60f9a70f7e6c0d08c0da23c1fb008e364c389d3e60ba3d6`, not inferred from a mock. No production unit/controller snapshot was replaced.

## Actual execution

`test-private-maintenance.py` prepares a fresh private LiveKit fixture and its own pinned boot unit. It verifies persisted/idempotent enter, all-process quiescence, ordinary apply/provision refusal, real systemd restart refusal, older pinned boot refusal, exclusive staging, refusal to release while a staged process runs, stale-generation rejection, explicit release leaving services stopped, and successful subsequent boot. The manifest bytes do not change.

Receipts:

- `p0v3-maintenance-a0174e0a67f2` — initial native proof.
- **`p0v3-maintenance-8876c2336776`** — current proof, including the hardened control-file namespace/pending-write implementation.

Both dedicated `fence-*` fixtures are stopped and their units disabled; retained for diagnostics. They did not change the then-current fleet count (18 deployments / 39 daemons, 25 selected families plus OpenBao). The subsequently added [Mastodon deployment](private-social-integration.md) brings the current fleet to 19 deployments / 45 daemons, 26 selected families plus OpenBao. The shared host was not rebooted.

The real recovery harnesses now use the fence:

- **Firefly:** `p0v3-finance-restore-c1ab069467dc`, encrypted snapshot `kacd20637d3411b75f5db2dc2206cfb70`. Only completed PostgreSQL dependencies may be staged. The database is stopped again before fence release; native restored financial readback/writes, unchanged migrations and source/target write/network isolation pass.
- **OpenBao:** `p0v3-bao-restore-0a8a7faf5487`, snapshot `k0dfca37fd10d42114d1346d44d78617c`. No staging target is allowed. Quiesced Raft/audit/config capture, recovered-share unseal, versioned secret readback, post-snapshot exclusion and target restart/isolation pass.

- **Mastodon/RSS:** `p0v3-social-restore-f8ce8a9c8659`, snapshot `k078df19d4a586965c5f5587198524542`. Only PostgreSQL is staged, with the runtime and RSS state locks held during coordinated capture. Native restored message/media/OAuth, Valkey divergence, all 47 bot identities and unchanged checkpoints pass; the target is stopped. See [social recovery](private-social-integration.md#coordinated-encrypted-recovery).

These harnesses explicitly test normal startup denial while fenced. They retain the runtime lock during external capture and refuse automatic recovery if an active fence's generation was not successfully recorded. On successful completion the source fence is released before source supervision resumes; restored targets are stopped. Earlier component backup harnesses have not all been converted yet.

## Unit evidence and remaining boundaries

Unit tests cover persistence before a failed stop, a fresh controller object encountering the same fence, idempotent retry, absence of unauthorized start/create effects, allowed staging without journal changes, unfinished initializer denial, reserved input names, corrupt state, pending temporary files and generation-safe release.

This is not power-loss fault injection, a host reboot test, database-level read-only enforcement, egress filtering, fencing against direct privileged Podman commands, a multi-deployment atomic fence or protection against another orchestrator that bypasses the controller. Staged database processes can still accept explicitly authorized writes. External helpers still require coordinated locking. Whole-stack update/rollback effects, public cutover, schedules and independently reviewed clean-install/restore cycles remain unfinished.
