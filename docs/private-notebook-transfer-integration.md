# Private notebooks, transfers and reusable single-user recovery

## Implementation-only native runner and cold projection

`NotebookRuntime.coldRestoreSpec` retires notebook-init and refuses to start without the recovered work directory. Compiler equality and complete cold-import validation remain mandatory at the generation recovery boundary.

`acceptance/runners/jupyter-notebook-native.py` is a standalone stdlib native adapter: scoped verified HTTPS, no proxy/redirect/retry, bounded RFC6455 WebSocket frames, actual kernel execute-request/stream/reply/idle correlation, saved native output through Contents API, and unauthenticated access denial. RESTORE reads the original notebook/digest without rewriting it and separately exercises a new ephemeral kernel. It never infers restore isolation or bootstrap retirement from caller booleans; those unsupported assertions remain false. Context supplies exact `https://notebooks.datamancy.net/` (or the explicitly private `https://notebook:8443`) and protected CA/token paths. This is not a browser journey or a new native receipt. It requires an HTTPS endpoint; the older plain private notebook recipe below is not silently treated as TLS-capable.

These are working internal component deployments, not a full-stack release. There are now **20 running daemons across 18 selected logical families**. The separate JupyterHub family is still unfinished; a personal notebook server is not a multi-user Hub.

## Jupyter notebook

`NotebookRuntime.kt` runs the acquired, immutable Jupyter base-notebook image as UID 1000 with a read-only image root, a 2 GiB memory limit and a private home/work volume. A generated token protects the server. Unauthenticated API access is denied, XSRF/origin checks remain enabled, terminal endpoints are disabled and the Lab extension manager is read-only. No existing workspace is mounted. Token-bearing startup URLs are suppressed with the supported `WARN` log level; the live probe checks that the configured token is absent from daemon logs.

```sh
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
$CLI runtime prepare-notebook platform/release/downloaded-candidate-inventory.json notebook-r2
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/notebook-r2.json
python3 platform/scripts/test-persistent-notebook.py
```

`acceptance/scripts/NotebookKernelProbe.java` uses real REST and WebSocket connections. It creates a notebook/session, waits for a Python kernel-info response, executes `print(sum(range(11)))`, receives the actual `55` stream plus successful execution/idle messages, saves that real output through the Contents API, and deletes its kernel session. The Python lifecycle harness then cleanly stops/restarts the deployment and reads back the saved notebook/output without recomputing it.

Successful receipt: **`p0v3-notebook-062f66e1b76d`**. The first `notebook` candidate exited because `WARNING` is not a supported traitlets log-level string; that state is retained and `notebook-r2` is the working deployment. An unconfigurable browser-file trait was also removed. These failures were not counted as usable notebook installations.

The upstream `SimpleLocalProcessSpawner` explicitly warns against production use because it does not isolate users. It was inspected, not deployed as a shortcut to claiming JupyterHub completion. This server is a token-authenticated personal notebook only; isolated Hub spawning and owner SSO remain separate work.

## qBittorrent

`QbittorrentRuntime.kt` runs the image's actual `/app/qbittorrent-nox` binary directly, avoiding the root-oriented S6 init wrapper. It has private configuration/download volumes, generated PBKDF2-HMAC-SHA512 credentials (100,000 iterations, 16-byte salt, 64-byte derived key), mandatory authentication including localhost, and enabled CSRF/clickjacking/host-header checks. DHT, PeX, local peer discovery and UPnP are disabled. There are no published ports or existing media mounts.

```sh
$CLI runtime prepare-qbittorrent platform/release/downloaded-candidate-inventory.json
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/qbittorrent.json
python3 platform/scripts/test-private-bittorrent-transfer.py
```

The transfer probe creates a temporary confined peer on the deployment's owned internal network. That peer alone generates 128 KiB of random fixture data. The harness builds canonical private-torrent metadata from its hashes—**it never copies the payload into the downloader**. Both peers' live preferences and tracker lists are checked. The downloader starts at zero progress, receives one explicit private peer, transfers the bytes using BitTorrent, and reaches verified completion with matching SHA-256 and native downloaded-byte accounting. After clean restart, the authenticated API and file digest still agree.

Latest receipt: **`p0v3-transfer-f948e9bc49ee`**, payload SHA-256 `d72ae47543ddadee3eee9c20e2dd878cf07ff0a511fbac05c97db5ce57680923`. The earlier successful `p0v3-transfer-e3d0a2e5b8d8` lacked the additional live tracker-list assertion. Temporary seeders are ownership/image-audited, stopped and removed; their private fixture volumes and diagnostic receipts remain. No public swarm or copyrighted media was used.

The image is qBittorrent 5.3.0. Its successful login can return an empty response rather than the older `Ok.`, and torrent-add returns structured results. The harness verifies subsequent authenticated state and the exact info-hash instead of confusing these API changes with bad credentials. Completed progress can precede updated byte counters. More importantly, an upload-queued torrent can retain zero in the persistent `downloaded` field while `downloaded_session` correctly records all received bytes. A repeated test exposed this and was retained as failed; the harness now requires the maximum of these two counters to cover the payload, records both, and does not double-count overlapping totals. Unit regression cases cover queued and overlapping accounting.

## Reusable single-user restore preparation

`SingleUserRestore.kt` adds:

```sh
$CLI runtime prepare-single-user-restore \
  platform/release/downloaded-candidate-inventory.json RECOVERED_INPUT_DIRECTORY NEW_NAME
```

This is deliberately constrained to a **single daemon and UID/GID-1000 data**, with acquired Linux/amd64 image identities, no extra capabilities and a new deployment name. It does not support database clusters or mixed-owner volumes. It consumes the recovered `source-spec.json` and private source inputs, preserves those recovered bytes, rejects changed recovery inputs on re-preparation, and replaces original initialization jobs with a recovery admission check. Initial database/account creation is not replayed.

Every recovered volume must have no incomplete-copy marker and must contain a completion marker bound to the original manifest SHA-256. Merely preparing/provisioning the target cannot start an empty volume as a successful restore. The marker is an operational checkpoint, **not an independent signature or replacement for encrypted archive verification**; the restore workflow must verify and copy the actual exported bytes before writing it.

The notebook recovery harness exercises the entire path:

```sh
python3 platform/scripts/test-notebook-encrypted-restore.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-notebook-062f66e1b76d
```

It cleanly stops the source, acquires the same POSIX lock used by the JVM, snapshots data/configuration/manifest into encrypted Kopia, verifies 100% of files, and exports the snapshot. Source container identity/start state must remain unchanged during this interval. After resuming the source it creates a source-only artifact. The restore gets **all application data and credentials from the encrypted export**, not a plaintext source copy. Exported inputs and the manifest are verified; the target volume starts empty, gets an incomplete-copy marker, an exact copied-tree comparison and finally the manifest-bound completion marker.

The restored server runs on a separate internal network. The test verifies blocked source TCP access, original saved output, absence of the post-snapshot source artifact, and a **new real kernel execution on the restored server**. The restored-only notebook must remain absent on the original. The restored deployment is then stopped/quarantined; data and recovery evidence are retained.

Latest successful receipt: **`p0v3-notebook-restore-17f064218deb`**, snapshot **`ke2142d9a9e84406802420167017918ec`**. Earlier independent execution of this same component harness also passed as `p0v3-notebook-restore-b09af3b2ede1` / `k758acda027972d6c9e650c905f843331`. Neither is independent full-stack review or increments full-stack acceptance.

## Runtime audit and limits

The runtime now also rejects adopted containers with unexpected PID/IPC/UTS/cgroup/user/network namespace settings, memory/PID limits, devices, supplemental groups or inherited volumes. Unit drift cases prove rejection before mutation; all eleven active deployments passed re-audit/apply. Platform Kotlin unit line coverage is 92.61% (2,469/2,666); the JVM checks and nine Python unit tests pass. Existing private IPC namespaces reported as `shareable` are accepted, not host/container IPC namespaces.

Public HTTPS, SSO/owner onboarding, browser/Android journeys, qBittorrent encrypted restoration, multi-user Hub isolation, other families and the complete transactional release executor remain unfinished. Kopia evidence is local, not off-host protection, and recovery credentials/plaintext exports are privately retained. **Full-stack clean-install plus isolated-restore acceptance remains 0/2.**
