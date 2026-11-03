# Private node-exporter and Prometheus

`node-metrics-r2` adds native **node-exporter 1.12.1** with a separate native Prometheus scraper. The existing five-container observability deployment is unchanged. This is a synthetic textfile/self-metrics profile, **not host monitoring**: no host filesystem, log, device, PID or network-namespace mounts are added.

At introduction, private coverage reached **33/39 selected families plus OpenBao and Keykeeper**, with **80 declared running service containers in 27 supervised deployments**; see the [current inventory](private-runtime.md) for later additions. Component counts are not production acceptance. **Full-stack clean-install acceptance remains 0/2.**

## Runtime boundaries

`NodeMetricsRuntime.kt` and `runtime prepare-node-metrics INVENTORY NEW_NAME` declare two serving containers and one durable, empty-state-guarded metrics initializer. Both services use UID/GID 65534, read-only roots, no added capabilities, bounded memory, the private AppArmor profile and an internal network without published ports. Inputs are protected and checksum-bound; initializers are not replayed on restart.

The exporter disables **all default collectors**, enabling only the native textfile collector plus its own Go/process metrics. Its synthetic metrics volume contains the seed and unique probe files. It does not measure the real host's CPU, memory, filesystems, interfaces or hardware. An authenticated `collect[]=cpu` request is rejected rather than enabling a disabled collector.

TLS on `node:9100` requires and verifies client certificates, with TLS 1.2 minimum. Prometheus receives the separate scrape-client certificate/key and validates the server CA and exact `node` hostname; `insecure_skip_verify` remains false. The exporter never receives that client's private key. Each deployment generates a distinct private CA; the temporary issuing key is discarded. The older PKI helper's client filenames are `admin.pem`/`admin-key.pem`, but here they confer only exporter HTTPS access, not database/system administration. No host trust store is modified.

Exporter controller readiness is only a TCP listener check. Native mTLS requests and actual Prometheus target/query checks independently establish functioning authenticated scraping. Prometheus's private HTTP API is not publicly routed. Lifecycle/admin APIs and outward alert receivers are not enabled.

## Actual data and failure journeys

`platform/scripts/test-private-node-metrics.py` verifies:

1. Actual native exporter version and synthetic seed value; no host collector series.
2. Successful certificate-authenticated `/metrics`; missing/untrusted client certificate, untrusted server CA and wrong hostname all fail. Disabled collector selection returns HTTP 400.
3. Native Prometheus reports the exact HTTPS target, `up=1`, and the exported seed.
4. A unique, bounded synthetic textfile is atomically created with value 42, then checksum-guarded and atomically changed to 43. Native scrape/query observes both values. No network write is retried.
5. A uniquely named malformed fixture produces the native textfile error metric and a firing `PrivateTextfileInvalid` rule labelled `synthetic-only`. Removing **only that owned fixture** resolves the alert. No receivers or real incidents are involved; no counters are cleared.
6. After an actual pinned systemd restart, the same containers have new start times and unchanged initialization journals. The current file remains 43, while native timestamped PromQL retrieves the older 42 sample and the earlier error sample from persistent TSDB history. This is not re-seeding or re-injecting historical samples.

The probe retains unique valid fixture files/history, action intents, failures and diagnostics. Cleanup checks file type, refuses symlinks, verifies the exact malformed fixture's hash, and does not retry an uncertain deletion. Optimized Python refuses before imports/effects. Later exceptions invalidate the receipt rather than preserving an earlier partial pass.

Passing receipts:

- Direct restart: `p0v3-node-1a893da27415`.
- Pinned systemd restarts: `p0v3-node-89275f24b9c7` and latest **`p0v3-node-67d7390bbdc5`** (including stricter profile and cleanup guards).
- Manifest SHA256: `becbf960c624c5972b6674738a54e4eb1675806978cc258259d29dbf8e7a4b8d`.
- Controller tree: `f96c08db85039c90bea3aeb00ca4d11c13a56b118705aef11e2f7981b1b65478` (seventeenth retained snapshot).

```sh
python3 platform/scripts/test-private-node-metrics.py --supervised
```

Each run creates new synthetic marker files, not replacements for previous runs.

## Immutable PID 1 fix and retained failure

The original `node-metrics` deployment is stopped and retained. Its unwrapped exporter exited **2** on requested SIGTERM; the unchanged controller correctly rejected the shutdown. Receipt `p0v3-node-failed-2d7e233af2d8` retains that failure and service log. Exit code 2 was not reclassified as success.

The corrected offline image retains the original exporter binary and adds the distribution's static **catatonit 0.2.1-2+b13** for signal forwarding and child reaping. Real lifecycle tests now observe exporter-container exit 143 and Prometheus exit 0. This helper does not restart crashed children and is not a watchdog.

- Base: `quay.io/prometheus/node-exporter@sha256:da83fae85603c4e47e6c68369a7d746e2dda683dc35ea2e234b4f171e0d92798`.
- Derived image: `localhost/p0v3-node-exporter@sha256:daf70dc167702888cd9d949edab429eda1d3abb92a81d788f8bb427711b28a96`.
- Derived image ID: `7f5929fc3744930debe8888b0e726585e4526ea866fc8a94f0f32aeea0827d76`.
- Static helper SHA256: `84e9bde9a352e11949c9a09abe64b81e83d5dc345a9d99c62eefdfdfc359bb96`, enforced by the Containerfile.
- Build receipt/context: `p0v3-node-build-976b3350a678`; network disabled and pulls forbidden during build. Upstream/packaging source archives and license notices are retained in the context and image. Source archives match the SHA256 values in the [Debian source descriptor](https://deb.debian.org/debian/pool/main/c/catatonit/catatonit_0.2.1-2.dsc); this is not a claim of independently verified release signatures.

## Coordinated encrypted recovery

`NodeMetricsRecovery.kt` and `runtime prepare-node-metrics-restore INVENTORY RECOVERED_DIRECTORY NEW_NAME` accept only the exact source recipe. The recovered initializer checks both volume completion markers, rejects missing/incomplete/foreign/symlink markers (including dangling links), and never copies the seed. Input changes on repeat preparation are refused.

`scripts/test-node-metrics-encrypted-restore.py` actually disables/stops the source unit, enters its manifest/input-bound maintenance fence, and holds the runtime lock while capturing **both** stopped textfile and TSDB volumes plus exact TLS/configuration inputs. Bounded streaming tar capture rejects linked/special/privileged/path-escaping members. Source containers, inputs, initializer journal and complete file inventories are checked for stability. Kopia encrypts the combined capture, verifies 100% of files, rejects an incorrect repository password, and exports checksum-verified bytes. A new isolated, fenced target receives the archives only after guarded empty-state checks; invalid restore markers are exercised before normal startup.

**Passing recovery receipt: `p0v3-metrics-restore-731df3abee30`.** Snapshot `k2c1d5ddab3f7a068bbebf8dbfca67ee8`; archive-manifest SHA256 `4c3cf386fd2ad3feba4d982f8561720480308fdcb5740a9a8ceec14b5bb30279`. Native restored mTLS scraping and timestamped PromQL recover the original 42/error historical samples, not newly injected history. Source-only post-snapshot metrics are absent on the target; target-only writes remain absent on the source. The target survives a real restart with unchanged initialization journal/container IDs and changed start timestamps. Its namespace cannot connect to source TCP 9100 or 9090. The source is enabled/active again; `nmrestore-731df3abee30` is retained **stopped**, never boot-enabled or publicly routed.

```sh
python3 platform/scripts/test-node-metrics-encrypted-restore.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-node-67d7390bbdc5
```

Use a passing same-manifest native fixture whose historical samples remain inside the TSDB retention window. No expired samples are silently regenerated. The source-manifest marker is not a unique snapshot identity: exported archive checksums separately bind this recovery. This is local, private component recovery, not off-host or full-release acceptance.

## Remaining work

The introduction audit found exactly 27 enabled/active units and 80 running declared containers, no published ports or active maintenance records, and the original node profile stopped. JVM checks and 52 Python unit tests pass; platform JVM unit-only coverage is 3468/3757 lines (92.31%). These checks are not independent acceptance.

Production host telemetry and its mount/privacy/privilege review, integration into the final shared observability deployment, certificate renewal/revocation, off-host backup, upgrade/rollback, shared-host reboot and crash supervision remain unfinished. Persistent TSDB readback after restart is **not a backup or restore test**. No new full-fleet restart or independent full-stack acceptance is claimed.
