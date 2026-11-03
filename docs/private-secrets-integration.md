# Private OpenBao, native Keykeeper storage and encrypted Raft recovery

**Not production key custody, deployed Keykeeper SSO or full-stack acceptance. Acceptance remains 0/2.**

At its introduction, `openbao-r4` added one running OpenBao daemon, bringing the private runtime to **18 deployments / 39 daemons**, covering **25/39 selected families plus OpenBao**. The subsequently added [Mastodon deployment](private-social-integration.md) brings the current fleet to **19 deployments / 45 daemons, 26/39 selected families plus OpenBao**. OpenBao/Keykeeper are additional requirements outside `products.json`; 39 daemons does not mean 39 completed families.

## Backend and lifecycle

`OpenBaoRuntime.kt` runs acquired **OpenBao 2.7.2** directly via `/usr/bin/bao`, not its development-mode entrypoint. It uses single-node persistent Raft, native TLS at `https://bao:8200`, no public ports, UID/GID 1000, a read-only root, bounded resources, no added capabilities and the dedicated AppArmor profile. The node has no configured peers or auto-join. No shared trust store, sysctl, host logs or unrelated resources were changed.

Native declarative audit configuration writes only this backend's audit records to its private data volume. `log_raw=false` retains native HMAC redaction. The isolated restore test verifies that the particular synthetic value, root token and base64 shares do not occur literally in the stopped backend archive; this is not a claim that all metadata is encrypted or a substitute for audit review.

**Startup readiness deliberately means verified TLS API availability.** `bao status` exit 2 (sealed/uninitialized) is accepted for lifecycle readiness, but secrets are not operational until initialization/unsealing. No root token or Shamir share is placed in runtime inputs, startup commands or the boot unit. Restarting starts sealed. The operational harness separately requires unsealed active health and actual secret readback.

Initialization is explicit, with five Shamir shares and a threshold of three. Before the one-time request, the harness fsyncs an initialization intent; returned recovery state is written mode 0600 under a mode-0700 directory and fsynced. An already initialized instance cannot be reinitialized by rerunning the harness. Repeat tests require the prior private fixture directory; ambiguous/lost initialization responses are not silently retried or reset.

**All shares and the root token are co-located in the protected synthetic fixture. This does not provide real split custody.** Production human custody, approved auto-unseal/recovery policy, root-token retirement, off-host escrow and operational rotation are unfinished. Never use real owner secrets here. Private TLS certificates expire after 365 days; rotation remains unfinished.

## Verified native operations

`test-private-openbao.py` checks:

- TLS CA, hostname and exact certificate; initialized/sealed state and three-share threshold (the first two shares leave the server sealed).
- KV-v2 with mandatory CAS: create, exact read, stale-write conflict, second version and restart persistence.
- Anonymous denial, a narrow read-only token, forbidden writes/system access/sealing, and token revocation.
- Restart into a sealed state with protected reads returning 503, followed by explicit unseal and version-2 readback.
- Explicit sealing and subsequent unseal; final source state is operational and unsealed after the probe.

OpenBao 2.7 compatibility fixes were tested rather than bypassed: the binary is `/usr/bin/bao`; the old `file` storage backend and `disable_mlock` setting are unsupported; audit-device creation is declarative, not via the old mutation API. A fresh KV-v2 mount can return a transient version-upgrade response; only that explicit response receives a bounded configuration retry. Earlier `openbao`, `openbao-r2`, and initialized `openbao-r3` deployments are stopped/retained, not overwritten.

## Actual Keykeeper adapter and authorization

`OpenBaoStore` retains loopback-only access by default. Remote access now needs explicit `allowRemoteHttps=true` and HTTPS, with native certificate/hostname validation and no redirects. Remote plaintext, userinfo, paths, query strings, fragments and missing hosts are rejected. `serve --oidc` exposes this opt-in as strict `KEYKEEPER_BAO_REMOTE_HTTPS=true`; invalid boolean values fail configuration. That adapter opt-in does not change the listener. A later, separately configured [Keykeeper native TLS/OIDC deployment](private-keykeeper-integration.md) now serves the private network without public ports.

`test-keykeeper-openbao.py` and `acceptance/scripts/KeykeeperBaoProbe.java` run the actual compiled `Vault`, `AccessPolicy` and `OpenBaoStore` against a fresh native KV-v2 mount and a short-lived, mount-scoped token. They verify creation, human→agent read grants, denied editing/sharing, subsequent edit grants, native CAS conflict, revocation, filtered listing and restart readback. Backend administrative access is denied to the service token, which is revoked after testing. Audit events are checked for value/token leakage.

The JVM receives a per-process trust store containing the fixture CA; a run without that trust fails, while the trusted run succeeds. No host JVM trust store is modified. **Principals are synthetic test principals; this is not the deployed OIDC login journey.** The backend integration probe is not a persistent Keykeeper daemon. The later [Keykeeper composite](private-keykeeper-integration.md) separately verifies native browser and agent identities; its coordinated recovery and production custody remain unfinished.

The new immutable candidate `localhost/p0v3-keykeeper:candidate-2` has digest `sha256:ea432995d9fe6df7173cf4c4a5dc6af60918b500e373baacaa9cc2a51802edc4` and image ID `6395880624f161a6d9dc3c1bdbb1eeb69117c6d978061984066c298baf28e03d`. It was built offline from the pinned base, and unconfigured OIDC startup correctly fails. Candidate 1 was not replaced. Candidate 2 is **not deployed**.

## Encrypted functional recovery

`test-openbao-encrypted-restore.py` audits the pinned source unit/manifest, disables/stops only that unit, enters a [durable no-staging maintenance fence](private-maintenance.md) and takes its runtime lock. It verifies that ordinary startup is denied and releases the matching generation before source supervision resumes. It captures the quiesced Raft data **and audit log**, input files, source manifest and protected fixture recovery material. A regular-file-only bounded tar inventory rejects traversal, duplicate normalized names, links, special files and privileged modes.

Kopia encrypts this snapshot, verifies 100% of files and exports to an empty private directory. The harness checks exact file hashes and restored archive inventory; a fresh target volume is verified byte/mode/size-for-byte/mode/size before the initialization completion marker is written. It reuses the constrained single-UID restore adapter, not a fabricated backup marker alone.

The target starts sealed on a separate network. Recovered original shares unseal it; the original version-2 secret is read back. Post-snapshot source data is absent. New target writes do not appear on the source, survive a target restart/unseal, and target→source TCP is blocked while the source is live. Targets are stopped afterward. Source supervision is restored and the source is explicitly unsealed for the fixture.

This is quiesced **single-node** Raft-directory recovery, not multi-node failover, native online-snapshot replacement, Keykeeper browser/SSO recovery, off-host backup or whole-stack recovery. Local encrypted repositories and protected plaintext exports remain for diagnostics. The current persistent-instance recovery test checks OpenBao data; it does not independently replay the Keykeeper grant workflow against those restored records.

## Receipts and supervision

Under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-bao-395cb88d6682` — initial native backend functional/restart pass.
- **`p0v3-bao-e43c9155b3a5`** — backend rerun after the expanded systemd test, with explicit unseal.
- `p0v3-keykeeper-bao-05d5ae538b92` — real Keykeeper adapter/authorization against native OpenBao.
- **`p0v3-keykeeper-bao-fc8faf6cf8de`** — repeats it and explicitly rejects the untrusted CA.
- `p0v3-bao-restore-a08ad801bf71` — isolated encrypted recovery, snapshot `k4205dbc4eb13873589ff1c404d502a15`.
- **`p0v3-bao-restore-50a0e6de1225`** — repeated functional recovery, snapshot `k4721d85175576adf34997e21b7272613`.
- **`p0v3-bao-restore-0a8a7faf5487`** — recovery with durable source fencing, snapshot `k0dfca37fd10d42114d1346d44d78617c`.
- `p0v3-keykeeper-build-efd7ee6b5109` — candidate-2 build provenance.
- **`p0v3-boot-bed6a9f978ec`** — all eighteen units/39 daemons restarted with unchanged IDs/journals and seven pinned controllers. Explicitly reports `manualUnsealRequired:["openbao-r4"]`; no host reboot or automatic unseal was claimed.

`p0v3-private-openbao-r4.service` pins controller tree `60aee905f1ae5bfad60f9a70f7e6c0d08c0da23c1fb008e364c389d3e60ba3d6`. Both `brestore-*` targets remain stopped. The source is enabled/active and was explicitly unsealed after tests. Running the boot-supervision probe again will seal it; that is deliberate, not a watchdog failure or permission to store unseal keys in a unit.

## Commands

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
./keykeeper/gradlew -p keykeeper check installDist --offline

# For a genuinely fresh instance, use a fresh name and omit --fixture on its first probe.
platform/build/install/p0-v3-platform/bin/p0-v3-platform runtime prepare-openbao \
  platform/release/downloaded-candidate-inventory.json NEW_PRIVATE_NAME
python3 platform/scripts/test-private-openbao.py --name NEW_PRIVATE_NAME

# Current enrolled fixture; no initialization reset:
F=/mnt/media/p0-v3/image-acquisition-receipts/p0v3-bao-e43c9155b3a5
python3 platform/scripts/test-private-openbao.py --fixture "$F"
python3 platform/scripts/test-keykeeper-openbao.py --fixture "$F"
python3 platform/scripts/test-openbao-encrypted-restore.py --fixture "$F"
```

None of these component results increments the required independently reviewed full-stack clean-install/restore cycles.
