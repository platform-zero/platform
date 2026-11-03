# Private CrowdSec integration

`crowdsec-r4` adds native CrowdSec 1.8.2 parsing, detection, authenticated decision delivery and restart persistence. At introduction, private component coverage reached **30/39 selected families plus OpenBao, 62 declared daemons in 23 supervised deployments**; see [the current runtime inventory](private-runtime.md) for subsequent additions. This is **not public traffic enforcement**. Full-stack acceptance remains **0/2**.

## Deployment and boundaries

`CrowdsecRuntime.kt` and `runtime prepare-crowdsec INVENTORY NEW_NAME` prepare one journalled initializer and one native daemon. The image is digest-pinned; UID/GID 1000, read-only root, dropped capabilities, dedicated AppArmor, an internal network and no published ports are enforced by the existing runtime audits.

The initializer refuses pre-existing database/configuration/bootstrap contents. It copies the pinned image's bundled Grok patterns from `/staging/etc/crowdsec/patterns`, installs only the implementation-authored synthetic parser/scenario, and uses native `cscli` to create the local machine identity and a decision-consumer API key. It does not force registration or run a hub updater. The generated key stays in a protected bootstrap volume **not mounted by the serving daemon**. The daemon necessarily has its local machine credential and SQLite authentication database.

Native TLS listens on private `guard:8443`. Its machine credential names the private CA explicitly, certificate verification stays enabled, and the readiness command performs native `cscli lapi status` authentication. Prometheus metrics are private on port 6060; they are not yet wired into the separate observability deployment. No global trust store was changed.

Only `/synthetic-logs/http.log`, a dedicated application volume, is acquired. **No host, Caddy, application-owner or existing workspace logs are mounted.** Central API configuration is absent; native metrics verify CAPI and PAPI are disabled. No reputation/blocklist download, cloud sharing, external console enrollment or notification transport is configured. GeoIP enrichment is absent and produces an expected missing-database warning rather than triggering a download.

The parser reads native `Line.Raw`, not a nonexistent pre-parsed `message` field. It extracts a timestamp, source IP, status, method and path. The scenario counts synthetic 401 responses per IP, with capacity two, one-minute leakage, five-minute blackhole and a 30-minute decision profile. All generated addresses are reserved documentation ranges. This is a deliberately small fixture policy, **not a production HTTP/security policy**.

Images and protected inputs are immutable under the runtime's checks. Bootstrap-copied policy and patterns reside on a writable application volume; this is not tamper-resistant policy storage. The native agent itself is trusted with its database and local API identity.

## Actual checks

`platform/scripts/test-private-crowdsec.py` proves:

- Private CA/hostname/exact-leaf validation and rejection by the normal system CA store.
- Anonymous and invalid-key decision reads denied.
- A valid decision-consumer key cannot read watcher alerts or delete decisions.
- Native parser-success and bucket-pour counters advance before the threshold check; mere receipt of an unparsed line is insufficient. Overflow counters stay unchanged below threshold and advance exactly once above it, so asynchronous API delivery cannot hide an early overflow.
- Benign 200 responses and two parsed 401 responses produce no decision for their fixture addresses. The third 401 produces exactly one native `ban` decision for the expected IP/scenario.
- A separately created native bouncer credential receives a native startup decision stream containing the detected ban. A separate explicitly administrative, synthetic 10-second decision appears in that stream, expires natively, appears in the incremental deleted stream and remains expired after restart.
- The temporary bouncer loses access after native revocation, including after restart. The primary fixture credential is not silently replaced.
- Actual systemd restart preserves the container ID, changes its start timestamp, leaves the initializer journal unchanged, preserves the decision ID and keeps the benign address unbanned.

Only benign warm-up lines are retried while tailing starts. Attack events are not replayed to manufacture a pass. Existing decisions are not cleared; each run finds unused synthetic addresses. Decision expiry remains native wall-clock behaviour. These checks do not prove persistence of partially filled in-memory buckets.

## Evidence and reproduction

Protected receipts in `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-guard-00d8c276d830`: native detection, API denial/revocation and clean restart.
- `p0v3-guard-9380a5e219e9`: the same checks with actual pinned systemd restart.
- `p0v3-guard-46aac6886e97`: adds explicit bucket-pour/overflow counters and retained metrics evidence.
- **`p0v3-guard-75a499afb60e`**: latest supervised pass, including native startup/incremental decision streams and expiry.

Manifest SHA-256: `371cc26927e566a19679f6e8f427ea9bceab41cc52cbf83c8f8db5ae1198e2d1`.
Certificate SHA-256: `c6e26a1f3d8bd453fbd17607696876fb88b97beb35dd72c611cc6833b12dea41`.
Controller tree: `2eb888108b9f6803fddfe6333a65b2663029ae2f69278510e2e7ff438c016e32`, the twelfth pinned snapshot.

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-crowdsec.py --supervised
```

This restarts only the CrowdSec fixture. It is not a complete 62-daemon fleet restart, host reboot, crash-watchdog test or independent release approval. Credentials never appear in receipts or console output; native diagnostics remain in owner-only directories. Optimized Python is rejected before harness effects.

## Retained failures

The earlier `crowdsec`, `crowdsec-r2` and `crowdsec-r3` deployments are stopped and retained:

- The first lacked a Grok-pattern directory.
- The second used the image's runtime path instead of its bundled `/staging` source and failed initialization; it was not replayed over partial state.
- The third started but failed real detection because the custom parser incorrectly read `message`. Receipt `p0v3-guard-30caebad497b` remains failed; its metrics show unparsed input and no decision. The successful recipe reads `Line.Raw` and the probe now specifically waits for successful parsing.

## Remaining

A traffic-enforcing Caddy/application bouncer, trusted client-IP handling, production parser/scenario review, production false-positive/reconciliation tests, scoped secret custody/rotation, observability wiring, coordinated encrypted SQLite/configuration/credential/log recovery, off-host recovery and independent acceptance remain unfinished. No host firewall, shared network policy, public route or unrelated resource was changed.

Native configuration and parsing behaviour were checked against the pinned upstream [configuration](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/config/config.yaml), [API credential/configuration types](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/pkg/csconfig/api.go) and [parser implementation](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/pkg/parser/node.go), in addition to the actual acquired image and native tests.
