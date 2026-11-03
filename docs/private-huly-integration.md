# Private Huly — native issue, collaboration document and restart evidence

`huly-r10` supplied the thirty-fifth selected family with private component coverage. With the later [JupyterHub](private-jupyterhub-integration.md) and [SOGo](private-sogo-integration.md) integrations, the current total is **37/39**, plus OpenBao and Keykeeper. This is not complete-stack acceptance (**0/2**), production onboarding or a restored Huly deployment.

## Actual scope

The Kotlin `HulyRuntime.kt` recipe starts fourteen daemons and completes four guarded initialization jobs. Native application bundles are unchanged:

- Huly 0.7.426 account, workspace, transactor, collaborator, fulltext, front, stats and Rekoni services, Silo object storage, native KVS 0.3.2 and private Caddy.
- CockroachDB 24.2.10 with verified TLS and an application-scoped SQL principal; root client material is mounted only into database initialization.
- Elasticsearch 7.14.2 with the official attachment plugin, verified TLS, scoped `huly*` access and retired bootstrap password.
- Redpanda 24.3.6 on the dedicated internal network. **Kafka is not authenticated**; network confinement is not authenticated broker isolation.
- Six persistent volumes: CockroachDB, Elasticsearch data/configuration, objects, Redpanda and workspace upgrade logs.
- UID/GID 1000, read-only roots, empty capability sets, no-new-privileges, bounded resources, the private AppArmor profile and no published ports throughout this recipe.

Private HTTPS is `https://huly:8443`. Exact Host/SNI and foreign-Origin checks are enforced. Both `/_collaborator` and its subpaths reach the actual native collaboration service; matching only the slash-suffixed path was insufficient. Optional mail/calendar/Telegram connectors explicitly return 503 rather than pretending to work.

Initial setup creates exactly three synthetic local identities through a loopback-only bootstrap account process. A read-only native migration barrier precedes signup. Serving signup is disabled. Administrative writes are not retried on timeout or ambiguous results. Input checksums and `runtime.jobs` prevent initializer replay.

### KVS transport compatibility

The native KVS binary uses `tokio_postgres::NoTls` and cannot consume a verified-TLS PostgreSQL DSN. Its bytes are retained unchanged in a pinned Node-based image. `huly-kvs-proxy.cjs` accepts only the fixed loopback DSN, binds `127.0.0.1:26257`, negotiates PostgreSQL SSLRequest, and verifies CockroachDB's CA and hostname with TLS >= 1.2 **before forwarding native bytes**. There is no remote plaintext fallback or replay. Handshakes, connections and diagnostics are bounded; native tracing DSNs/JWTs/secrets are sanitized, including split lines.

Native transport probes establish the authentication challenge over verified TLS, wrong-CA/hostname rejection, direct plaintext-database rejection and bridge inaccessibility from a peer container. The transport probe sends zero application passwords; the actual application uses its scoped database credentials through the verified bridge. Nineteen mock-based Node unit tests separately exercise bootstrap, search rotation, ambiguity refusal, negotiation, sanitization and supervisor shutdown/failure behavior. Unit-only coverage across the five Huly runtime JS helpers is **98.80% of lines** (95.61% of branches), with a >=90% line gate in `test_huly_bootstrap.py`. Live browser/lifecycle probes are not counted in that coverage.

### Derived immutable images

| Purpose | Manifest digest |
|---|---|
| Elasticsearch + verified official plugin | `b07456315f9a55e5940a4da24e5d5a0ab6293f8c8cf0f6ae2c826f0b739ae133` |
| Unchanged KVS binary + Node transport wrapper | `889f824034e49ce6b4666d3dcb343930e1b8b4f3bea3234cec9394bfef09d503` |
| Unchanged Caddy executable without file-capability xattr | `12aaf65164cae642f31c1434d19ff3fd83cea5bb2e03ecaf473308b594ef47b9` |

Protected build receipts: `p0v3-huly-search-build-6d582630bc3e`, `p0v3-huly-kvs-build-1f55c14434e9`, `p0v3-huly-caddy-build-1a587d36647d`. No broad capability grant or shared-host sysctl change was used. These are compatibility artifacts, not independently approved production images.

## Native evidence

Latest component pass: **`p0v3-huly-fbb2ba95f277`**, beneath `/mnt/media/p0-v3/image-acquisition-receipts/`.

It verifies, before and after an actual systemd stop/start:

1. Fresh native owner login and readback of the existing synthetic issue and collaboration-backed description.
2. A separately authenticated outsider cannot select or enumerate the private workspace; the native account API returns `:Forbidden`.
3. Elasticsearch independently contains both the issue title and description.
4. Private CA/hostname/leaf checks, default-trust and foreign-Origin denial, exact Host rejection, native collaboration routing and explicit optional-integration unavailability.
5. KVS verified transport and negative cases described above.
6. Fourteen changed daemon start times, unchanged container IDs, unchanged manifest/configuration/credentials and initializer ledger. Sanitized before/after container snapshots and input hashes are retained.

Earlier successful lifecycle proofs: direct controller restart `p0v3-huly-4b7721f2b6f0`, first supervised restart `p0v3-huly-1b65fb1b8571`. Native creation evidence remains `p0v3-huly-browser-45bfa4683eda`; verification never recreates that issue.

The first repeat wrapper (`p0v3-huly-f180868d91ac`) correctly failed closed: initial application navigation raced the issue-row click. The verifier now follows the native issue permalink. For this existing fixture, the permalink was recovered from the already captured native DOM and retained in a new exclusive provenance sidecar; the original intent was not overwritten or deleted and no application creation was replayed. Browser-only diagnostic receipts deliberately remain `passed:false, diagnosticOnly:true`; the lifecycle wrapper separately evaluates native outcomes and retains `fullStackAcceptance:false`.

## Repeat without creating data

From the workspace root:

```sh
python3 platform/scripts/test-private-huly.py --name huly-r10 --supervised
# Read-only browser diagnostic, without restart:
python3 platform/scripts/inspect-private-huly.py --name huly-r10 --mode verify-issue
```

Do **not** use create/resume modes to repeat acceptance. Workspace/issue intents and permalink provenance are protected under `/mnt/media/p0-v3/huly-probe-state/`, outside immutable runtime inputs. Both effectful Python probes refuse optimized Python before imports/effects. Secrets are passed through protected files or stdin, not command-line arguments.

Manifest SHA-256: `bbf4971932f55e7f90daea5ba3e4f3cd2faa4c86abb5f65654567f133b0fc37a`.

`p0v3-private-huly-r10.service` is installed, enabled and active, using immutable controller tree `e72621f91f088447b17f6405a53e6ae598cd6f54b955416ffdbf00fa612f09e4` (nineteenth snapshot). This is an audited oneshot boot/shutdown unit, **not a crash watchdog**.

Earlier read-only fleet census `p0v3-fleet-2e3538bcfca5` records 29 enabled/active units and 95 running declared daemons, no published ports, read-only non-root operation, no-new-privileges and capability sets matching their manifests. The older Matrix Caddy retains its explicitly declared `NET_BIND_SERVICE` exception; Huly has none. This census is not a new 95-container fleet restart or application-availability proof.

## Retained failures and limitations

Earlier candidates are retained, stopped and not boot-enabled. Failures covered unsupported keystore CLI syntax, read-only GC logs, migration readiness, missing frontend connector configuration, pending-task self-counting, native KVS TLS incompatibility, Caddy file capabilities, workspace upgrade-log persistence and exact collaboration routing. `huly-r8` and `huly-r9` retain their intentional update-maintenance fences. They must not be silently released or restarted.

Outstanding work includes reader/member role and collaboration authorization tests, native search UI/editing journeys, Keycloak SSO/TOTP and real-owner onboarding, coordinated encrypted six-volume/configuration recovery, migrations and transactional rollback, reviewed production image/security policy and broker authentication, production custody, mail/calendar integrations, public HTTPS/renewal, Android and independent clean installs. The old compatible Elasticsearch cohort is not a production-security approval. Native restart persistence does not prove backup restoration, and transport TLS is not E2EE.
