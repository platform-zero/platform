# Persistent private runtime — actual deployment, not a complete release

The Kotlin CLI now executes real, persistent deployments in the dedicated rootful Podman store. `PrivateDeployment.kt`, `RuntimePreparation.kt`, `FoundationRuntime.kt`, `IdentityRuntime.kt` and `ObservabilityRuntime.kt` are used by the commands below. This is **not** a registration of the full `ReleaseEffects` backend: public activation, coordinated backup/restore, migrations, transactional upgrades and full-stack acceptance remain incomplete.

## Currently running

[Huly's native lifecycle evidence](private-huly-integration.md) now passes verified database transport, native issue/description and indexing readback, outsider denial and an actual fourteen-daemon supervised restart. Its SSO/member-role/recovery scope remains unfinished. [Native JupyterHub](private-jupyterhub-integration.md) additionally passes isolated user origins/homes, saved kernel execution, authorization denial and four-container supervised restart. [SOGo](private-sogo-integration.md) now adds native calendar/contact journeys and supervised persistence, without mail integration. [Private mail](private-mail-integration.md) now adds native SMTP/IMAP, attachment persistence and sender/relay/admin/TLS denials. [The separate SOGo/mail composite](private-sogo-mail-integration.md) additionally passes native SOGo SMTP, IMAP/browser and Sent-copy persistence, cross-user/transport denials, calendar/contact journeys and five-daemon supervised restart. [Coordinated encrypted composite recovery](private-sogo-mail-recovery.md) now additionally passes native restored mail/calendar/contact/browser journeys, attachment bytes, denials, restart and source/target write isolation. Current census `p0v3-fleet-76f661b89a89` verifies 33 enabled/active units and 109 running declared daemons; it is not a whole-fleet restart or application-availability proof. Retired `huly-r8`, `huly-r9`, `jupyterhub-r7`, `mail-r4`, `mail-r7` and `sogo-mail-r1` retain maintenance fences; the failed `smrestore-0609bbce6070` import is additionally fenced. No retained fence was silently released.

109 declared long-running service containers across thirty-eight selected product families plus OpenBao and Keykeeper remain running, with **no host port bindings**:

| Deployment | Running processes |
|---|---|
| `foundation-r3` | PostgreSQL 17.11, Valkey 7.2.15, ntfy 2.35.0 |
| `identity-r2` | Separate PostgreSQL 17.11, optimized Keycloak 26.8.1 |
| `observability` | Alertmanager 0.34.2, Loki 3.7.9, Prometheus 3.15.1, Alloy 1.21.3, Grafana 13.3.0 |
| `forgejo-r2` | Forgejo 17.0.1 |
| `planka-r3` | Separate PostgreSQL 17.11, Planka 2.2.1 |
| `sql-cache` | MariaDB 10.11.19, Memcached 1.6.45 |
| `jellyfin-r4` | Jellyfin with generated fixture media only |
| `donetick` | Donetick with local SQLite storage |
| `homeassistant-r2` | Home Assistant with virtual devices only |
| `notebook-r2` | Personal Jupyter notebook with real kernel execution |
| `jupyterhub-r8` | Native Hub/CHP, separate Alice/Bob notebook containers and private subdomain TLS ingress; actual kernel output, cross-user denial and restart persistence |
| `sogo-r2` | Native CalDAV/CardDAV, browser calendar/contact readback, scoped TLS SQL, private Apache and Memcached; mail unavailable |
| `qbittorrent` | Authenticated qBittorrent with private generated-data transfer |
| `searxng-r2` | SearXNG native SQLite FTS5 search and TLS nginx; synthetic corpus, no public engines |
| `erpnext-r7` | MariaDB, authenticated Valkey cache/queue, ERPNext backend, Socket.IO, worker, paused scheduler and TLS nginx |
| `crowdsec-r4` | Native CrowdSec parser/scenario and TLS local API; synthetic logs only, no traffic enforcement or CAPI sharing |
| `seafile-r4` | MariaDB, authenticated Valkey, native Seafile server, paired Seahub/fileserver backend and private TLS nginx |
| `files-office-r7` | Separate five-container Seafile storage plus native ONLYOFFICE CE DocService/embedded converter and office TLS nginx |
| `keykeeper-identity-r4` | Separate PostgreSQL, native TLS Keycloak, OpenBao and native TLS Keykeeper; human browser and scoped agent CLI |
| `node-metrics-r2` | Native mTLS node-exporter and separate Prometheus; synthetic textfiles/self-metrics only, no host telemetry |
| `backup` | Native TLS Kopia UI/API, guarded encrypted repository and networkless restored synthetic fixture; not whole-stack/off-host backup |
| `huly-r10` | Fourteen native Huly/CockroachDB/Elasticsearch/Silo/Redpanda/KVS/Caddy daemons; issue/description, outsider denial, indexing and supervised persistence |
| `matrix-r2` | Separate PostgreSQL, Synapse, Element nginx and private-PKI Caddy |
| `matrix-identity-r4` | Separate PostgreSQL, Keycloak, Synapse, MAS, identity nginx and Element nginx; native delegated OIDC and identity recovery |
| `opensearch-r2` | OpenSearch 3.9.0 with TLS client-certificate authentication |
| `firefly-r2` | Separate PostgreSQL, PHP-FPM and nginx for Firefly III 6.7.9 |
| `bookstack-r3` | Separate MariaDB, PHP-FPM and nginx for BookStack v26.09.2 |
| `knowledge-identity-r4` | Separate PostgreSQL/Keycloak and MariaDB/PHP/nginx with native OIDC over private HTTPS |
| `livekit` | LiveKit 1.13.11 and TLS nginx; actual client-media E2EE and encrypted isolated configuration recovery |
| `openbao-r4` | OpenBao 2.7.2 native TLS, single-node Raft and declarative audit; starts sealed after restart |
| `mastodon-r4` | Separate PostgreSQL/Valkey, Mastodon 4.7.4 Puma/Sidekiq/streaming and private TLS nginx; 47 silent RSS bot accounts |
| `mail-r9` | Native Stalwart 1.0.1, implicit-TLS SMTP/IMAP/HTTP, local-only delivery and retained mailbox state |
| `sogo-mail-r2` | Separate PostgreSQL, Memcached, Stalwart, SOGo and Apache; native SMTP/IMAP/browser integration and calendar/contact persistence |

See [private-application-integration.md](private-application-integration.md) for actual Git/kanban/SQL/cache workflows, Chromium journeys, and encrypted isolated Forgejo restoration. Restore instances are stopped after verification; they are not counted among running daemons. [Media/home integration](private-media-home-integration.md) records the newer streaming, chore and virtual-automation checks and their remaining acceptance gaps. [Notebook/transfer integration](private-notebook-transfer-integration.md) covers actual kernel execution, reusable single-user restore preparation, encrypted isolated notebook recovery and genuine private peer transfer. [Matrix integration](private-matrix-integration.md) records native message/media persistence, real HTTPS Element journeys, E2EE delivery and fresh-device encrypted-key recovery; this is not an isolated homeserver restore. [Private search integration](private-search-integration.md) adds real OpenSearch indexing, filtered queries, authorization denial and restart persistence; no encrypted cluster restore is claimed. [Private finance integration](private-finance-integration.md) adds real Firefly account/expense creation and exact balance readback in a fresh browser after restart; encrypted database/files/keys recovery now also passes native restored workflows and source/write isolation. SSO remains unfinished. [Private wiki integration](private-wiki-integration.md) adds real book/chapter/page authoring, search, authorization denial and restart readback; encrypted wiki recovery remains unfinished. [Native cross-service SSO](private-knowledge-sso.md) now passes Keycloak required actions, BookStack subject binding, PKCE and negative authorization checks in a separate composite. Its five additional daemons reuse already-counted families and do not complete production SSO.

Names are `p0v3-live-<deployment>-<process>`. Each deployment has its own internal network, labelled volumes and configuration secrets. Image `EXPOSE` entries shown by `podman ps` are not published host ports. There is no public HTTPS endpoint. [Pinned systemd boot/shutdown units](private-boot-supervision.md) now cover all thirty-three active deployments; actual service restarts and notebook persistence passed, but the shared host was not rebooted. There is no crash watchdog or unattended reconcile timer. [Node-exporter integration](private-node-metrics.md) verifies actual mTLS scraping, live synthetic changes, native alerts and persistent TSDB history; its separate coordinated encrypted recovery now verifies actual historical samples, mTLS, divergent writes and TCP isolation. Neither test is host monitoring or full-release recovery.

Private manifests and inputs are under `/mnt/media/p0-v3/runtime-deployments/`. The Podman graph remains root-only under `/mnt/media/p0-v3/release-runtime/graph`; input storage is deliberately separate so its permissions were not weakened. Generated credentials are mode 0600 in mode-0700 directories. They are never printed or regenerated on a successful repeated preparation.

The identity recipe creates an `owner` account in the private `p0v3` realm with a temporary password and both `UPDATE_PASSWORD` and `CONFIGURE_TOTP`. Its initial credential is retained in the private `identity-r2/realm.json`; the separate bootstrap administrator credential is in `identity-r2/keycloak.env`. No test enrolls the real owner's second factor. This realm currently permits private HTTP; it is not a production/public identity configuration.

[LiveKit integration](private-rtc-integration.md) now passes actual browser E2EE audio/video, wrong-key and token/administration denial, restart and encrypted configuration/key recovery. Rooms are ephemeral. Matrix calling, public TURN and Android acceptance remain unfinished.

[OpenBao and native Keykeeper datastore checks](private-secrets-integration.md) now pass versioned secret/grant persistence and encrypted isolated Raft recovery. OpenBao and Keykeeper are additional to the 39 selected families. [The separate Keykeeper composite](private-keykeeper-integration.md) now passes native browser OIDC/password-change/TOTP, agent CLI access, record sharing/denial/revocation and supervised persistence. Production custody, token rotation and coordinated recovery remain unfinished. Backend lifecycle readiness permits sealed API availability; operational acceptance separately requires explicit unseal and secret readback. Boot restart deliberately seals the backend.

[Private social integration](private-social-integration.md) adds native OAuth/PKCE, direct-message streaming, authorization denial and persisted browser readback. All 47 RSS bot identities across nine unchanged packs are verified by the real publisher transport, but publication remains gated. Coordinated encrypted social/RSS recovery now passes native restored message/media/OAuth and Valkey readback, source/restore write isolation, recovered bot-token verification and unchanged RSS checkpoints. Isolated targets are stopped. Mastodon SSO, public federation/publication and full-release recovery acceptance remain unfinished.

[Delegated Matrix identity](private-matrix-identity.md) now proves native MAS/Keycloak/Element login, password/TOTP requirements, exact subject binding, denied outsider/admin/password-grant access, and fresh-device identity recovery after a pinned systemd restart. Its message fixture is not E2EE. It adds MAS as the 27th selected family; coordinated homeserver/identity restore and integrated calling remain unfinished.

[Private SearXNG](private-metasearch-integration.md) adds native full-text/phrase/pagination searches, actual Chromium POST searches and a pinned unit restart with unchanged corpus and initializer journal. No public engines or existing user documents are used. Encrypted isolated corpus/configuration recovery now passes durable source fencing, verified Kopia export, guard denial, native restored browser searches, persistent divergent writes and source TCP isolation; this is not off-host or full-release recovery.

[Private ERPNext](private-erp-integration.md) adds native company setup, browser customer creation, calculated draft quotation/readback, actual queued work and realtime delivery, authorization denial and pinned restart. It does not prove posted accounting, SSO or coordinated encrypted ERP recovery. The recurring scheduler is deliberately paused; its PID-1 wrapper is not a watchdog or queue-quiescence mechanism.

[Private CrowdSec](private-security-integration.md) adds native parsing/threshold detection, authenticated decision streams, expiry/revocation and supervised persistence. It does not ingest host logs, enforce traffic policy or prove encrypted security-state recovery.

[Private Seafile](private-files-integration.md) adds actual browser/API uploads, verified downloads, read-only sharing, denial/revocation and restart persistence. Its five declared serving containers include one loopback-coupled Seahub/Go-fileserver pair; the count is not an OS-process census. Coordinated encrypted three-database/file-state recovery now passes in a stopped-after-verification isolated target. [A separate ONLYOFFICE composite](private-office-integration.md) now passes native DOCX keyboard editing/save/readback, read-only denial, durable callback replay protection and supervised persistence. Active editing-session durability and composite/whole-release/off-host recovery remain unfinished.

## Dependency-only staging and recovery

`runtime stage-private PRIVATE_MANIFEST PROCESS_ID` starts only that process and its dependency closure, retaining the **full** manifest fingerprint, image checks and resource audits. It rejects running processes outside the selected closure before mutations. Staging alone does not establish a fence. [Durable maintenance](private-maintenance.md) is now available via `maintenance-enter`, `maintenance-status` and generation-matched `maintenance-leave`: it blocks ordinary apply/boot, permits only the recorded staging target, and requires all processes stopped before release. Disable the relevant pinned boot unit before entering and retain the deployment lock during external capture. Older pinned controllers fail closed on the control record; they are not silently upgraded. The [financial recovery harness](private-finance-integration.md) exercises this with native `pg_dump`/`pg_restore` and recovered files/keys. `runtime prepare-firefly-restore INVENTORY RECOVERED_INPUT_DIRECTORY NEW_NAME` prepares only a supported financial restore. `runtime prepare-mastodon-restore` adds a separately constrained social adapter with cache/media/token guards and no application migration/account replay. Neither is an arbitrary database adapter. `runtime prepare-searxng-restore` separately supports the exact offline SQLite search recipe, with an existing-corpus integrity/manifest guard instead of seed replay. `runtime prepare-seafile-restore` supports the exact private CE recipe after fenced import of its three application databases and block/configuration state; original identity/schema seeds are replaced by read-only checks. The native recovery probe verifies snapshot permissions, divergent writes and TCP isolation before stopping the target. `runtime prepare-sogo-mail-restore` supports the exact cold PostgreSQL/Stalwart/home/configuration composite with source-bound guards and no database/account/mail-bootstrap replay. Its native recovery harness verifies restored mail/calendar/contact/browser readback, attachment bytes, denials, post-snapshot exclusion, restart and write isolation before stopping the target. These adapters do not implement whole-release or off-host recovery.

Long initialization jobs may outlast one 120-second transport wait. The runtime retries only that read-only wait observer, at most five observations; it never replays/restarts the initialization job. On exhaustion, state and journal remain for reconciliation.

## Commands

From the workspace root, after `./platform/gradlew -p platform installDist --offline`:

```sh
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
INVENTORY=platform/release/downloaded-candidate-inventory.json

# Fresh names only; repeat preparation preserves existing inputs or refuses changed recipes.
$CLI runtime prepare-foundation "$INVENTORY" foundation-r3
$CLI runtime prepare-identity "$INVENTORY" identity-r2
$CLI runtime prepare-observability "$INVENTORY" observability

$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/foundation-r3.json
$CLI runtime status-private /mnt/media/p0-v3/runtime-deployments/identity-r2.json
$CLI runtime stop-private /mnt/media/p0-v3/runtime-deployments/observability.json
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/observability.json
```

The installed `p0v3-private-v1` AppArmor profile is a prerequisite for these recipes. Its source and upstream license are in `platform/runtime/`. The implementation work installed only `/etc/apparmor.d/p0v3-private-v1` and loaded that exact profile. No shared container/crun profile was edited or disabled.

## Execution and recovery rules

- Validate the DAG, digest references, numeric non-root identities, volume ownership and input paths before execution.
- Check the dedicated graph/run roots and active rootful/AppArmor/seccomp confinement.
- Audit **every existing declared resource** before mutating Podman: deployment/fingerprint labels; container image ID, user, read-only root, security options, added capabilities, network membership, mounts and absence of public port bindings.
- Require every exact image to exist and match its manifest/image identity. Deployment uses `--pull=never`.
- Fingerprint the typed recipe together with hashes of its private inputs. Changed inputs or recipes require a separate reviewed update path; they are never silently applied in place.
- Pass private configuration files through Podman secrets with the container's UID/GID and mode 0400. Do not make host secret files world-readable to accommodate image users.
- Disable inherited image volumes with `--image-volume=ignore`; all persistent mounts must be declared and owned.
- Serialize operations with a private lock file. Fsync the owner record before starting resources.
- Fsync a checksummed initialization journal **before** each one-shot start, and mark completion only after its verified zero exit. Completed jobs do not rerun even if their containers are removed. Missing in-flight jobs, corrupt journals and failed initializers require reconciliation.
- Poll an explicit native command or an HTTP readiness endpoint at the inspected private container address. A bounded ten-minute readiness budget accommodates real first-start schema migrations. Readiness alone is not product acceptance.
- Stop in reverse dependency order; reject forced/unclean exits such as 137. No volume deletion/pruning command is provided.

## Real failures found and fixed

1. ntfy requires `base-url` when attachment storage is configured. The first unpublished recipe lacked it; it failed rather than being counted healthy.
2. Podman warnings on stderr polluted JSON when output streams were merged. The transport now captures stdout/stderr separately in private temporary files.
3. The host's named unconfined `crun` AppArmor profile stacks with container profiles. The default container policy denied PostgreSQL signals to those stacked labels: `pg_isready` passed, but `CHECKPOINT`, autovacuum signals and clean shutdown failed. A dedicated v3 policy retains the upstream container restrictions and narrowly allows same-v3 stacked peers in both label orders. `CHECKPOINT` and clean PostgreSQL shutdown now pass without adding `CAP_KILL` or disabling AppArmor.
4. A PostgreSQL-client initialization container inherited an anonymous image volume. Strengthened live mount auditing detected it. New containers suppress inherited volumes. The earlier `identity` deployment was stopped after explicit ownership/image checks; its state was retained. `identity-r2` uses only declared volumes.
5. Grafana's first database migration exceeded the original one-minute readiness budget. Its state was retained; the bounded longer budget allowed the same deployment to finish without reinitializing its database.
6. Podman's `CapAdd` records differences from defaults, not the final capability set. Audits now require exact `EffectiveCaps` and `BoundingCaps`, with missing/extra-capability regression tests. All twelve active deployments passed re-audit.

Earlier unpublished `foundation`, `foundation-r2` and `identity` resources are stopped and retained for diagnosis. No unrelated resource or volume was deleted.

## Executed functional evidence

- `python3 platform/scripts/test-persistent-foundation.py`: actual SQL write and forced PostgreSQL checkpoint, authenticated Valkey write, private ntfy publish, clean stop/restart, all three readbacks, repeated idempotent apply, unchanged credentials and container identities. Latest receipt: `p0v3-runtime-check-ffc85ad77e6c`.
- `python3 platform/scripts/test-persistent-identity.py`: owner identity and both required actions survive clean stop/restart. The completed database initialization helper is deliberately removed after validating its ownership, image, zero exit and durable completion record; apply does **not** recreate or rerun it. Receipt: `p0v3-persistent-identity-ffe3942e4443`.
- `python3 platform/scripts/test-persistent-observability.py`: all five Prometheus scrape targets report up; authenticated Grafana queries Prometheus; Alloy receives a real log which is queried through Loki and through Grafana's Loki proxy; Alertmanager accepts/readbacks a private test alert; a real Grafana dashboard and the Loki log survive clean stop/restart. Receipt: `p0v3-observability-814247c77048`.

Private receipts live beneath `/mnt/media/p0-v3/image-acquisition-receipts/`. Observability currently covers its own services and the explicit log-ingestion API, not host journals or the entire application stack. Its alert receiver deliberately has no outward destination. The three lifecycle tests listed above are not encrypted restores or browser acceptance. The separately documented application tests now include real Chromium and an encrypted, isolated Forgejo restore. Earlier Chromium/encrypted identity component evidence is documented separately in [private-identity-integration.md](private-identity-integration.md).

**The remaining product families and full-stack lifecycle are not finished. Clean full-stack acceptance remains 0/2.**
