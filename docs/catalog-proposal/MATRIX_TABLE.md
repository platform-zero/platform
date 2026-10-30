<!-- Generated from MATRIX.md by render_matrix.py; edit the source ledger, then rerun. -->
# 89-service metadata matrix (research proposal; not deployment inventory)

Inventory: [authoritative manifest](../../src/main/resources/services.json). **46 modules, 89 IDs.** See [method/limitations](STAGES.md), [handoff](INTEGRATION_INPUTS.md), and `verify_matrix.py`. Each module heading links the strongest available **upstream entry point**; `local` headings have only the manifest, so function is a hypothesis where marked `?`. Links to documentation home pages are pointers, *not evidence for a particular image/tag, configuration, Android package, or custom helper*. Avoid treating a same-name project as proof of the local container's entrypoint. State describes data whose loss matters; capture secrets/config and restore coherently, not just volumes. **Every route below requires explicit owner approval, DNS/TLS/auth review; nothing is provisioned.** `—` = no separately public route. `Android` is a product-level candidate, not a service's APK. `No verified official` does not mean none exists. Definitions in [ledger](STAGES.md).


## alertmanager — [Prometheus Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| alertmanager | D | UI/API | No verified official | `alerts.datamancy.net` (admin-only) | Silences, notification log, config/secrets; decide retention. | Silence a test alert, verify delivery/expiry; restore silences/config. |

## alloy — [Grafana Alloy](https://grafana.com/docs/alloy/latest/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| alloy | D | H/metrics | No verified official | — | Pipeline config/credentials; optional WAL/positions if enabled. | Verify a labelled log/metric arrives at Loki/Prometheus; restore pipeline config. |

## bookstack — [BookStack docs](https://www.bookstackapp.com/docs/admin/installation/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| bookstack | D | UI | No verified official; browser candidate | `books.datamancy.net` | App DB, uploaded files, `.env`/APP_KEY, attachments. | Create page with attachment, retrieve after DB+file+key restore. |

## caddy — [Caddy docs](https://caddyserver.com/docs/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| caddy | D | H (proxy/API optional) | N/A | — (fronts approved routes) | Caddyfile/config, TLS certificate storage if internally issued, credentials. | Approved HTTPS endpoint presents trusted certificate and routes to correct backend after config restore. |

## crowdsec — [CrowdSec docs](https://docs.crowdsec.net/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| crowdsec | D | H/API | N/A | — | Decisions/acquisition config, credentials, local DB if used; separate bouncer integration. | Generate controlled test signal and check decision + bouncer enforcement; restore rules/config. |

## donetick — [Donetick upstream](https://github.com/donetick/donetick)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| donetick | D | UI | Official Android **unverified**; browser candidate | `chores.datamancy.net` | DB, uploaded assets and config/secrets (backend/version TBD). | Create recurring task, mark complete, verify history after restore. |

## element — [Element Web upstream](https://github.com/element-hq/element-web)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| element | D (static web serving possible) | UI | [Element Android repo](https://github.com/element-hq/element-android) / [Element X Android](https://github.com/element-hq/element-x-android): official client candidates; compatibility/version TBD | `chat.datamancy.net` | Web config/branding; messages and keys live in Synapse/clients, **not** Element Web; preserve client recovery keys separately. | Sign in to approved homeserver and send/read encrypted message with recovery procedure verified. |

## forgejo — [Forgejo docs](https://forgejo.org/docs/latest/admin/installation/docker/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| forgejo | D | UI/API/git SSH | No verified official Android; browser/git client | `git.datamancy.net` (+ SSH hostname/port separately) | DB, repositories, LFS, attachments, packages, app.ini, signing secrets, runner artifacts. | Push commit via SSH/HTTPS, clone after coordinated DB+repo+secret restore. |

## forgejo-runner — [official runner guide](https://forgejo.org/docs/latest/admin/actions/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| forgejo-runner | D (job executor) | H | N/A | — | Registration token/config and cache (cache disposable); logs/artifacts stored in Forgejo. | Push workflow, see successful run/artifact; do **not** expose Docker socket to untrusted jobs. |

## grafana — [Grafana docs](https://grafana.com/docs/grafana/latest/setup-grafana/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| grafana | D | UI/API | No verified official Android; browser candidate | `grafana.datamancy.net` (admin-only) | DB (SQLite or external), dashboards, users, datasource config, encryption secret, plugins. | Save dashboard/panel and retrieve after DB+secret restore. |

## homeassistant — [official mobile app](https://www.home-assistant.io/integrations/mobile_app/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| homeassistant | D | UI/API | **Official Home Assistant Android** (linked in upstream doc) | `home.datamancy.net` (access policy TBD) | `/config` configuration, integrations, recorder DB if local, secrets, backup files; external devices not captured. | Toggle authorized device or demo entity; restore configuration/automation and check entity history. |

## jellyfin — [Jellyfin clients](https://jellyfin.org/docs/general/clients/) / [backup](https://jellyfin.org/docs/general/administration/backup-and-restore)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| jellyfin | D | UI/API | **[Official Jellyfin Android](https://jellyfin.org/downloads/clients)** (`org.jellyfin.mobile`; exact deployed version TBD) | `media.datamancy.net` | Config/metadata/database, users, artwork and actual media libraries (often separate mounts). | Play a library item; after restore verify metadata/users **and media**; transcoding cache not source of truth. |

## jupyter-notebook — [Jupyter Docker Stacks](https://jupyter-docker-stacks.readthedocs.io/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| jupyter-notebook-build | B **inferred from ID; verify build recipe** | H | N/A | — | Build inputs/lockfiles/image digest; notebooks belong to JupyterHub user storage, not build job. | Build reproducible pinned image and launch notebook kernel in authorized JupyterHub session. |

## jupyterhub — [JupyterHub docs](https://jupyterhub.readthedocs.io/en/stable/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| jupyterhub | D | UI | No verified official Android; browser candidate | `notebooks.datamancy.net` | Hub DB, cookie/crypto secrets, user notebook home dirs, authenticator state; spawner details TBD. | Sign in, execute cell, save notebook; reopen after DB+home+keys restore. |

## kopia — [repository server](https://kopia.io/docs/repository-server/) / [repositories](https://kopia.io/docs/repositories/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| kopia | D? (server vs CLI schedule **unknown**) | UI **if** server enabled; otherwise H | No verified official Android | `backup.datamancy.net` **only if UI server and protected** | Encrypted repository at **separate chosen storage**, repository password/key, policies, config; never claim success from UI alone. | Back up a test file, inspect snapshot and restore bytes to an isolated path; off-host survivability is deferred. |

## loki — [Loki docs](https://grafana.com/docs/loki/latest/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| loki | D | API/H (not end-user UI) | N/A | — | Index/chunks/WAL/object store depending mode and retention; config. | Query labelled log after restart/restore within retention policy. |

## mailserver — [docker-mailserver upstream, identity NOT confirmed](https://docker-mailserver.github.io/docker-mailserver/latest/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| mailserver | D? (mail stack identity/version unknown) | H (SMTP/IMAP protocols) | Android mail clients exist; no project-specific official app established | `mail.datamancy.net` **mail host not web UI**; MX/SPF/DKIM/DMARC TBD | Mailboxes, queue, users, DKIM keys, TLS, aliases, spam rules; coordinate delivery during snapshot. | Send+receive external message over authorized SMTP/IMAP, restore message and DKIM identity; no SMTP open relay. |

## mariadb — [MariaDB backup docs](https://mariadb.com/kb/en/backup-and-restore-overview/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| mariadb | D | H (SQL) | N/A | — | Databases, users/grants, binlogs and consistent backup (logical/physical), config. | Write fixture, restore to isolated DB, compare rows/grants. |

## memcached — [Memcached](https://docs.memcached.org/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| memcached | D | H | N/A | — | Volatile cache; config only; **not** backup authority. | Cache hit after set; dependent app remains correct after cache loss. |

## node-exporter — [Prometheus node exporter](https://github.com/prometheus/node_exporter)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| node-exporter | D | H/metrics | N/A | — | Exporter config/collector options; no business data. | CPU/filesystem metric scraped with expected target labels. |

## ntfy — [phone client](https://docs.ntfy.sh/subscribe/phone/) / [config](https://docs.ntfy.sh/config/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| ntfy | D | UI/API | **Official ntfy Android** (Play, F-Droid, upstream releases) | `notify.datamancy.net` | Server config, auth DB, message cache/attachments if enabled, topic ACL, tokens. | Subscribe Android client to private test topic, publish, receive; restore auth/topic policy and retained messages per policy. |

## onboarding — [local inventory only](../../src/main/resources/services.json)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| onboarding | ? local-only (D/J unresolved) | ? | N/A pending owner spec | `start.datamancy.net` **only if confirmed UI** | Unknown; request implementation contract and data map. | Owner-defined completed onboarding creates intended access without leaking credentials; restore contract unknown. |

## onlyoffice — [ONLYOFFICE Docs](https://helpcenter.onlyoffice.com/docs/installation/docs-community-install-docker.aspx)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| onlyoffice | D | API/editor UI in host app | No separate official Android client claim for Docs server; mobile app compatibility TBD | `office.datamancy.net` **integration endpoint only; confirm WOPI/JWT** | Config, JWT secret, certificates and document integration; document master copies usually in host app, not editor cache. | Open/edit/save a Seafile document and retrieve updated source after coordinated restore. |

## opensearch — [OpenSearch docs](https://docs.opensearch.org/latest/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| opensearch | D | API; admin UI is separate Dashboards (not in IDs) | N/A | — | Indices, snapshots on external repository, security config/keys; not automatically canonical for every consumer. | Index/search fixture; restore snapshot if index authoritative, else rebuild and check search. |

## planka — [Planka upstream](https://github.com/plankanban/planka)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| planka | D | UI | No verified official Android; browser candidate | `boards.datamancy.net` | DB, attachments, secret/config. | Create card/checklist with attachment, move card, retrieve after restore. |

## portal — [local inventory only](../../src/main/resources/services.json)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| portal | ? local-only (D likely, **unverified**) | ? UI assumed pending contract | N/A | `datamancy.net` **proposal only** | Unknown: links, auth/session, app config and user data need contract. | User selects approved app and lands at correct authenticated route; owner to specify restore. |

## postgres — [PostgreSQL backup](https://www.postgresql.org/docs/current/backup.html)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| postgres | D | H (SQL) | N/A | — | Clusters/roles/db, WAL, extensions, version-compatible logical/physical backups. | Insert fixture then isolated restore with roles, constraints, app connection. |

## prometheus — [Prometheus storage](https://prometheus.io/docs/prometheus/latest/storage/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| prometheus | D | UI (admin/query) + metrics API | No verified official Android | `metrics.datamancy.net` (admin-only) | TSDB/WAL/rules/targets/config; snapshots if retention matters. | Query known metric and firing rule; restore config and historical range if required. |

## qbittorrent — [qBittorrent wiki](https://github.com/qbittorrent/qBittorrent/wiki)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| qbittorrent | D | UI (WebUI if enabled) | No verified official Android; third-party remotes not official | `torrents.datamancy.net` **private-only** | Torrent/session metadata, config and downloaded files; license/legal and egress policy TBD. | Add authorized test torrent, verify completed payload and session after restore. |

## seafile — [Seafile admin manual](https://manual.seafile.com/latest/) / [official mobile downloads](https://www.seafile.com/en/download/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| seafile | D | UI/API/WebDAV conditional | **Official Seafile Android** (`com.seafile.seadroid2` on [vendor download page](https://www.seafile.com/en/download/)); exact deployed version TBD | `files.datamancy.net` | DBs, blocks/objects, config/keys and sync state; atomic consistency across DB and storage. | Upload file from web/client, share, restore DB+blocks and download matching checksum. |

## searxng — [SearXNG admin docs](https://docs.searxng.org/admin/installation.html)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| searxng | D | UI/API | No verified official Android; browser candidate | `search.datamancy.net` | settings/secret, engine prefs; optional cache; minimal authoritative data. | Search a query and open result; restore configuration/engine settings. |

## sogo — [SOGo docs](https://www.sogo.nu/support.html)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| sogo | D | UI + CalDAV/CardDAV | No verified official Android; Android DAV clients vary | `groupware.datamancy.net` | SOGo SQL settings, calendars/contacts, session config; mailboxes in mailserver, not SOGo. | Add calendar event/contact; sync via DAV and retrieve after coordinated restore. |

## stack-foundation — [local inventory only](../../src/main/resources/services.json)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| volume-init | J? initialization helper **unverified** | H | N/A | — | Volume ownership/layout decisions; data resides on initialized volumes, not in job. | Run once idempotently against disposable volume; no permission regression or data deletion; ask owner for command. |

## valkey — [Valkey docs](https://valkey.io/topics/persistence/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| valkey | D | H (protocol) | N/A | — | RDB/AOF **if configured** and used for durable queues/session state; otherwise cache only; map per consumer. | Queue/session survives restart **if required**; restore RDB/AOF when authoritative. |

## erpnext — [Frappe background services](https://docs.frappe.io/framework/user/en/bench/resources/background-services) / [background jobs](https://docs.frappe.io/framework/user/en/api/background_jobs)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| erpnext | ? umbrella ID; role unresolved | ? | No verified official Android; browser candidate | — | No independent data established; site data belongs to bench/DB. | Owner must define whether ID actually starts process; no fabricated probe. |
| erpnext-backend | D | API (web requests; frontend dependent) | same product | — | MariaDB site DB plus `sites` assets/config, encryption keys. | Save invoice and view via approved frontend after restore. |
| erpnext-bootstrap | J? local helper | H | N/A | — | Site creation/install/migration effects in DB and sites; preserve site config and admin secrets. | Idempotent site setup/migration; verify installed ERPNext doctypes, no duplicate site. |
| erpnext-configurator | J? local helper | H | N/A | — | `common_site_config.json` and secrets; exact mutations unknown. | Generated config points to approved DB/cache endpoints; rerun does not erase custom keys. |
| erpnext-queue-long | D (worker) | H | N/A | — | Queue is in Redis/Valkey as configured; job output in DB/files. | Enqueue long job and observe committed result, not just worker health. |
| erpnext-queue-short | D (worker) | H | N/A | — | Same shared queue and site state. | Enqueue short job; observe completed task exactly once. |
| erpnext-scheduler | D | H | N/A | — | Scheduling state in site DB/cache; schedule config. | Scheduled test task fires once and persists intended DB effect. |
| erpnext-websocket | D | API/WebSocket | N/A | — (frontend upgrades to internal socket) | No independent canonical state; shared queue/config. | Browser receives real-time job update through approved ERPNext frontend. |

## firefly-iii — [official Docker importer](https://docs.firefly-iii.org/how-to/data-importer/installation/docker/) / [backup guidance](https://docs.firefly-iii.org/how-to/firefly-iii/advanced/backup/) / [cron](https://docs.firefly-iii.org/how-to/firefly-iii/advanced/cron/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| firefly | D | UI/API | No verified official Android; third-party clients must not be presented as official | `finance.datamancy.net` | DB, uploads, APP_KEY, env/DB credentials; export is **not** a backup (upstream). | Create account and transaction; restore DB+uploads+APP_KEY and compare balance. |
| firefly-cron | J periodic | H | N/A | — | No independent data; mutations to Firefly DB; CLI token/cron secret. | Recurring transaction executes once on schedule; no duplicate after restart. |
| firefly-identity-check | J? local helper | H | N/A | — | Unknown; inspect contract, may check IdP state. | Owner defines what identity is checked; fail closed on mismatch. |
| firefly-importer | D | UI/API | same product | `import.finance.datamancy.net` **only if independently exposed** | Import config/tokens and staging files if used; posted transactions in Firefly DB. | Upload sample bank CSV, map columns, import exactly once; verify ledger entries. |
| firefly-importer-sso | ? local integration helper | ? | N/A | — | Unknown SSO credentials/redirect mapping. | Authenticate importer with approved IdP and return to importer; exact behavior TBD. |
| firefly-native-api | ? local shim (NOT upstream Firefly API identity proof) | API? | N/A | — | Unknown mapping/tokens/state; require spec. | Owner-defined authorized client API call; never expose by default. |
| firefly-sso | ? local integration helper | ? | N/A | — | Unknown IdP client secrets/session config. | Login via approved IdP without bypass; confirm logout semantics. |

## huly — [upstream *development* compose](https://github.com/hcengineering/platform/raw/refs/heads/main/dev/docker-compose.yaml) (not a production deployment contract)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| huly-account | D | API | No verified official Android; browser/desktop candidates | — | Account records in CockroachDB; secrets/config. | Register authorized account and sign in after account-DB restore. |
| huly-cockroach | D | H (SQL) | N/A | — | Cockroach cluster data, certificates, backups; upstream dev uses single insecure node **do not copy**. | Restore accounts/workspace records to isolated cluster. |
| huly-collaborator | D | API/WebSocket | N/A | — | Collaborative changes persisted via workspace/db/object store; no standalone data asserted. | Two users edit same doc and see merged content after restore. |
| huly-elastic | D | API/H | N/A | — | Search index; rebuildability/version must be established. | Search newly indexed document; restore or rebuild index with verified results. |
| huly-front | D | UI | browser/desktop candidate; Android official unverified | `work.datamancy.net` | Front config/branding; canonical workspace state elsewhere. | Sign in, create issue/document and find it after coordinated restore. |
| huly-fulltext | D | API/H | N/A | — | Indexing config; Elasticsearch index shared; source Cockroach/objects. | Search document text after upload and after index recovery. |
| huly-kvs | ? (ID not in cited dev compose; implementation unclear) | H? | N/A | — | Unknown; ask whether durable key/value store and snapshot contract. | Owner defines write/read/restore or declares ephemeral. |
| huly-minio | D | API/H (object storage) | N/A | — | Buckets/objects, policies, encryption/credentials; coordinate with DB. | Upload attachment via Huly and recover identical bytes after object+DB restore. |
| huly-redpanda | D | H (stream bus) | N/A | — | Kafka log/offsets/cluster config; replayability and retention TBD. | Event reaches consumer once and workflow settles after restart. |
| huly-rekoni | D | API/H | N/A | — | Derived preview/text extraction; no independent canonical state verified. | Uploaded document has extracted searchable text. |
| huly-stats | D | API/H | N/A | — | Observability telemetry/config; independent retention TBD. | Record service metric/error; verify authorized internal visibility. |
| huly-transactor | D | API/WebSocket | N/A | — | Writes CockroachDB/object store; secret/config. | Edit issue and confirm persisted result via second client after restore. |
| huly-workspace | D (worker; upstream dev `WS_OPERATION=all+backup`) | H | N/A | — | Cockroach workspaces, MinIO blobs and **configured external backup target**; verify local runtime flags. | Create workspace; trigger/verify backup then restore to isolated workspace, preserving attachments. |

## keycloak — [Keycloak server guide](https://www.keycloak.org/server/containers)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| keycloak | D | UI (admin/account) + OIDC API | No separate official Android server app; browser/OIDC clients | `auth.datamancy.net` | Realm/users/clients in DB, signing keys, secrets/theme/config; restore issuer stable. | Login to an approved client; restore realm and validate old/new session policy. |
| keycloak-bootstrap | J? custom provisioner | H | N/A | — | Writes realm/client configuration to Keycloak DB; bootstrap secrets. | Idempotently create intended realm/client/roles, no new client secrets on rerun unless approved. |

## keycloak-auth-gateway — [Keycloak authorization services concepts](https://www.keycloak.org/docs/latest/authorization_services/) **not documentation for this custom binary**

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| keycloak-auth-gateway | D? custom gateway | API/H? | N/A | — (auth subrequests on protected routes) | Unknown session/allowlist/token cache; require local spec. | Unauthorized user denied protected URL; authorized user returns correctly; no redirect loop. |
| keycloak-configure | J? custom provisioner | H | N/A | — | Writes gateway/Keycloak config; exact effect unknown. | Idempotent configuration with owner-approved redirects/scopes. |

## livekit — [LiveKit deployment](https://docs.livekit.io/transport/self-hosting/deployment/) / [MatrixRTC JWT bridge](https://github.com/element-hq/lk-jwt-service)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| livekit | D | API/WebRTC (not standalone UI) | Via Element compatible Android client (version/MatrixRTC support TBD) | `rtc.datamancy.net` **WSS plus separate TURN/UDP ports/domain** | API keys/secrets, room policy, Redis if used; media ephemeral unless recording configured. | Join room with two authorized Element clients; hear audio through real external NAT; no promise of recording. |
| matrix-rtc-auth | D? bridge identity **unverified** (compare `lk-jwt-service`) | API/H | N/A | `rtc-auth.datamancy.net` **only if client/MSC requires** | LiveKit signing credentials, Matrix homeserver access and deployment config; backing DB unknown. | Authenticated Matrix user receives scoped call token; unauthorized user denied; confirm exact product/image first. |

## mastodon — [upstream docs](https://docs.joinmastodon.org/admin/install/) / [backup](https://docs.joinmastodon.org/admin/backups/)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| mastodon-init | J? local bootstrapping | H | N/A | — | Migration effects in PostgreSQL; keys/env. | Run migration once idempotently, preserve existing posts. |
| mastodon-recommendation-seeder | J? local-specific | H | N/A | — | Recommendation records in DB? unknown; verify source/behavior. | Seed expected recommendations once with audit trail; owner defines source feed. |
| mastodon-sidekiq | D (job worker) | H | N/A | — | Redis queue, DB/posts/media and delivery state; coordinate restore. | Send authorized post; confirm outbound federation/notification delivery. |
| mastodon-storage-init | J? local-specific | H | N/A | — | Media bucket/volume permissions and config; no data deletion. | Rerun leaves prior media intact and writable. |
| mastodon-streaming | D | API/WebSocket | N/A | — (path on web origin if required) | No independent canonical data; DB/Redis upstream. | Authenticated timeline receives new post without refresh. |
| mastodon-web | D | UI/API | **[Official Android Mastodon app](https://docs.joinmastodon.org/user/official-ios-android-app-user-guide/)** | `social.datamancy.net` **immutable federation domain decision** | PostgreSQL, Redis queue, media, env signing keys, email/TLS; federation identity/domain not freely migratable. | Publish with image, view from remote instance and Android app; restore post/media/identity. |

## mastodon-rss-publisher — [Mastodon API](https://docs.joinmastodon.org/client/intro/) **local automation IDs not upstream documented**

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| mastodon-rss-account-bootstrap | J? custom | H | N/A | — | Account/token in Mastodon DB + automation secret; ownership and scopes unknown. | Provision dedicated least-privilege account without duplicates; manual owner approval. |
| mastodon-rss-publisher | D? periodic worker or J? | H | N/A | — | Feed checkpoint/dedupe, OAuth token, Mastodon posts; exact implementation unknown. | Publish one permitted RSS item once; rerun must not duplicate post. |
| mastodon-rss-state-init | J? custom | H | N/A | — | Creates checkpoint/state store; backend/location unknown. | Initialize without clobbering prior cursor; repeat with unchanged state. |

## matrix-authentication-service — [MAS setup](https://element-hq.github.io/matrix-authentication-service/) / [database](https://element-hq.github.io/matrix-authentication-service/setup/database.html)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| matrix-authentication-service | D | UI login/consent + OIDC API | Via compatible Element Android client; version TBD | `login.datamancy.net` (issuer/redirect owner decision) | **PostgreSQL dedicated DB** (upstream), signing keys/config, client/session secrets; preserve issuer. | Sign in and renew Matrix client session; recover accounts after isolated DB+keys restore. |
| matrix-authentication-service-db | D? local separate DB service (verify actual engine) | H | N/A | — | Upstream MAS requires PostgreSQL; snapshot DB incl roles/WAL for this service. | Restore MAS users/clients/session policy in isolated instance. |
| matrix-authentication-service-keys | J? local key generator | H | N/A | — | **Signing keys essential**; must never regenerate on every restart. | Repeat startup preserves key identity; issuer tokens verify per intended rollover policy. |

## postgres-ssd — [PostgreSQL backup](https://www.postgresql.org/docs/current/backup.html) **SSD placement is local, not upstream feature**

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| postgres-ssd | D | H (SQL) | N/A | — | Dedicated cluster on SSD; roles/DB/WAL, backup target outside same SSD. | Write fixture, simulate SSD failure via isolated restore, check roles/data. |
| postgres-ssd-bootstrap | J? local helper | H | N/A | — | Init roles/databases/bootstrap creds; exact targets unknown. | Run twice; no dropped DB/rotated creds; apps connect to expected databases. |

## synapse — [Synapse admin docs](https://element-hq.github.io/synapse/latest/usage/administration/) / [backups](https://element-hq.github.io/synapse/latest/usage/administration/backups.html)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| synapse | D | Matrix API (not user UI) | Element Android app (client, **not** Synapse app) | `matrix.datamancy.net` plus `.well-known` delegation/federation **owner decision** | Homeserver DB, media, signing keys, server_name, MAS integration secrets, federation state. | Send E2EE message across two accounts and federation; restore media/DB/keys on isolated host. |
| synapse-permissions | J? local helper | H | N/A | — | Filesystem ownership/mode for media/config/keys; never reset data. | Rerun preserves key/data integrity and appropriate least privilege. |
| synapse-room-bootstrap | J? local helper | H | N/A | — | Room state in Synapse DB; access token; exact rooms unknown. | Create intended room once, repeat without duplicate or unintended invite. |

## test-runners — [Android Emulator docs](https://developer.android.com/studio/run/emulator) / [local IDs](../../src/main/resources/services.json)

| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |
|---|---|---|---|---|---|---|
| android-test-runner-api34 | ? test helper (daemon/ephemeral job TBD) | H | **Android API 34 test target, not product app** | — | Test artifacts/logs if required; emulator data disposable unless contract says otherwise. | Launch pinned API 34 image, run approved test, produce trace/artifact (not production backup). |
| android-test-runner-api36 | ? test helper (daemon/ephemeral job TBD) | H | **Android API 36 test target, not product app** | — | Same; isolate emulator credentials/data. | Run approved API 36 test; capture result/artifact. |
| test-runner | ? test helper | H | N/A | — | Test fixtures/artifacts only, source of truth external; exact runner unknown. | Execute identified suite against disposable endpoint and emit reproducible report. |
| test-runner-managed | ? custom test orchestrator | H | N/A | — | Test-run metadata/artifacts/credentials unknown. | Orchestrate approved jobs, retain reports and clean ephemeral workers; contract TBD. |

**Release provenance to pin at integration time (not pinned here):** [Jellyfin Android releases](https://github.com/jellyfin/jellyfin-android/releases), [Home Assistant Android releases](https://github.com/home-assistant/android/releases), [ntfy Android releases](https://github.com/binwiederhier/ntfy-android/releases), [Seafile Android releases](https://github.com/haiwen/seadroid/releases), [Element X Android releases](https://github.com/element-hq/element-x-android/releases), [Mastodon Android releases](https://github.com/mastodon/mastodon-android/releases), [Forgejo server releases](https://forgejo.org/releases/), [MAS releases](https://github.com/element-hq/matrix-authentication-service/releases). Release-page links are provenance pointers, **not** a claim that any specific tag/image is chosen or installed. Confirm package, signing, architecture and compatibility with the approved endpoint before adoption.\n\n**Coverage caveat:** proposed routes are grouped product entry points only, not one hostname per ID. API-only or internal workers should not receive a public browser route merely because the inventory names them. Official Android candidate != a tested version, working push, or managed APK. Confirm release metadata/package/signing and endpoint compatibility before adoption. The Huly cited compose is explicitly `dev` and uses insecure local examples; never deploy those values.
