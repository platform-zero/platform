# Fresh r9 / pinned OLD service memory and lifecycle inventory

This is a source comparison, **not** a capacity admission or native RSS.
Pinned generator `92aaf2c9bbeea10c6cbe1b91bbc3950dda6548431ffd80fadf35629ee1deb1e6`: missing descriptor limits
receive a limit only if the active OLD policy supplied `resource_defaults.memory`;
a supporting OLD Quadlet `--memory` is separately observed, not an RSS sample.
Current fresh process ceilings: 68736 MiB steady; 2048 MiB largest serial one-shot; observed host MemAvailable at audit: 47901 MiB. No r9 process RSS exists because no full stack has been started.

# Current selected processes (132 rows)

| Product | Current process | Lifecycle | Cap MiB | Current heap/worker command clues | OLD direct descriptor cap | OLD Quadlet cap | OLD lifecycle | Mapping |
|---|---|---|---:|---|---|---|---|---|
| postgres | postgres-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| postgres | postgres | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| forgejo | forgejo-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| forgejo | forgejo-migrate | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| forgejo | forgejo-owner-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| forgejo | forgejo-db-finalize | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| forgejo | forgejo | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| valkey | valkey | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| ntfy | ntfy | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| planka | planka-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| planka | planka-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| planka | planka-db-finalize | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| planka | planka | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| mariadb | mariadb-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mariadb | mariadb | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| memcached | memcached | selected steady | 128 | not in command | unspecified | 2G | daemon | same-module-service |
| keycloak | identity-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keycloak | identity-realm-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keycloak | identity-db-finalize | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keycloak | keycloak | selected steady | 1024 | not in command | ${KEYCLOAK_MEMORY_LIMIT:-2G} | 2G | daemon | same-module-service |
| alertmanager | alertmanager | selected steady | 128 | not in command | unspecified | 2G | daemon | same-module-service |
| prometheus | prometheus | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| loki | loki | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| alloy | alloy | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| node-exporter | node-exporter | selected steady | 128 | not in command | unspecified | 2G | daemon | same-module-service |
| grafana | grafana | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| bookstack | bookstack-files-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| bookstack | bookstack-migrate | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| bookstack | bookstack-php | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| bookstack | bookstack | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| caddy | caddy | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| crowdsec | crowdsec-guard-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| crowdsec | guard | selected steady | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| donetick | donetick | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| element | element-web | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | erp-native-site-install | oneshot | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | erp-redis-bridge | selected steady | 128 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | erp-maria-cutover | oneshot | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | backend | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | websocket | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | worker | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | scheduler | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| erpnext | erp | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-db-finalize | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-files-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-migrate | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-php | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly | selected steady | 256 | not in command | 1g | no matched Quadlet | daemon | same-module-service |
| firefly-iii | firefly-users-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-runtime-config | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-native-api | selected steady | 256 | not in command | 256m | no matched Quadlet | daemon | same-module-service |
| firefly-iii | firefly-importer-files-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| firefly-iii | firefly-importer | selected steady | 1024 | not in command | 1g | no matched Quadlet | daemon | same-module-service |
| firefly-iii | firefly-sso | selected steady | 256 | not in command | 256m | no matched Quadlet | daemon | same-module-service |
| firefly-iii | firefly-importer-sso | selected steady | 256 | not in command | 256m | no matched Quadlet | daemon | same-module-service |
| homeassistant | homeassistant-config-init | oneshot | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| homeassistant | homeassistant | selected steady | 2048 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-cockroach | selected steady | 2048 | not in command | 2G | 2G | daemon | same-module-service |
| huly | huly-database-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-elastic-config-init | oneshot | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-elastic | selected steady | 1536 | not in command | 2G | 2G | daemon | same-module-service |
| huly | huly-elastic-users | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-objects | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-redpanda | selected steady | 1024 | --memory=512M | 2G | 2G | daemon | same-module-service |
| huly | huly-stats | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-account-bootstrap | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-account | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-workspace | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-transactor | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-collaborator | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-rekoni | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-fulltext | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-front | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly-kvs | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| huly | huly | selected steady | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| huly | huly-redpanda-acl | oneshot | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jellyfin | jellyfin-media-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jellyfin | jellyfin | selected steady | 2048 | not in command | unspecified | 2G | daemon | same-module-service |
| jupyter-notebook | notebook-init | oneshot | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jupyter-notebook | notebook | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jupyterhub | alice | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jupyterhub | bob | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jupyterhub | hub | selected steady | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| jupyterhub | hub-controller | selected steady | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keycloak-auth-gateway | auth-gateway | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keykeeper | keeper-trust-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| keykeeper | keeper | selected steady | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| livekit | livekit | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |
| livekit | rtc-authorizer | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| livekit | rtc-web | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mailserver | mail-init | oneshot | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mailserver | mail | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-db-migrate | oneshot | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-fresh-users | oneshot | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-rss-feature | oneshot | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-db-finalize | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon | selected steady | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | sidekiq | selected steady | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | streaming | selected steady | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | social | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-bridge-journal-init | oneshot | 128 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| mastodon | mastodon-redis-bridge | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| matrix-authentication-service | mas-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| matrix-authentication-service | mas-migrate | oneshot | 768 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| matrix-authentication-service | mas-config-init | oneshot | 768 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| matrix-authentication-service | mas | selected steady | 768 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| onlyoffice | onlyoffice-state-init | oneshot | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| onlyoffice | onlyoffice-docservice | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| onlyoffice | onlyoffice-front | selected steady | 2048 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| openbao | bao | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| opensearch | opensearch-config-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| opensearch | opensearch | selected steady | 2048 | not in command | ${OPENSEARCH_MEMORY_LIMIT:-3G} | 3G | daemon | same-module-service |
| opensearch | opensearch-security-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| portal | portal | selected steady | 256 | not in command | unspecified | 2G | daemon | same-module-service |
| qbittorrent | qbittorrent-config-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| qbittorrent | qbittorrent | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| seafile | seafile-schema-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| seafile | seafile-server | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| seafile | seafile-users-init | oneshot | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| seafile | seafile-backend | selected steady | 1024 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| seafile | seafile-files | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| searxng | searxng-corpus-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| searxng | searxng | selected steady | 512 | not in command | unspecified | 2G | daemon | same-module-service |
| searxng | searxng-web | selected steady | 256 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| sogo | sogo-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| sogo | sogod | selected steady | 1536 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| sogo | groupware | selected steady | 384 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| synapse | synapse-db-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| synapse | synapse-signing-key-init | oneshot | 512 | not in command | unspecified | no matched Quadlet | unmatched | unmatched-needs-dedicated-recipe-review |
| synapse | synapse | selected steady | 1024 | not in command | unspecified | 2G | daemon | same-module-service |

# Every pinned OLD descriptor service (94 rows)

| OLD module/service | Lifecycle | Descriptor hard cap | Supporting Quadlet hard cap | Worker/heap descriptor settings | Descriptor source |
|---|---|---|---|---|---|
| alertmanager/alertmanager | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/alertmanager/legacy/stack.runtime.yaml |
| alloy/alloy | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/alloy/legacy/stack.runtime.yaml |
| bookstack/bookstack | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/bookstack/legacy/stack.runtime.yaml |
| bookstack/bookstack-procedural-docs | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/bookstack/legacy/stack.runtime.yaml |
| caddy/caddy | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/caddy/legacy/stack.runtime.yaml |
| crowdsec/crowdsec | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/crowdsec/legacy/stack.runtime.yaml |
| donetick/donetick | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/donetick/legacy/stack.runtime.yaml |
| element/element | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/element/legacy/stack.runtime.yaml |
| erpnext/erpnext-configurator | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-bootstrap | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-backend | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-websocket | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-queue-short | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-queue-long | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext-scheduler | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| erpnext/erpnext | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/erpnext/legacy/stack.runtime.yaml |
| firefly-iii/firefly-identity-check | oneshot | 512m | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly | daemon | 1g | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly-sso | daemon | 256m | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly-native-api | daemon | 256m | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly-cron | daemon | 4g | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly-importer | daemon | 1g | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| firefly-iii/firefly-importer-sso | daemon | 256m | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/firefly-iii/legacy/stack.runtime.yaml |
| forgejo/forgejo | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/forgejo/legacy/stack.runtime.yaml |
| forgejo-runner/forgejo-runner | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/forgejo-runner/legacy/stack.runtime.yaml |
| grafana/grafana | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/grafana/legacy/stack.runtime.yaml |
| homeassistant/homeassistant | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/homeassistant/legacy/stack.runtime.yaml |
| huly/huly-cockroach | daemon | 2G | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-redpanda | daemon | 2G | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-minio | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-elastic | daemon | 2G | 2G | ES_JAVA_OPTS=-Xms1024m -Xmx1024m | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-rekoni | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-stats | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-transactor | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-collaborator | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-account | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-workspace | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-front | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-fulltext | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| huly/huly-kvs | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/huly/legacy/stack.runtime.yaml |
| jellyfin/jellyfin | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/jellyfin/legacy/stack.runtime.yaml |
| jupyter-notebook/jupyter-notebook-build | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/jupyter-notebook/legacy/stack.runtime.yaml |
| jupyterhub/jupyterhub | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/jupyterhub/legacy/stack.runtime.yaml |
| keycloak/keycloak-bootstrap | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/keycloak/legacy/stack.runtime.yaml |
| keycloak/keycloak | daemon | ${KEYCLOAK_MEMORY_LIMIT:-2G} | 2G | JAVA_OPTS_KC_HEAP=-XX:InitialRAMPercentage=35 -XX:MaxRAMPercentage=60 | /tmp/p0-old-integrated-descriptors-36b6b7/modules/keycloak/legacy/stack.runtime.yaml |
| keycloak-auth-gateway/keycloak-configure | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/keycloak-auth-gateway/legacy/stack.runtime.yaml |
| keycloak-auth-gateway/keycloak-auth-gateway | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/keycloak-auth-gateway/legacy/stack.runtime.yaml |
| kopia/kopia | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/kopia/legacy/stack.runtime.yaml |
| legal-research-mcp/legal-research-db-bootstrap | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/legal-research-mcp/legacy/stack.runtime.yaml |
| legal-research-mcp/legal-research-mcp | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/legal-research-mcp/legacy/stack.runtime.yaml |
| livekit/livekit | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/livekit/legacy/stack.runtime.yaml |
| livekit/matrix-rtc-auth | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/livekit/legacy/stack.runtime.yaml |
| loki/loki | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/loki/legacy/stack.runtime.yaml |
| mailserver/mailserver | daemon | ${MAILSERVER_MEMORY_LIMIT:-4G} | 4G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mailserver/legacy/stack.runtime.yaml |
| mariadb/mariadb | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mariadb/legacy/stack.runtime.yaml |
| mastodon/mastodon-storage-init | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon/mastodon-init | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon/mastodon-web | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon/mastodon-streaming | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon/mastodon-sidekiq | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon/mastodon-recommendation-seeder | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon/legacy/stack.runtime.yaml |
| mastodon-rss-publisher/mastodon-rss-state-init | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon-rss-publisher/legacy/stack.runtime.yaml |
| mastodon-rss-publisher/mastodon-rss-account-bootstrap | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon-rss-publisher/legacy/stack.runtime.yaml |
| mastodon-rss-publisher/mastodon-rss-publisher | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/mastodon-rss-publisher/legacy/stack.runtime.yaml |
| matrix-authentication-service/matrix-authentication-service-db | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/matrix-authentication-service/legacy/stack.runtime.yaml |
| matrix-authentication-service/matrix-authentication-service-keys | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/matrix-authentication-service/legacy/stack.runtime.yaml |
| matrix-authentication-service/matrix-authentication-service | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/matrix-authentication-service/legacy/stack.runtime.yaml |
| memcached/memcached | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/memcached/legacy/stack.runtime.yaml |
| node-exporter/node-exporter | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/node-exporter/legacy/stack.runtime.yaml |
| ntfy/ntfy | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/ntfy/legacy/stack.runtime.yaml |
| ntfy/ntfy-native-auth | daemon | unspecified | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/ntfy/legacy/stack.runtime.yaml |
| onboarding/onboarding | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/onboarding/legacy/stack.runtime.yaml |
| onlyoffice/onlyoffice | daemon | ${ONLYOFFICE_MEMORY_LIMIT:-4G} | 4G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/onlyoffice/legacy/stack.runtime.yaml |
| opensearch/opensearch | daemon | ${OPENSEARCH_MEMORY_LIMIT:-3G} | 3G | OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g, bootstrap.memory_lock=true | /tmp/p0-old-integrated-descriptors-36b6b7/modules/opensearch/legacy/stack.runtime.yaml |
| planka/planka | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/planka/legacy/stack.runtime.yaml |
| portal/portal | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/portal/legacy/stack.runtime.yaml |
| postgres/postgres | daemon | 8G | 8G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/postgres/legacy/stack.runtime.yaml |
| postgres-ssd/postgres-ssd | daemon | 8G | 8G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/postgres-ssd/legacy/stack.runtime.yaml |
| postgres-ssd/postgres-ssd-bootstrap | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/postgres-ssd/legacy/stack.runtime.yaml |
| prometheus/market-data-exporter | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/prometheus/legacy/stack.runtime.yaml |
| prometheus/prometheus | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/prometheus/legacy/stack.runtime.yaml |
| qbittorrent/qbittorrent | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/qbittorrent/legacy/stack.runtime.yaml |
| seafile/seafile | daemon | ${SEAFILE_MEMORY_LIMIT:-2G} | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/seafile/legacy/stack.runtime.yaml |
| searxng/searxng | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/searxng/legacy/stack.runtime.yaml |
| sogo/sogo | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/sogo/legacy/stack.runtime.yaml |
| stack-foundation/volume-init | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/stack-foundation/legacy/stack.runtime.yaml |
| synapse/synapse-permissions | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/synapse/legacy/stack.runtime.yaml |
| synapse/synapse | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/synapse/legacy/stack.runtime.yaml |
| synapse/synapse-room-bootstrap | oneshot | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/synapse/legacy/stack.runtime.yaml |
| test-runners/android-test-runner-api36 | on-demand | 12G | 12G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/test-runners/legacy/stack.runtime.yaml |
| test-runners/android-test-runner-api34 | on-demand | 12G | 12G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/test-runners/legacy/stack.runtime.yaml |
| test-runners/test-runner | on-demand | ${TEST_RUNNER_MEMORY_LIMIT:-4G} | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/test-runners/legacy/stack.runtime.yaml |
| test-runners/test-runner-managed | on-demand | ${TEST_RUNNER_MEMORY_LIMIT:-4G} | unmatched/none | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/test-runners/legacy/stack.runtime.yaml |
| valkey/valkey | daemon | unspecified | 2G | not explicit | /tmp/p0-old-integrated-descriptors-36b6b7/modules/valkey/legacy/stack.runtime.yaml |

# Supporting OLD Quadlets without an exact descriptor service name

| Quadlet name | Cap | Source |
|---|---|---|
| vaultwarden | 2G | /home/gerald/huly-oidc-20260923/quadlet/rootless-vaultwarden/webservices-vaultwarden.container |
| vaultwarden-maintenance | 2G | /home/gerald/huly-oidc-20260923/quadlet/rootless-vaultwarden/webservices-vaultwarden-maintenance.container |
| workload-spawner-api | 2G | /home/gerald/huly-oidc-20260923/quadlet/rootless-workloads/webservices-workload-spawner-api.container |
| workload-spawner-postgres | 2G | /home/gerald/huly-oidc-20260923/quadlet/rootless-workloads/webservices-workload-spawner-postgres.container |
| workload-spawner-router | 2G | /home/gerald/huly-oidc-20260923/quadlet/rootless-workloads/webservices-workload-spawner-router.container |

## Read-only retained memory observation

`retained-legacy-memory-observation-285.tsv` observed 109 legacy running
containers with approximately **8,367 MB Podman `MemUsage`** at one instant;
`retained-canonical-memory-observation-285.tsv` had zero running containers.
This metric includes cgroup memory/cache and is **not RSS**, a frozen workload
forecast, or a substitute for per-generation effective admission. At the
source audit, host `MemAvailable` was 47,907 MiB; preserving 16,384 MiB
headroom leaves no more than 31,523 MiB for *additional measured/proven*
resident use at that instant, before backup, CI, managed lanes and transient
work. This arithmetic is not a permission to start a partial cohort or to
assume all fresh ceilings simultaneously resident.

## Split recipe and on-demand findings

| OLD service/role | OLD cap evidence | Fresh selected split | Aggregate fresh ceiling | Decision |
|---|---:|---|---:|---|
| `onlyoffice` | descriptor 4G, Quadlet 4G | `onlyoffice-docservice` + `onlyoffice-front` | 4096 MiB | Same aggregate ceiling; split is not proof of inflated application memory. |
| `jupyterhub` | Quadlet 2G | `hub-controller` + `hub` | 2048 MiB | Same aggregate for hub; separate `alice`/`bob` agents add 4096 MiB selected steady without an OLD hub-daemon precedent. Their availability must be native on-demand, not merely relabelled in an audit. |
| `seafile` | descriptor/Quadlet 2G | `seafile-server` (1024) + `seafile-backend` (1024; two Gunicorn workers/two threads) + `seafile-files` (256; one nginx worker/512 connections; 10 MiB bodies spool to disk) | **2304 MiB** | r9-only `seafile/r2` corrects the isolated 1 GiB nginx proxy ceiling to an explicit 256 MiB design bound: one nginx worker, 512 connections, disk-spooled request bodies, and the existing 128 MiB tmpfs limit (which also counts against its cgroup). The 256 MiB split margin above OLD 2G remains intentional; a native concurrent-upload/TLS readback must still test it before admission. Each service retains a hard cap; admitted *working* memory is still unmeasured and must be qualified separately. |
| `firefly` + importer + two SSO peers | OLD 1G + 1G + 256m + 256m | `firefly-php`, `firefly-importer`, `firefly-sso`, `firefly-importer-sso` | 2560 MiB | Same total as explicit OLD services; independent SSO grants are a v3 requirement. |
| PostgreSQL | OLD postgres-ssd descriptor/Quadlet 8G | one shared `postgres` | 2048 MiB | Current is already below OLD ceiling; do not duplicate one provider per recipe. |
| `erpnext` group | eight OLD daemon Quadlets each 2G | v3 split backend, worker, scheduler, redis bridge, etc. | See per-process table | OLD generator defaults and current split differ; compare worker counts under load, never sum eight OLD maxima as an RSS requirement. |

**One r9-only cap was corrected:** Seafile's nginx proxy from 1024 to 256 MiB;
no application server cap was changed. All 41 directly mapped current processes
have OLD descriptor or supporting-Quadlet hard ceilings and none exceeds them.
The Seafile proxy correction follows its one-worker configuration, not an attempt to force the cap sum under physical RAM; the two application processes retain 1 GiB caps each. Its +256 MiB aggregate margin is deliberate until native measurement.
The dangerous excess is treating on-demand notebooks as always-on; correct their native lifecycle before changing a limit. This audit rejects both unexamined cap summation and unsupported cap reductions.

## Admission implications

- A container `--memory` is an upper ceiling, not reserved resident memory. Do not infer hardware shortage from a sum of maxima.
- OLD missing service limits are not evidence that lowering an explicitly bounded fresh process is safe.
- The r9 `alice`/`bob` notebook agents are currently selected steady even though their *in-container* JupyterHub single-user processes start on login; OLD test runtimes are on-demand. Native container on-demand scheduling, Hub spawning and readback are required before reclassifying their 4096 MiB of hard ceilings as nonconcurrent.
- Native broker/CI guard, retained generations, backup scratch, workers, image staging and disk must be measured/qualified separately while retaining 16384 MiB available memory and 10240 MiB disk.
- Provider consolidation and serial one-shots avoid multiplying OLD provider caps. No cap is lowered solely to force admission.

