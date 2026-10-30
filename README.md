# Platform Zero v3 — platform

New Kotlin/KTS implementation. This repository owns the platform, service inventory, deployment, site model, SSO and lane integration. It does not copy the old P0 generator or its source code.

`src/main/resources/services.json` records exactly the 89 service IDs supplied by the owner: 34 single-service and 55 multi-service entries in 46 *named* modules. A prior report mentioned 57 modules but did not identify 11 of them; do not invent them. **All entries are inventory-only. Nothing is installed or accepted.** Keykeeper and the v3 lane product are additional components, not counted in those 89.

Using Java 21: `./gradlew test`, `./gradlew run --args='catalog validate'`, `./gradlew run --args='catalog list'`. Bulk Gradle cache can be kept under `/mnt/media/p0-v3/cache/gradle-user` with `GRADLE_USER_HOME`.

## Explicit host-local site plans (offline only)

`sites.json` is a **separate operator-supplied** schema, not the inventory. For example (the digest below is only a syntax example, **not** a verified/pullable image):

```json
{"schemaVersion":1,"sites":[{"id":"scratch","workloads":[{"id":"probe","image":"docker.io/library/busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}
```

Commands: `site validate <sites.json> <site-id>`, `plan render <sites.json> <site-id>`, `stage offline <sites.json> <site-id> <temp-workspace>`, `stage restore <temp-workspace> <site-id>` (use `./gradlew run --args='…'`). The workspace must be an existing directory **beneath the system temp directory**, initially empty; subsequent operations require its site marker. Staging writes `current/` Quadlet files and a checksum manifest, saves one previous version, and restore rolls back one version (or removes the first stage). It rejects unexpected files and modified stages. It never starts containers, installs units, pulls images, publishes ports, mounts volumes, edits production directories, or manages live services. No active deploy or functional restoration is claimed.

Site/workload IDs are bounded slugs; workloads must be explicitly named, cannot reuse any inventory service ID, and require a SHA-256-pinned image reference. Unknown config fields (including secrets, environment, routes and mounts) are rejected. Render order is stable; each file uses `Network=none` and `ReadOnly=true`. The JSON render plan includes the Quadlet text and is safe to compare in tests, but should **not** be interpreted as acceptance of that image or application. The isolated staging and rollback tests check filesystem behavior only. Do not copy these files to a live Quadlet search path until an independently reviewed deployment, backup, functional restore and acceptance process exists.

## Non-negotiable boundaries

- SSO: distinct Keycloak identities for each human and agent, equal application policy across stack services; one host Linux account per human for their v3 lanes.
- Worklane evolves separately at `github.com/geraldsummers/worklane`; do not alter the active `software_lab` installation or its project data. New v3 lanes replace Herdr with TUIOS. Agents can contact and receive replies from users through Matrix/Element.
- Source-only development here: no installing on the real host until v3-only account, storage and reset boundaries are explicit and independently tested. The real-domain gate is at `datamancy.net` through Cloudflare.
- Backups to `/mnt/media/p0-v3` must be automatically tested by isolated restore, then by real functional tests. Never infer success from an artifact alone.
- Acceptance cases are independently owned under `../acceptance`; implementation unit tests do not assert release readiness.
