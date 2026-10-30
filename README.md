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

## Verified unit coverage gate

Run `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user ./gradlew clean check --offline` to run the tests and the JaCoCo **LINE** covered-ratio verification gate (minimum **90%**, bundle-wide, all production JVM classes; no class, package or source exclusions). The `check` task depends on `jacocoTestCoverageVerification`, which depends on the XML/HTML report and tests. From a clean run: **236 covered / 243 total production Kotlin lines = 97.12%** (7 missed), with **18 tests, 0 failures**. Source breakdown: `Sites.kt` 43/43, `LaneAccounts.kt` 50/51, `Catalog.kt` 26/27, `IsolatedStage.kt` 81/86, `Main.kt` 36/36. Report: `build/reports/jacoco/test/jacocoTestReport.xml` and `build/reports/jacoco/test/html/index.html`. This is unit/CLI/offline filesystem coverage, **not** functional deployment, backup/restore proof or full-stack acceptance.

## Offline SSO-to-Linux lane-account intents

The separate `lane plan <request.json> <trusted-issuer> <occupied-usernames.json>` command emits **JSON data only**. No useradd, account database reads, PAM changes, directory creation, SSO changes, or live service operations occur. Example request (identifiers are illustrative, not a verified SSO deployment):

```json
{"schemaVersion":1,"siteId":"scratch","issuer":"https://sso.example.test/realms/v3","humans":[{"subject":"opaque-human-a","username":"p0v3_alice"}],"agentSubjects":["opaque-agent-a"]}
```

The independently supplied trusted HTTPS issuer must **exactly** match the request. Subjects are bounded, case-sensitive opaque IDs; duplicates among humans or across human/agent identities are rejected. Each human has exactly one explicit bounded `p0v3_` username; duplicate names, reserved suffixes (including `gerald`, `software_lab`, `root`, `agent`), unsafe names, and names in the supplied occupied-username snapshot are rejected. The snapshot is a nonempty JSON string array of Linux usernames, e.g. `["root","gerald","software_lab"]`; the planner does **not** collect it from the host or assert it is fresh/complete. The plan is sorted by username and contains no account command, passwords, agent account intents or application permissions. Agents remain separate application identities; lack of a Linux lane account does **not** reduce their application access or create a host-account requirement.

**Still missing for real deployment:** independent issuer and subject verification against a real SSO authority, current complete host-account/UID inventory and race-safe collision enforcement, account/UID and lane-storage lifecycle design, authorization review for human and agent application access, safe provisioning/rollback, and functional backup/restore acceptance. Do not apply the plan on this host. The required two clean full-stack installs remain **0/2**.

## Non-negotiable boundaries

- SSO: distinct Keycloak identities for each human and agent, equal application policy across stack services; one host Linux account per human for their v3 lanes.
- Worklane evolves separately at `github.com/geraldsummers/worklane`; do not alter the active `software_lab` installation or its project data. New v3 lanes replace Herdr with TUIOS. Agents can contact and receive replies from users through Matrix/Element.
- Source-only development here: no installing on the real host until v3-only account, storage and reset boundaries are explicit and independently tested. The real-domain gate is at `datamancy.net` through Cloudflare.
- Backups to `/mnt/media/p0-v3` must be automatically tested by isolated restore, then by real functional tests. Never infer success from an artifact alone.
- Acceptance cases are independently owned under `../acceptance`; implementation unit tests do not assert release readiness.
