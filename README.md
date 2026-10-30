# Platform Zero v3 — platform

New Kotlin/KTS implementation. This repository owns the platform, service inventory, deployment, site model, SSO and lane integration. It does not copy the old P0 generator or its source code.

`src/main/resources/services.json` records exactly the 89 service IDs supplied by the owner: 34 single-service and 55 multi-service entries in 46 *named* modules. A prior report mentioned 57 modules but did not identify 11 of them; do not invent them. **All entries are inventory-only. Nothing is installed or accepted.** Keykeeper and the v3 lane product are additional components, not counted in those 89.

Using Java 21: `./gradlew test`, `./gradlew run --args='catalog validate'`, `./gradlew run --args='catalog list'`. Bulk Gradle cache can be kept under `/mnt/media/p0-v3/cache/gradle-user` with `GRADLE_USER_HOME`.

## Non-negotiable boundaries

- SSO: distinct Keycloak identities for each human and agent, equal application policy across stack services; one host Linux account per human for their v3 lanes.
- Worklane evolves separately at `github.com/geraldsummers/worklane`; do not alter the active `software_lab` installation or its project data. New v3 lanes replace Herdr with TUIOS. Agents can contact and receive replies from users through Matrix/Element.
- Source-only development here: no installing on the real host until v3-only account, storage and reset boundaries are explicit and independently tested. The real-domain gate is at `datamancy.net` through Cloudflare.
- Backups to `/mnt/media/p0-v3` must be automatically tested by isolated restore, then by real functional tests. Never infer success from an artifact alone.
- Acceptance cases are independently owned under `../acceptance`; implementation unit tests do not assert release readiness.
