# First canonical shared-provider cohort

**Later recovery integration:** the [native Kopia generation path](kopia-generation-recovery.md) now snapshots and restores this cohort in fresh scopes. The v1 capsule evidence below remains retained and unchanged.

This is integrated component engineering, **not completion of the canonical release or qualification**. The count remains **0/2**. `canonical-core` is an alternative compiled recipe; historical `foundation` and `planka` recipes and their fences remain intact.

## Implemented boundary

`CanonicalCoreRuntime.kt` combines PostgreSQL, Valkey, ntfy and Planka. With SQL/cache and Forgejo it supplies **seven logical products, seven daemons, three member deployments** instead of the earlier four-member/eight-daemon application cohort. It uses exactly one PostgreSQL daemon. Canonical Keycloak, MAS, Synapse, Firefly, Mastodon, SOGo and the remaining providers are not wired by this increment.

- `PrivateDeployment` supports explicitly declared, owned internal networks and exact per-process attachment checks. Default fields are omitted even with `encodeDefaults=true`, preserving legacy recipe/fingerprint representation.
- PostgreSQL joins the private foundation, administration and Planka-data networks. Planka joins only its data and frontend networks; unrelated ntfy traffic is denied. There are no public ports/routes.
- PostgreSQL rejects plaintext TCP. Bootstrap uses libpq `verify-full`; Planka migrations use verified TLS. The production Sails adapter also needs explicit `datastores.default.ssl` configuration: URL `sslmode` alone was insufficient. The sealed `planka-database.js` supplies the local CA and `rejectUnauthorized=true` without changing the image or global trust.
- Planka uses a distinct non-superuser runtime role with database CONNECT, schema USAGE, table DML and sequence USAGE/SELECT privileges. The schema-owning migration role becomes NOLOGIN before the daemon starts. Runtime inputs omit administrator/bootstrap/migration credentials. This is clean-install privilege separation, **not an implemented update/rotation protocol**.
- `RuntimeDatabaseAccess` records consumer/provider/physical volume/database/principal/credential-input/network relationships. Structural validation does not itself grant SQL privileges. The compiled bootstrap SQL and native denial checks enforce this cohort's actual privileges.
- Ownership inventory keeps mount writers separate from network writers. A database consumer's logical state and mounted state must share a recovery group. Existing ownership reports still say `centralWiringVerified=false`: a valid declaration is not whole-release connectivity evidence.

The admitted install reservation was **7,808 MiB**, retaining **16,384 MiB memory and 10,240 MiB disk headroom floors**. This removes one duplicate database without reducing any process limit. It is not a measured full-release migration/client/restore peak or proof that all 39 families fit.

## Recovery

The new exact `CANONICAL_CORE` restore cohort is `canonical-core`, `sql-cache`, `forgejo`. Its CLI is:

```text
release generation-restore-canonical-core INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CAP FRESH_TARGET_Q
```

Source specifications and input sets must equal the compiled recipe. Restores remove initializers, administrator/migration/bootstrap-only inputs and retired database-consumer declarations. Planka starts with `app.js --prod`, directly depends on restored PostgreSQL and keeps the authenticated TLS/runtime configuration. Source ownership remains authenticated provenance, not site authority for the target. All targets initially remain stopped/fenced.

Native readback checks historical database/cache/notification state, exact Git commit/README/issues/comments and board/card/list/comments, anonymous denials and restart. The Planka login oracle reads the original source's protected bootstrap fixture credentials; those credentials are not mounted into target daemons. Both source and restored target passed live application-session TLS checks, nonprivileged-role checks, foreign-database/DDL/role-creation/plaintext denials and unrelated-network rejection. No fixtures were recreated on restore.

This still uses the bounded v1 cold-capsule format. Routine freeze/capture/resume, backup after restored-generation promotion, Kopia schedules, full metadata, attachments, post-snapshot exclusion, cross-application identity and update/rollback are not established here.

## Evidence and retained correction

Engineering package: **`p0v3-canonical-core-engineering-026be5a8f0cb`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

| Operation | Receipt |
|---|---|
| Failed initial TLS wiring; linked stop-only reconciliation | `p0v3-generation-dc7a17563f2d` |
| Fresh corrected install, workflows, restart and retirement | `p0v3-generation-4e6105b5d068` |
| Authenticated capture, wrong-key/tamper refusal | `p0v3-capture-fb56f9f2031b` |
| Fresh native historical restore/restart | `p0v3-generation-restore-a908aa6d6a25` |
| Actual partial-import controller SIGKILL | `p0v3-import-interruption-adfc378bb7f3` |
| Caught fresh-target scratch-tar tampering | `p0v3-import-interruption-dacfd6d26399` |

The first Sails daemon attempted plaintext and was correctly rejected. Its failed stop also exposed an isolation defect: an unclean exit aborted remaining per-member stop attempts. Shutdown now attempts the remaining daemons in reverse order, retaining failure/suppressed errors and fences; interruption is handled separately. A regression proves later stop attempts occur after an unclean exit. The failed generation was reconciled, never replayed or relabelled as passed. The previous proof-graph unit test was also corrected to exclude the new conflicting alternative recipe, preserving its historical 27-recipe counts.

The final complete rebuild matched **all seven distribution files** used for corrected native execution. Final unit gates:

| Repository | Passed unit tests | Unit lines |
|---|---:|---:|
| Platform | 222 (4 opt-in integrations skipped) | 5,258/5,757 = 91.33% |
| Acceptance | 46 | 807/820 = 98.41% |
| Keykeeper | 26 | 576/617 = 93.35% |
| Worklane | 142 | 11,842/13,112 = 90.31% |

Python helper suite: **120 passed**. Worklane used the dedicated local unit toolchain; no remote lab checks or `dist/` publication. Browser/Android/helper/native evidence is not included in unit coverage. No acceptance cases were populated.

The protected **33 deployments / 109 declared daemons** and all original **75 fence hashes** are unchanged. **90 fences** are now retained, including all failed/source/restore/fault scopes. No protected deployment was restarted, no source was started/unfenced during recovery, and no public activation, RSS publication, Bao recovery or boot enrollment occurred.
