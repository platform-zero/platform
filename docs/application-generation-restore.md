# Coordinated foundation, Forgejo and Planka recovery

The generation controller now has an explicit **seven-product / eight-daemon** cold restore adapter. This extends the existing five-service recovery path; it is not whole-release completion or a full-stack qualification cycle. The count remains **0/2**.

## Typed controller path

```text
release generation-restore-applications INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CAP FRESH_TARGET_Q
```

Only the exact `foundation`, `sql-cache`, `forgejo`, `planka` cohort is supported by this command. The existing `generation-restore-foundation` command still requires exactly the two foundation/SQL-cache members. Both use the same durable import, admission, authenticated extraction, native volume verification, and failure-isolation machinery.

The adapter:

- Checks archived definitions against the current compiled, digest-pinned recipes, not arbitrary archived commands.
- Requires the exact original input set; extra or missing inputs cannot become restore authority.
- Removes all initializer definitions and dependencies. Forgejo starts existing state with `web`, not migration/admin creation; Planka starts `app.js --prod`, not `db/init.js`.
- Reconnects Planka's daemon dependency directly to its restored PostgreSQL daemon. Removing its migration job must not remove database readiness ordering.
- Preserves the exact authenticated bytes of every input needed by restored daemons. Bootstrap-only `database-init.env` remains in the authenticated recovered source tree, not in the live Planka input directory. PostgreSQL's preserved environment is explicitly retained for its restored daemon.
- Preserves source site ownership as authenticated provenance without delegating source site/route authority to targets.
- Leaves imported targets stopped and fenced until an explicit private verification client starts them. Clean-install staging and import replay remain refused.

All seven volumes use the existing strict archive and native re-export comparison. No link/type/ownership validation was relaxed to support Git or Planka. This still does not claim full ACL/xattr/nanosecond preservation.

## Executed native evidence

Engineering receipt: **`p0v3-app-restore-engineering-b4462e920a48`**.

| Phase | Receipt |
| --- | --- |
| Fresh owned install/workflows/restart/retirement | `p0v3-generation-84b675058a5a` |
| Frozen encrypted capture | `p0v3-capture-9845783719b9` |
| Fresh coordinated import/readback/restart/retirement | `p0v3-generation-restore-dbef39eb9e09` |
| Actual controller kill during partial import | `p0v3-import-interruption-ffb2b7f426ba` |
| Caught authenticated-payload tampering during partial import | `p0v3-import-interruption-b0c7d3d3c0c3` |

The restore client independently reads the original native fixture receipts and retained Git fixture. It verifies historical Git commit identity and exact README bytes through a fresh clone, the original issue/comment through authenticated native APIs, and anonymous private-repository denial. Planka verification uses the original project/board/card/moved-list IDs, native login with preserved credentials, the original comment and anonymous card denial. These checks run again after target restart. No user/repository/project/card initializer or fixture-creation probe is invoked during restore.

PostgreSQL/Valkey/ntfy historical readback, ntfy message ID/time/expiry, MariaDB commit/rollback and authentication, and Memcached's deliberately ephemeral lifecycle remain verified in the same restored cohort. Source deployments are never restarted or unfenced. This does not prove browser journeys, attachment restoration, comprehensive product authorization, post-snapshot exclusion, migration or update/rollback.

The fault client now accepts `--applications`. It pauses only its fresh controller after the first PostgreSQL re-export appears, proves member import incomplete, and waits for observed native children to settle. Kill mode preserves unknown outcomes; tamper mode changes only the fresh target's unconsumed ntfy scratch archive and verifies controller-owned reverse isolation of **all four members**, including unattempted applications. Replay/startup/fence-release denials and linked stop-only reconciliation pass. No target daemon is created in either fault case. This is not host power-loss or general detached-child containment proof.

Every source/target remains stopped/fenced. The protected **33 deployments / 109 daemons** and all prior fence hashes are unchanged; **75 fences** are now retained. No boot enrollment, public activation, RSS publication, old-send replay, or credential regeneration occurred.

## Validation and remaining work

Controller and functional-runner artifact hashes remained unchanged across native execution and an additional complete rebuild. Fault runner hashes are separately retained. Platform: **216 unit tests passed, 4 opt-in integration tests skipped**, **5165/5654 = 91.35%** unit lines. Python: **115 passed**. Acceptance: **36 passed / 98.23%**; Keykeeper: **26 passed / 93.35%**; Worklane: **142 passed / 90.31%**, unit-only outside Herdr, with no remote lab or dist publication. The real acceptance manifest still rejects **62 missing or invalid checks**.

Unit regressions cover exact cohort selection, wrong-cohort refusal before target preparation, altered executable definitions, extra input rejection, bootstrap-input exclusion, dependency rewiring, preserved hashes, no inherited site authority, replay refusal, and failure isolation across attempted/unattempted members. The existing interruption/result-write/reconciliation regressions remain passing.

Canonical shared providers/identity/network/schema contracts, other application recovery adapters, installed backup/restore schedules, live whole-release transactions, remaining browser/Android journeys and the full qualification matrix remain unfinished. Seven-product component restoration does not satisfy either required complete full-stack cycle.
