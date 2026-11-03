# Typed private-generation assembly

The controller now resolves **35 private recipe variants** through `GenerationAssembly.kt`. This replaces hand-authored runtime manifests for this path; it is not the complete canonical release assembly or a declaration that 35 integrated products are qualified. The added [`canonical-core`](canonical-provider-core.md) alternative shares PostgreSQL with Planka; it conflicts with separate `foundation` or `planka` selections.

## Commands

```text
platform release generation-assembly-plan INVENTORY_JSON PRIVATE_ASSEMBLY_REQUEST_JSON
platform release generation-prepare INVENTORY_JSON PRIVATE_ASSEMBLY_REQUEST_JSON
```

Planning reads exact inventory bytes and validates their requested SHA-256. It does not generate credentials, invoke Podman, create controller directories or initialize applications. Preparation generates fresh protected synthetic inputs through the registered Kotlin factories, seals the resulting generation, and returns its ID and bundle digest. Existing generation stage/audit/isolation commands then consume that digest.

A request has `schemaVersion:1`, a fresh `q-<12 hex>` ID, candidate-descriptor and inventory SHA-256 values, typed `selections` (`recipe`, optional recipe-name `dependencies`), and capacity policy. It uses the existing private-only purpose and memory/disk floors. The engineering harness automatically creates these inputs; no operator-authored credentials or human approval gate is added.

## What is enforced

- Only compiled, registered recipe functions can construct configurations. Requests cannot provide commands, host mounts or arbitrary deployment names.
- Every selected recipe and its process/image declaration is resolved before **any** credential generation. Unknown recipes, duplicate recipe names, missing/cyclic dependencies, foreign namespaces, weak capacity policies and insufficient disk declarations are rejected.
- Each recipe declares its primary capabilities. Competing alternatives are rejected: for example `seafile` plus `office`, `mail` plus `sogo-mail`, `matrix` plus `matrix-identity`, or `openbao` plus the Keykeeper composite. Supporting service copies are explicitly not central production ownership.
- Plans report exact process-definition hashes, image references/content IDs, daemon/initializer roles, each volume's UID and potential writers, and each input filename's consumers. No generated credential values appear in the plan.
- All destination input directories/manifests must be fresh before preparation. A fsynced group intent precedes preparation, and a member intent precedes each factory invocation. Exact returned definitions and paths are checked before sealing.
- Partial preparation is retained, not regenerated or silently adopted. Failures/interruption retain outcomes when persistence succeeds; fatal/persistence failures leave unresolved intents. Reusing the generation is forbidden.
- The sealed bundle binds the assembly-intent digest. Stage/audit reject missing or unsuccessful assembly completion; deleting the intent cannot downgrade an assembled generation to the legacy path. Isolation still uses sealed definitions so damage to preparation-completion metadata does not authorize startup or prevent ownership-checked stopping of other members.

Preparation does **not** initialize/unseal Bao, renew tokens, start applications, enroll boot units, execute migrations, publish routes or send RSS posts.

## Scope still missing

`missingCapabilities`, `globalIntegrationValidated:false`, `fullStackQualification:false` and `publicActivation:false` are explicit outputs. Embedded Caddy processes are not a qualified public ingress capability. Private identity/database copies inside existing composites are not shared central identity/data wiring. Worklane/TUIOS/Pi and the RSS publisher are not fabricated recipe entries.

This registry is an intermediate implementation toward the full release: exact production site/credential/route ownership, central integration, application lifecycle adapters, coordinated recovery, schedules, public HTTPS and the real acceptance matrix remain unfinished. Full-stack qualification remains **0/2**.

## Executed checks

- Unit tests resolve all 35 recipe variants against repository artifact metadata **without executing those services**.
- Unit tests cover primary-ownership conflicts, dependency/policy/inventory failures, input/state ownership reports, fresh actual foundation/SQL configuration generation, partial failures, interrupted preparation, retained secrets and private-file guards. Their runtime backend throws if preparation tries to invoke it.
- Native receipt **`p0v3-generation-f4dc52665920`**, bundle **`68b9cb96cd956e455099fa4692e576c58ac58d48cedb1ce463099b2366286d6e`**, exercised typed plan/preparation, pristine audit, staging, PostgreSQL/Valkey/ntfy/MariaDB/Memcached workflows, restart persistence and linked isolation reconciliation. The simulated pending-isolation boundary did not kill a process or simulate power loss.
- The new foundation and SQL/cache deployments remain stopped/fenced. Across the four generation engineering runs there are now eight stopped member deployments and eight added fences; the original seven fences remain unchanged. The protected fleet remains **33 enabled/active deployments / 109 declared running daemons**.

This is one further five-service engineering run, not an encrypted restore or either complete install/restore qualification cycle.
