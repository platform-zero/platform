# Implementation completion source status (historical checkpoints)

> **Superseding authority and current backlog:** [rapid completion](rapid-completion.md).
> Direct implementation and bounded execution through 2/2 are authorized; no subagents or
> coverage quota. The source-only/two-worker restrictions below are historical.

> **Historical authority (superseded):** [two-worker plan](../../.coord/implementation-20261109T071312Z/plan-v2.md)
> and [RUN](../../.coord/implementation-20261109T071312Z/RUN.md). At most two implementation
> workers edit only exact ACTIVE-packet paths; the coordinator reviews, not concurrently
> implements production code. Write source and test source only. **Do not execute** builds,
> compilation, syntax/import/lint/format checks, test discovery/execution/coverage, the
> implementation inventory, or native/runtime/acquisition/deployment effects. Future
> execution needs separate authorization; source review and the checkpoints below are
> not validation of changed source. Qualification remains **0/2**.

The historically accepted completion areas include canonical providers/managed-component
contracts, identity/application/lane lifecycles, whole-release Kopia recovery/scheduling,
owned update/rollback/activation, HTTPS/RSS and genuine acceptance adapters. None of
these areas is complete merely because a source file or historical unit checkpoint exists.
The current 39-product / 57-target / 107-variant scope is unchanged.

## Current read-only inventory

Run `python3 platform/scripts/implementation_inventory.py` from the workspace root.
This authorized diagnostic reads source and metadata without importing or executing
product/runner code. It does not confer execution authority or evaluate qualification.

The diagnostic output is now **schema 2** (not a change to release evidence schemas):

- `variantsWithMissingDeclaredFiles` and `missingDeclaredFileCount` count absent exact
  manifest paths, separately from related implementation elsewhere.
- `variantsWithIncompletePhaseDeclarations` and each case's `phaseDeclarations` describe
  only `implementedPhases` metadata. They replace the ambiguous `missingPhases` terminology;
  they do **not** count unimplemented workflows.
- `relatedSources` hashes explicit `adapterSourceReferences` from
  `release/implementation-scope.json`. These are leads for integration, not verified or
  wired replacements for absent adapters. Missing related files remain visible.
- Domain `declaredStatus` and `reportedBlockers` are identified as manual metadata,
  not independently reconciled findings. `reportedQualification` identifies its policy
  source rather than pretending to have inspected trial evidence.
- Android pin findings concern catalog metadata only; availability, authenticity and
  installed custody are not established by this census.

The refreshed snapshot is
[implementation-inventory-03.json](../../.coord/rapid-completion/implementation-inventory-03.json):
**39 products / 57 targets / 107 variants**, **5 missing declared adapter files**, and
**83 variants with incomplete phase declarations** (79 neither, 4 INSTALL only;
24 declare both). All five missing adapters have explicitly referenced related source.
Donetick and ONLYOFFICE still lack qualifying Android pin metadata in the catalog.

This is not a completion percentage. Existing files and declared phases do not establish
semantic implementation or passing workflows. Actual test checkpoints and the capability
backlog are recorded in [rapid completion](rapid-completion.md). Historical inventory
snapshots and qualification evidence are preserved; no manifest phase was promoted by
this metadata correction.

## Reviewed integrations now connected

- `release generation-canonical-plan` reports the actual partial canonical topology and
  missing capabilities, without credential preparation or runtime effects.
- Typed `release install|update|backup|restore-test|rollback|reconcile|qualify|activate`
  requests are registered and must match the CLI operation before constructing runtime
  controls. **Registration is not full release completion.** In particular native owned
  update import/migration/activation still refuses incomplete authority.
- `runtime ingress-lifecycle` and `runtime private-pki-lifecycle` call the existing typed
  controllers. `prepare-matrix-rtc` and `prepare-erpnext-restore` are registered. MatrixRTC
  also has an exact catalog/process/input ownership entry; it remains a private composite,
  not shared-provider or real-domain qualification.
- Production release Caddy dispatch has no ambient host-loopback fallback. Its
  default-omitted `ReleaseIngress.runtime` binds `manifest:{path,sha256}` and
  `runtimeFingerprint`. The manifest must be the exact named file in the canonical runtime
  registry, explicitly published in CANONICAL_V2, with matching site/approved hosts and
  container-loopback admin. Native requests use the audited namespace transport. Old
  request bytes remain readable, but absence of this binding cannot authorize effects.
- Generation admission uses the serial topological startup envelope without changing
  existing sealed reservation bytes or lowering process limits/headroom. Other active or
  uncertain generations retain conservative reservations, and Kopia worker memory is
  included. Starting an already imported target charges its reservation once, not twice.
  This does not grant source-isolation authority or prove the entire fleet fits this host.

## Controller-owned imported startup

`GenerationRuntime.startRestored(inventory, generation, bundleHash)` is now used by
staged and qualified functional restores, explicit restore-test dispatch and the weekly
backend. It is separate from clean-install staging and grants no site/public authority.

Admission verifies original Kopia lineage, successful generation/member import records,
authenticated native import markers, exact compiled daemon-only projections, immutable
inputs, no public publication, retained import fences, absent target containers and
capacity. Every member is audited before the first startup effect. Exclusive generation
and per-member startup intents prevent retries, including after a lost acknowledgement.

`PrivateDeployment.startImported` holds the runtime lock across its final import/resource
check, fence release, allocation of daemon containers and readiness. It cannot recreate
missing imported volumes/networks/secrets, run initializers or adopt a partially started
target. Failure re-establishes a fence before attempting stop. Generation-level failure
also attempts independent cohort isolation even if saving the failure result fails;
interrupt status and all prior evidence are retained. No source resume is performed by
this operation. The existing held-source controller still requires verified target
isolation before source resume.

This closes the earlier path that called a RESTORE runner against stopped imports and
the weekly path that separately released fences and applied manifests. It does **not**
complete missing canonical recipes, managed-component startup, restored HTTPS/client
access, RSS exclusion, native update migration, or functional adapters.

## Further completion work: qualification, RSS maintenance and Home Assistant

### Late-bound qualification dispatch

`release qualify <private-request.json>` now accepts the `qualify-bound` discriminator
with `finish: ReleaseAcceptanceInvocation` and `candidate: ActivationInput`. `finish`
references the current BEGIN head and completion evidence; `candidate` references the
exact pending candidate identity. Neither includes a guessed future assessment head.

The controller preflights both inputs and the pinned Acceptance distribution, validates
the journal hash chain, and creates an exclusive attempt claim identified by canonical
journal path plus BEGIN head. It invokes FINISH once, requires exactly one FINISH appended
to the unchanged prefix with the same trial identity, persists the actual assessment
binding, then invokes ASSESS with that head. Stdout is not head authority. Changed requests
or paths to equivalent candidate/evidence files cannot evade a retained uncertain attempt.
ASSESS still independently verifies semantic evidence; nonzero status is never promoted
to success. A later journal change prevents a successful transport receipt.

Legacy `qualify` requests remain readable and retain their explicit expected-head check,
but use the same once-only path. Candidate/journal parser diagnostics are private. This
is transport/orchestration completion, not new qualification evidence or completion of
the two-cycle whole-release execution controller.

### Durable RSS maintenance primitive

`RssSchedule.quiesce(root, bindingHash, operationId) { ... }` now writes an exclusive,
binding-specific intent while holding the schedule lock. The controller body must perform
the complete operation and throw unless durable results, target isolation and source
resume checks succeed. Previously enabled schedules additionally require live committed
source authorization before an immutable completion record is written.

Exceptions, interruption and lost acknowledgements leave the intent intact. Enabled
ticks, activation release and new maintenance IDs reject incomplete, orphaned, foreign or
linked records. Completed operation IDs cannot replay. Permanent suspension remains
separate and is not undone. There is no timeout cleanup or public unpause endpoint.

**Integration remains unfinished:** this primitive is not yet connected to every
backup/restore/weekly path through a sealed per-generation enrollment association. Do not
claim global RSS exclusion or integrate controller payload capture ahead of that association
and writer exclusion. The generic controller callback is not a substitute for native
completion/isolation proof.

### Reviewed Home Assistant cold start

WHOLE_RELEASE now includes Home Assistant for the existing pinned **2026.10.4** image.
The projection preserves the original config volume and image, retires `config-init`,
and removes the original fixture-password environment file from the restored daemon.
A controller-pinned Python guard checks owned nonsymlink files, private authentication
storage, existing active-owner/provider association, completed onboarding and recorder
integrity/table presence at schema **53**, before executing the daemon. Missing state,
unreviewed images/schema, links, unsafe permissions and optimized Python refuse startup.
No replacement configuration, owner, password or database is created.

The guard follows the pinned upstream [auth store](https://github.com/home-assistant/core/blob/2026.10.4/homeassistant/auth/auth_store.py),
[local provider](https://github.com/home-assistant/core/blob/2026.10.4/homeassistant/auth/providers/homeassistant.py),
[onboarding storage](https://github.com/home-assistant/core/blob/2026.10.4/homeassistant/components/onboarding/__init__.py)
and [recorder schema](https://github.com/home-assistant/core/blob/2026.10.4/homeassistant/components/recorder/db_schema.py).
Only source was researched. Units use disposable SQLite/JSON files and mock the final
exec; no Home Assistant service was launched. This is not a semantic RESTORE adapter,
proof of original automation/history readback, or browser/Android qualification. Other
missing cold projections and metadata fidelity remain work.

## Verification and remaining authority

Historical focused units covered CLI pre-effect rejection, typed operation mismatch,
serialization, Caddy endpoint binding, MatrixRTC roles, startup non-replay,
partial/interrupted startup, isolation and capacity boundaries. They used mocked native
transports and services; they do not validate subsequent source changes.

Historical frozen checkpoint evidence is retained under
`.coord/delegation-20261103T001112Z/tests/` in the workspace. The former source-only ban
and 90% coverage quota are superseded. Current builds/tests/acquisition and bounded runtime
integration through qualification are authorized without subagents. The latest full units
passed **726 Platform** and **97 Acceptance** tests; native adapter/projection and spool
Python subsets passed **24** and **4** tests. See [rapid completion](rapid-completion.md)
for exact logs, current capability backlog and missing authentic signed-input/trust custody.
Keep source presence, artifact production, executed units and real workflow verification
separate. Full-stack qualification remains **0/2**.
