# Implementation scope and historical checkpoints

> **Superseding authority:** [rapid completion](rapid-completion.md). Direct implementation,
> builds/tests/acquisition and bounded execution through 2/2 are now authorized, without
> subagents or coverage quotas. Everything below describes earlier checkpoints and limits,
> not current execution authority.

## Archived source-only policy (superseded; do not apply)

> **Historical authority:** [approved two-worker replan](../../.coord/implementation-20261109T071312Z/plan-v2.md), [RUN](../../.coord/implementation-20261109T071312Z/RUN.md). At most two implementation workers. Write production code and tests; execute **no** compilation, builds, syntax/import/lint/format checks, tests/discovery/coverage, inventory scripts or native operations. Earlier sole-operator, twelve-worker and unit-execution permissions below are superseded. Preserve their historical evidence; do not treat it as validation of changed source. Qualification **0/2**.

That earlier approval limited implementation to **at most two implementation workers**, with a reviewing coordinator and ACTIVE-packet source/test edits only. It prohibited execution at that checkpoint. Rapid completion supersedes those restrictions: direct implementation and bounded execution through 2/2 are now authorized. The full 39-product / 57-target / 107-variant scope remains.

## Delegated implementation checkpoint (2026-11-03)

Historically, the user authorized twelve shared-checkout OpenAI `gpt-6-astra` delegates, then directed their cleanup and **sole-operator continuation**. All twelve delegate panes and their dedicated workspace were closed on 2026-11-03; handoffs, terminal snapshots and test evidence were retained, and source ownership was transferred to COORD at that checkpoint. This paragraph records the earlier arrangement, not current staffing, write authority or permission to run offline checks.

The completed unit checkpoints at that historical stage were:

- Keykeeper: **29 tests passed; 607/652 unit lines (93.10%)**.
- Worklane: after the formatting fix, **146 Rust tests plus four embedded-Python units passed; 12,214/13,537 unit lines (90.23%)**. The frozen recheck also passed `cargo fmt --check`.
- Acceptance: **58 Kotlin tests passed; 1,187/1,237 unit lines (95.96%)**; a further **116 mocked Python tests passed**. The changed Matrix browser driver compiled against cached dependencies but was **not launched**.
- Platform: the sole-operator recheck passed **422 Kotlin tests and 181 mocked Python tests; 9,277/10,196 unit lines (90.99%)**. The five initial delegated-checkpoint failures are resolved. Owned-update ownership now requires retained original metadata authenticated by the snapshot's source-bundle digest, retires only original initializer roles, preserves every daemon and original site/state/input authority, and retains explicit provider ownership of shared trust inputs. Fresh-install validation stays strict. Native owned-update import/start/activation remains incomplete and refused.

Every reported historical checkpoint retained identical before/after source fingerprints. Evidence is under `.coord/delegation-20261103T001112Z/tests/` in the workspace. Those results do not validate subsequent source edits. Later executed checks and their exact scope are recorded in [rapid completion](rapid-completion.md).

The historical sole-operator continuation connected the reviewed CLI/MatrixRTC registrations, pinned namespace-aware release ingress, and once-only imported startup. See [implementation completion progress and interfaces](implementation-completion.md) and the read-only `scripts/implementation_inventory.py` census. The `completion-02-restored-start` checkpoint passed **427 Kotlin + 185 Python tests**, **9,391/10,324 Kotlin unit lines (90.96%)**, with unchanged fingerprints. The capacity/census changes subsequently passed `completion-03-capacity-inventory`. Follow-up late-bound qualification, durable RSS maintenance and guarded Home Assistant recovery are documented in [implementation completion progress](implementation-completion.md); their exact frozen verification records are retained separately. These do not close the full implementation scope.

These are partial implementation handoffs, not completion. Acceptance declared **57 targets / 107 variants**; D12's historical report listed **75 variants without adapter files**, plus phase/artifact gaps. That is not the current census: the latest diagnostic distinguishes **5 missing exact adapter paths** from **83 incomplete phase declarations**, without inferring a completion percentage. Canonical closure, owned-update native import/activation, RSS-wide backup quiescence/state custody, managed-lane integration and genuine missing client adapters remain implementation work. No native/runtime/qualification operation occurred; **qualification remains 0/2**. Older per-increment evidence below is historical, not validation of the changed tree.

## Historical boundaries (superseded, retained for context)

- Write only source, test source and documentation paths granted by an ACTIVE packet. Do not compile, package, format, lint, run unit tests, inventory scripts, coverage, syntax/import checks or project checks. Source read/search/diff is permitted; source review is not validation.
- Do not deploy, pull/build images, operate Podman/systemd, start/restart applications, run native fault probes, browser/Android journeys, model-provider requests, ACME/RSS/mail operations, or qualification cycles.
- Do not clean up or reconcile existing live/test resources during this phase. The interrupted tamper scope `q-02d58ff35358` remains unresolved; it has not been replayed by this implementation increment.
- Earlier project-created test deployments are **not inherently protected assets**. The earlier blanket preservation policy was incorrect. They remain unchanged now because runtime operations are outside this phase, not because every old fixture must exist indefinitely. Unrelated services, media, accounts and workspaces remain outside project ownership.
- Preserve dirty/untracked source work. Use at most two implementation workers, one ACTIVE packet each; no nested agents or unassigned edits. The coordinator reviews and decides, not a concurrent third production worker. No remote Worklane release gate, `dist/` publication, toolchain installation or commits.
- Write focused source tests for requirements, defects and safety boundaries without executing or discovering them. Historical checks cannot validate changed source. Coverage gates await separate authorization.
- The superseded policy required 90% unit-only line coverage in each of four repositories. That quota is no longer a release gate; historical coverage cannot validate changed source or serve as native evidence.

## Implementation recorded at that source checkpoint

### Unit task separation

Platform's default `test` excludes `*RealIntegrationTest*` and native/integration/browser tags regardless of ambient opt-in variables. The real Quadlet-generator diagnostic has moved to the separately gated `nativeIntegrationTest` task. Unit tests inject command results and inspect temporary generated files; they no longer invoke the installed generator. The separate task is **not authorized to run during this phase**.

### Fresh store-bound owned preparation

`AssemblyRequest.store` binds the selected store through planning, ownership projection, all 35 existing preparation callbacks and sealed runtime manifests. Default LEGACY fields remain omitted for old record compatibility. Explicit `CANONICAL_V2` fresh preparation requires ownership; direct/unowned sealing cannot silently migrate into that store. Inputs are generated once for the correct definition, not generated under a legacy manifest and rewritten afterwards.

This implements fresh preparation, not a successful live installation or completion of central provider wiring. Existing runtime operations remain responsible for actual store/image/capacity admission.

Restored `GenerationRequest.releaseCandidateSha256` retains the original candidate identity separately from the restore-specific derived candidate digest. Continued restore lineage preserves this field. Old records omit the default/null field.

### Restricted transaction versus activation

`ReleaseTransaction.execute` now stops at restricted `ACCEPTED`, including successful clean installs and updates. It never opens public writes/outbound merely because staged and real-domain checks passed.

A separate `activate` requires a sealed deployment binding, an exact accepted journal head, explicit authorization verification and single-use consumption. Original install bindings are sealed at PREPARED. The delegated typed update journal adds once-only post-snapshot binding at STAGED, but its native owned-update import/start/activation path is still incomplete and remains refused. `ACTIVATION_STARTED` is durably compare-and-appended before consumption/effects; the permit digest is carried through the journal. Failures retain uncertainty and close writes/outbound without stale rollback. Legacy unbound transactions are readable but cannot use this activation method.

The production authorization provider is now implemented: see [activation/Caddy/RSS source details](activation-caddy-rss.md). It revalidates Acceptance evidence, pins both controllers to the candidate artifact closure, reobserves the live source/restricted routes and consumes authority in a fixed namespace. The typed production dispatcher is now registered, including namespace-aware ingress selection and controlled restored startup. The complete canonical cohort, native owned-update lifecycle and restored client ingress remain unfinished; command registration alone cannot pass those gates. Unit authorization doubles are not production permits.

### Whole-trial evidence evaluator

Acceptance implements `WholeTrialEvaluator`, with `finish-qualified` and `assess-qualified` CLI boundaries. It validates exact phase case/assertion sets and retained native artifacts, controller install/import/isolation outcomes, source snapshot/restore lineage, full capability declarations, and pinned candidate-bound unit coverage reports. Counts are parsed from JaCoCo XML or LLVM coverage JSON, not accepted from caller-supplied percentages. XML external resolution is disabled.

FINISH binds an immutable evaluation record. A lost FINISH acknowledgement can reconcile that exact record; changed evaluations cannot overwrite it. Assessment re-verifies the current passing streak and identifies the **second** installation, not an unnecessary third. Callers must anchor returned journal heads outside the journal. Build provenance and controller records remain trusted inputs; this is not independent execution attestation.

Production evaluation refuses incomplete official-client classification or executable coverage. The case manifest now declares 57 targets / 107 variants, but most real adapter implementations and several phase/artifact bindings remain missing. Positive evaluator tests use explicitly synthetic private unit fixtures and a simulated completed policy; they are not service evidence.

### Concrete Caddy and RSS adapters

`TransactionalCaddy` implements owned-slot ETag-guarded cutover, readback, scoped rollback and explicit observation-only reconciliation of lost acknowledgements. Restricted revisions preserve application cookies while removing the control credential before proxying. It does not implement listener/ACME provisioning or grant activation authority.

RSS now implements read-only reconciliation against the token's bot identity and exact author-owned remote status source, with durable checkpoint/evidence updates only for a matching attempted send. Absence never authorizes resend; unclaimed acknowledgements are refused. See [the exact contracts and remaining integration boundaries](activation-caddy-rss.md).

### Native Kopia retention actuator

`KopiaGenerationStore` now serializes snapshot/restore/retention through a repository control lock. Its retention actuator uses Kopia's native daily/weekly selection plus mandatory reference and functional-restore protection, exact-ID deletion, durable intent/readback and observation-only reconciliation. It preserves original pins and manifest IDs; Kopia pin updates would invalidate immutable recovery receipts. Worker interruption is preserved.

Delegated source now adds the production reference ledger, weekly restore controller/CLI and native retention registration. Capture, held-source and import reference hooks are integrated, but full RSS job exclusion and reference-writer integration review remain outstanding; this is not a completed scheduled-recovery system. There is no permissive default authority. See [Kopia retention contracts](kopia-retention.md) for the earlier actuator baseline. Its historical pre-delegation checkpoint was **287 passed, 6,523/7,182 lines (90.82%)**; the newer passing sole-operator checkpoints above supersede that historical validation status. No native operation occurred.

## Historical remaining-work list — not the current backlog

The whole plan is **not yet implemented**. Continue source work on:

1. Complete canonical provider/process/state/credential/network/site contracts and capacity-aware whole-release assembly, including Caddy, RSS and Worklane/TUIOS/Pi capabilities.
2. Completion of the registered production `ReleaseEffects` and typed dispatcher: owned update/migration/rollback, active-site publication authority, restricted restore ingress and whole-release reconciliation.
3. Central identity/credential lifecycle, scoped Bao recovery, managed lanes/model/session recovery, Matrix RTC/E2EE, files/office, business, mail and remaining application integrations.
4. Whole-release metadata-aware Kopia recovery, controller/custody bootstrap, installed weekly functional restore, maintenance coordination and reference-safe retention.
5. HTTPS/listener/renewal provisioning and integration of the implemented transactional cutover; installed RSS scheduling and integration of explicit uncertain-send reconciliation.
6. Real invocation-bound native/browser/Android runner implementations and complete official-client classification/manifest coverage.

The historical instruction deferred runtime execution. The current [rapid-completion authority](rapid-completion.md) permits bounded integration through qualification. Missing implementations still cannot be replaced with green fixture results or relabelled as operator prerequisites.

## Earlier unit checkpoint

The table below records the preceding increment. The newer activation/Caddy/RSS increment is recorded separately in its source-status document; do not transfer earlier counts to changed code.

| Repository/suite | Tests | Unit line coverage |
| --- | ---: | ---: |
| Platform | 260 passed, no skips | 5,997 / 6,594 = 90.95% |
| Acceptance | 50 passed, no skips | 1,013 / 1,034 = 97.97% |
| Keykeeper | 26 passing cached results; unchanged sources | 576 / 617 = 93.35% |
| Worklane, `--workspace --lib --bins --offline` | 142 passed | 11,842 / 13,112 = 90.31% |
| Platform Python unit discovery, `test_*.py` | 137 passed | Separate behavioral unit suite |

Gradle checks used Java 21, existing caches and `--offline`. Platform native tests were excluded, not opt-in skips. Worklane integration targets were excluded. No native task, deployment, browser/Android journey, model call or qualification cycle was run. The Python negative acquisition test prints an expected failure message from mocked acquisition; it is not an image acquisition in this phase.

Local unit logs: `/tmp/p0v3-implementation-{platform,acceptance}-final.log`, `/tmp/p0v3-implementation-{keykeeper,worklane,python}-units.log`. These are unit diagnostics, not native acceptance evidence.

## Current reporting reference

Report source implementation and actual unit results separately from artifact production and runtime validation. Use [rapid completion](rapid-completion.md) for current checks, admission gaps and remaining capabilities. **Full-stack qualification remains 0/2**. Public production cutover and historical RSS publication are not authorized.
