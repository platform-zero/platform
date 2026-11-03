# Ownership-bound private generation lifecycle

Ownership validation is now connected to an executable preparation path, not only an offline report:

```text
release generation-prepare-owned INVENTORY_JSON PRIVATE_ASSEMBLY_REQUEST_JSON PRIVATE_OWNERSHIP_JSON PRIVATE_APPROVED_HOSTS_JSON
```

This command prepares **fresh private inputs**, not public routes or a whole release. It requires explicit compiled roles for every process and matching compiled input ownership. All 34 recipe variants now have declarations; native owned execution has additionally covered Forgejo and Planka. Selected capabilities, exact resource contracts and capacity must still pass. Unverified new roles are rejected rather than inferred from image names. The existing `generation-prepare` command remains an explicitly unowned component-preparation path; it is not a full-release bypass or approval.

## Enforced boundary

- Validate the ownership contract, exact compiled specifications, generation identity/candidate/dependencies and resource request **before creating registry directories or invoking credential preparers**.
- Snapshot caller-owned policy collections so later callback mutations cannot change the validated policy.
- Persist `ownership.intent.json` before invoking any member preparation callback.
- Embed the complete binding—assembly summary, contract and hostname allowlist—in `GenerationBundle.ownership`. The bundle digest binds that metadata together with the actual manifest/input hashes.
- Recheck the sealed binding before committing the bundle. Generation live loading requires the original ownership intent with byte-identical contents. A missing or changed intent is not repaired or regenerated.
- Retain failed preparation records and partial inputs. A repeat attempt cannot replace credentials or reuse the consumed namespace.

These are generation-controller checks. They do not convert the legacy per-runtime maintenance primitives into a complete central authorization service, and they do not claim that central networking, shared database schemas, identity provisioning or public ingress is implemented.

## Encrypted recovery and non-inheritance

The binding is inside the source bundle, which is already an authenticated capsule payload. No separate unbound policy sidecar is relied on during recovery. `GenerationRecovery` validates the embedded ownership before importing state; valid capsule authentication alone is insufficient if that ownership is inconsistent.

The foundation restore adapter checks source ownership but **does not inherit its site/route policy as authorization for the new target namespace**. The imported target is private and has `ownership:null`; its `recoverySourceArchiveSha256` binds the original source evidence, including the ownership record retained in `recovered/source/bundle.json`. Credentials and native application data are preserved, but source hostname policy is not silently delegated. This is not a production restore/cutover ownership-rebinding implementation.

## Initial native execution (historical)

Engineering receipt: **`p0v3-owned-preparation-engineering-34968ba9c999`**. Controller and runner hashes remained unchanged through the final native sequence; the controller copies and failure/correction evidence are retained privately.

| Phase | Final receipt | Evidence |
| --- | --- | --- |
| Fresh owned install/workflows/retirement | `p0v3-generation-24e5ebfbf463` | Invalid ownership rejected before inputs; replay rejected; five native workflows/restarts passed; initializer ledgers and container identities unchanged |
| Frozen encrypted capture | `p0v3-capture-c5c4393773c3` | Authenticated bundle/inputs/volumes; wrong-key and tampering refusal; source remained stopped/fenced |
| Fresh native restore/readback/retirement | `p0v3-generation-restore-8f46b3c9b457` | Source ownership preserved in authenticated recovery, no inherited target site authority, historical native data/authentication/restart checks passed |

Final source `q-24e5ebfbf463` has bundle SHA-256 `a7660bf18bc87b6b340ef34b70e84be4d6b9daf1dd7c20ba9ce63ddb3deba04e`.

Capsule `cap-c5c4393773c3` has archive SHA-256 `2d932b386f6f31450a08134e7737e3b9fa5368e95bb5c9260c0a7ec68592980a`.

Final restored target `q-8f46b3c9b457` has bundle SHA-256 `8d55547f14702a3893eeb9301ab5eebca483e003c624abc17c99411d59120486`.

Final retained fences:

- Source foundation: `eaa57595-1369-4749-98d4-f5e4779e1fa0`; source SQL-cache: `a038c35e-ceff-44df-bf7c-3871167866d6`.
- Restore foundation: `d741b8bc-5239-4001-b377-560453321441`; restore SQL-cache: `ba629f4e-96f6-4283-bf0e-83b5de3bf020`.

An earlier passing sequence remains historical: source `q-b1e5f154bbf4`, capsule `cap-6f44190b07e5`, restore `q-bf24b0928774`. All four of its member fences remain retained too. It preceded the early candidate-binding hardening and was not relabelled as testing the final artifact.

## Retained corrections and regression gates

1. An authenticated-invalid-policy unit fixture initially put its key beneath the capsule's directory. The existing custody guard correctly refused it before the intended policy check. The fixture now uses separate custody; the guard was not weakened. Failed XML/log evidence is retained.
2. A further unit test exposed generation-candidate inconsistency reaching a preparation callback before late bundle validation rejected it. The complete generation projection is now checked before registry/credential effects. The failing regression is retained. After repair, the complete native sequence ran again with fresh identities.

Unit results: platform **211 passed / 4 opt-in integration skipped**, **5086/5570 = 91.31%** Kotlin unit lines; acceptance **36 passed / 98.23%**; Keykeeper **26 passed / 93.35%**; Worklane **142 passed / 90.28%** (unit-only, outside a Herdr pane, no remote lab or dist publication). Python **111 passed**; optimized execution is refused before effects.

The protected fleet remains **33 enabled/active deployments / 109 declared running daemons**. All original fence hashes are unchanged; the retained census is now **43**. No boot enrollment, public activation, source restart during recovery or initializer replay occurred.

These are five-service component sequences, not the required complete 39-family release cycles. They also span a code correction. Qualification remains **0/2**. Central provider/identity wiring, full-release transactions, schedules and client journeys remain unfinished.

## Compiled role/input follow-up

The [compiled process ownership increment](compiled-process-ownership.md) now resolves all 144 processes and 253 physical inputs in the existing non-conflicting recipe graph, including explicit responsibility for shared inputs. A fresh seven-product/eight-daemon owned cohort passed native Git/issue and board/card journeys alongside foundation workflows. Fresh five-service encrypted recovery also passed after a retained compiler-reproducibility correction. The current fence census is **59**; the protected 33/109 fleet is unchanged and qualification remains **0/2**. The larger cohort's coordinated recovery is not yet proven.
