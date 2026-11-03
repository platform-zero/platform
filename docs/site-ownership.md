# Compiled site/resource ownership contracts

`SiteOwnership.kt` adds an offline ownership boundary over the existing typed assembly. It does **not** implement central networking, shared database schemas, OIDC client provisioning, credential custody, Caddy loading or a live whole-release backend.

## Commands

```text
release site-ownership-inventory INVENTORY_JSON PRIVATE_ASSEMBLY_REQUEST_JSON
release site-ownership-check INVENTORY_JSON PRIVATE_ASSEMBLY_REQUEST_JSON PRIVATE_OWNERSHIP_JSON PRIVATE_APPROVED_HOSTS_JSON
```

Both compile existing recipes without invoking their preparation callbacks. They generate no credentials or runtime namespaces and do not contact Podman, DNS or applications. The host list is an explicit policy input, not proof of DNS, listener ownership or authorization to activate routes.

The inventory includes qualified `member/process`, `member/volume` and `member/input` references, exact immutable artifact identities, local dependencies, potential state writers and actual input consumers. It also reports missing capabilities, repeated artifact use and unclassified derived artifacts. It is **not** a guessed ownership assignment: unknown compiled logical roles remain `compiledProduct:null`.

A contract declares:

- Schema version, site identity and the published `assemblySha256`.
- Exactly one product owner for each compiled process and volume.
- Exactly one responsible product for each input file, its supplied credential classification and exact consumer set.
- A recovery group for each volume; a writer cannot straddle independent recovery groups.
- Exact hostname/product/process/port route ownership within the separate allowlist.

References must match the compiled resources exactly. Missing, duplicate and invented entries are refused. Every selected capability needs an explicit process owner. State owners must agree with their writers; input owners must be represented among their actual consumers. Routes cannot target initializers, foreign processes, another product's process or unapproved hosts.

The assembly digest uses the same serialization, **including defaults**, as `GenerationRuntime`'s durable `assembly.intent.json`. A regression compares the digest against a real unit-only preparation intent. Contract validation also checks that compiled specification hashes still match the assembly summary.

[Explicit compiled declarations](compiled-process-ownership.md) now cover all 34 recipe variants, including shared physical-input responsibility. Unknown new roles still remain unverified rather than being guessed from artifacts: an image's inventory provenance is not necessarily its logical service role. Generic images and multi-process applications can legitimately reuse artifacts. **Repeated images are not automatically duplicate services**, and they never authorize merging databases, sharing credentials or changing network boundaries.

`site-ownership-check` exit 0 means structural validation only. Its report always retains `executable:false`, `centralWiringVerified:false` and `publicActivation:false`. It is not public deployment approval. The separate [ownership-bound generation path](owned-generation-preparation.md) now enforces the validated binding before credential preparation and during generation loading, while remaining private and limited to explicitly compiled roles. Central release authorization remains unfinished.

## Initial offline inventory and checks (historical)

Receipt: **`p0v3-site-ownership-145e3aba6821`**.

All **27 non-conflicting compiled recipe choices** resolved against the repository's actual artifact metadata:

- **144 processes** (including declared one-shot initializers).
- **72 state volumes** with potential writers.
- **253 input files** with exact consumer references.
- **24 daemon artifacts** not uniquely classified through the main acquired-image inventory.
- **137 process roles** without an explicit compiled ownership declaration in this new model.
- Missing canonical capabilities: **Caddy, mastodon-rss-publisher, Worklane, TUIOS and Pi**. This does not mean every corresponding component binary is absent; notably, private proof composites already embed Caddy.

Artifact-use counts include eight PostgreSQL processes, four MariaDB processes and five Valkey processes, alongside legitimate multi-process application/image reuse. The full per-process graph is retained in the private receipt; these counts are not proof that central wiring exists.

A separate synthetic five-service contract passed exact structural validation. Removing a process owner was rejected with exit 1. No generation/runtime namespace was created, and no live credentials were generated. The synthetic `ntfy.v3.example.org` allowlist is **not** a production route policy or activation request.

Earlier receipt `p0v3-site-ownership-948fc74d56c9` remains historical. Corrections retain an initial test compile failure (wrong CLI helper name), align assembly digest serialization with durable preparation, and distinguish artifact reuse from logical service roles. Its records were not rewritten as evidence for the corrected implementation.

Validation: platform **204 passed, 4 opt-in integration tests skipped**, **5045/5529 = 91.25%** Kotlin unit lines; acceptance **36 passed / 98.23%**; Python **111 passed**. These are separate from native application/recovery evidence. Previously pinned operational controllers were not repinned, and prior native receipts remain tied to their original artifacts.

## Executable lifecycle follow-up

[`generation-prepare-owned`](owned-generation-preparation.md) now persists ownership before fresh credentials, seals it into the generation bundle, and preserves it through authenticated recovery without inheriting source site/route policy into restored targets. A fresh five-service install/capture/restore sequence passed after retained unit corrections. That checkpoint did not finish the full-release role graph or central wiring; its retained fence census was 43 and qualification remained 0/2. The subsequent [compiled role/input increment](compiled-process-ownership.md) resolves all 144 processes and 253 inputs in the existing 27-recipe graph, passes native owned preparation with Forgejo/Planka, and repeats fresh five-service recovery on reproducibly compiled controller bytes. The current fence census is 59; qualification is still 0/2.

## Still required

Resolve the missing canonical capabilities, canonical providers and application database/schema ownership; implement explicit credential issuance/rotation/custody; wire central networks and identity through typed adapters; connect validated contracts to live `ReleaseEffects`; then run all product/client/recovery cases. No complete ownership contract for the full release has passed. Full-stack qualification remains **0/2**.
