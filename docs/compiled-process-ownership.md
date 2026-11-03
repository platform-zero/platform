# Compiled process and shared-input ownership

This increment extends the private ownership boundary beyond foundation/SQL-cache. It is **not central wiring or full-release completion**. Qualification remains **0/2**.

## Implemented boundary

`CompiledProcessOwners.kt` explicitly assigns logical responsibility to every process in all **35 compiled recipe variants**, including alternative composites. The later [canonical provider core](canonical-provider-core.md) adds explicit network-mediated writers separately from physical mount writers; the historical graph counts below exclude that conflicting alternative. Tests require an exact match between each recipe's actual process IDs and its declarations; unknown processes are never classified by their image.

Examples: the LiveKit web helper belongs to LiveKit, Hub-managed notebook processes belong to JupyterHub, the Matrix identity proxy belongs to Keycloak, and the knowledge frontend belongs to BookStack. Database initialization belongs to the database product; application migrations retain application responsibility. Private application proxies do not constitute canonical public Caddy ingress.

The inventory now reports the compiled owner of each physical input. Single-product consumers determine an unambiguous owner. Shared inputs require explicit declarations, checked against their actual consumers:

- Keykeeper's Bao trust material: OpenBao.
- Node-metrics shared mTLS trust material: node-exporter.
- Office's inherited Seafile trust material and process supervisor: Seafile.
- SOGo and SOGo/mail database trust material: PostgreSQL.
- SOGo/mail mail trust material: mailserver.

A different consumer cannot simply claim responsibility for those shared files. Unknown or stale shared-input policy fails closed during owned preparation. These declarations do **not** establish a central certificate/secret issuer, rotation policy, database/schema grants or new file access. Existing exact consumer lists still determine the compiled mounts.

All 27 non-conflicting recipes resolve to **144 processes, 72 volumes and 253 inputs**, with no unresolved compiled process/input owners. All 72 volumes' declared mount writers agree on their product owner. This is not a claim that network-mediated database writes have been modeled as mount writers. Such schema/network/credential contracts remain required.

Artifact provenance remains separate: **24 daemon artifacts** are still not uniquely classified by the primary acquired-image inventory. Five canonical capabilities remain missing: **Caddy, mastodon-rss-publisher, Worklane, TUIOS and Pi**. Supporting databases and identity instances have not been consolidated.

## Capacity and execution scope

The inventory exposes `memoryReservationMiB`, using the generation controller's conservative calculation: daemon limits plus the largest initializer limit per member. A regression compares the inventory value with an actually prepared unit bundle.

The full private proof graph reserves **102,528 MiB**, plus **16,384 MiB headroom**. Read-only observation before final execution found **42,889 MiB available**. The full graph was **not prepared or staged**. Canonical consolidation and tested resource sizing are required; protected workloads must not be evicted and limits must not be silently lowered.

The smaller native client supports:

```sh
python3 platform/scripts/test-private-generation.py --ownership-bound --applications
```

It exercises foundation/SQL-cache plus fresh Forgejo and Planka: **seven logical products, eight daemons** because Planka still has its own PostgreSQL. Dependency ordering does not imply shared database wiring. It checks ownership rejection before credentials, replay refusal, native workflows and restarts, unchanged initializer ledgers/container identities, and retirement of all four members. The four native workflow clients now reject optimized Python before imports/effects; a unit regression checks this alongside the parent client. Foundation's Podman command also explicitly disables remote mode.

## Final evidence

Engineering receipt: **`p0v3-compiled-ownership-9ea3526ff790`**. Controller/runner/build-configuration hashes stayed unchanged across final native execution.

| Scope | Receipt |
| --- | --- |
| Seven-product owned install, Git/issues and board/card workflows, restart, retirement | `p0v3-generation-788cc737f7b4` |
| Fresh five-service owned install/workflows/retirement | `p0v3-generation-916ddcda7e86` |
| Frozen authenticated encrypted capture | `p0v3-capture-c7120107f442` |
| Fresh five-service native restore/readback/restart/retirement | `p0v3-generation-restore-9993ccd16fc3` |

The seven-product cohort was **not** tested through coordinated encrypted recovery. The five-service regression preserves source ownership inside authenticated recovery without granting the target source site authority. Neither sequence is a full-stack cycle. All targets remain stopped/fenced; the protected **33 deployments / 109 daemons** and prior fence hashes are unchanged. The retained fence census is **59**. No boot enrollment, public activation or RSS publication occurred.

## Retained corrections

Three read-only evidence-packaging failures remain separate: `p0v3-compiled-ownership-1a66942be860`, `p0v3-compiled-ownership-df6272fd1fe4`, and `p0v3-compiled-ownership-d1b25c726dca`. Corrections handle the CLI's trailing explanatory line, its intentionally sanitized rejection message, and an omitted request default. No runtime operation occurred in those packaging attempts.

An unchanged full rebuild then changed five class files relative to the incremental build. Archive metadata reproducibility alone was insufficient. `platform/gradle.properties` now disables incremental Kotlin compilation. **Two complete unchanged builds matched all seven distribution files**, followed by fresh repetitions of every native scope above. Original native evidence remains bound to the retained earlier controller in `p0v3-compiled-ownership-b925fe8b30cd`: seven-product generation `76eaf5097d73`, five-service generation `445bca11e8ab`, capture `d55d48e7af2a`, and restore `5af71e534cdb`. None was relabelled as testing the final artifact, and all its fences remain retained.

Final unit gates: platform **213 passed / 4 opt-in integration skips**, **5152/5635 = 91.43%**; acceptance **36 / 98.23%**; Keykeeper **26 / 93.35%**; Worklane **142 / 90.31%** (unit-only, outside Herdr, no remote lab/dist publication). Python **112 passed**. The real acceptance manifest still exits 1: **62 missing or invalid checks**.

Next: typed canonical provider/schema/credential/network/identity wiring, remaining product recovery adapters, real whole-release `ReleaseEffects`, schedules, client/Android journeys and the immutable full-stack qualification matrix. These declarations do not complete those tasks.
