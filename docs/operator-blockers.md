# Operator inputs, qualification admission and engineering gaps

> **Superseding authority:** [rapid completion](rapid-completion.md). Execute directly through
> 2/2 with builds, acquisition, tests and bounded runtime integration; no subagents or
> coverage quota. Public cutover and irreversible external actions are not authorized.
> Qualification remains **0/2**.

## Established admission gaps

The latest read-only host check found these paths absent:

- `/mnt/media/p0-v3/release-trust/qualification-producer-ed25519.pub`
- `/mnt/media/p0-v3/release-bootstrap-anchors/trusted-operator-ed25519.pub`
- `/mnt/media/p0-v3/release-artifacts`

Live qualification admission needs the approved producer public key/provenance and the
matching authentic signed input envelope/artifact closure. Supply its location or acquisition
route, not a private key in chat. An arbitrarily generated signer is not an independently
provisioned trust anchor. These are integrity/custody inputs, not an added human review gate.
The absent artifact catalog also requires engineering assembly; it is not by itself a task
for the operator. Missing Donetick/ONLYOFFICE Android catalog pins and unverified authentic
client/tool custody remain unresolved. Source inventory alone does not establish upstream
availability or installed custody.

Supplying trust inputs alone will not establish first-cycle readiness. Canonical assembly,
remaining actors/adapters, credentials, managed lanes and genuine runtime workflows remain
engineering work. Continue unblocked work without claiming a qualification pass. Current
results and the sole capability backlog are in [rapid completion](rapid-completion.md).

The current [completion contract](completion-plan.md) uses **AI-only automated self-qualification, no human approval gates and no subagents**. AI may diagnose failures, correct implementation/configuration or defective tests, and rerun safely without asking for approval. Passing evidence and protected boundaries remain mandatory. Full-stack automated qualification is **0/2**; historical independent-review references below are not current human-approval gates.

The previous version of this document incorrectly assigned release engineering to the operator and treated missing public activation inputs as a reason to halt work. That interpretation is superseded by the owner's explicit instruction to complete the engineering directly, without subagents.

The implementation agent selects supported upstream releases, resolves manifests, downloads images, creates v3-owned runtime boundaries, generates protected service credentials and recovery material, implements configurations and lifecycle commands, and performs private integration/recovery tests. These tasks do **not** wait for an operator-authored lock or credentials.

## Historical component context (not current candidate admission)

Earlier acquisition and real component results are in [image-acquisition.md](image-acquisition.md): 55 main-inventory upstream candidate images plus a separately acquired and privately deployed native mail-family candidate, a locally built Keykeeper runtime, and Caddy/ntfy/encrypted-Kopia functional restore. The rootful private store has been created and used. Those acquired component artifacts do not establish the current signed qualification-client/input closure or release-artifact catalog. [Private mail evidence](private-mail-integration.md) now covers SMTP/IMAP persistence and denials, not public delivery. A [separate SOGo/mail composite](private-sogo-mail-integration.md) now has native SMTP/IMAP/browser, transport/authorization-denial and supervised persistence evidence; [coordinated encrypted composite recovery](private-sogo-mail-recovery.md) now passes isolated native readback, attachment/authorization checks, restart and write isolation. Production custody and whole-release recovery remain engineering work.

Public activation still must use approved hostname scope and actual DNS/HTTP-01 reachability, preserve existing unrelated services, retain recovery keys, and pass independent product journeys. A check that fails blocks the affected operation, not unrelated engineering. The installer cannot make an unrelated public route approved by merely writing it into a file, or convert its own synthetic success receipt into independent acceptance.

The earlier legacy store exhausted its 2,048 shared object locks. A separately bound file-lock store and a recovered-source timer/re-restore chain subsequently passed engineering probes before the former unit-only restriction. Those historical results do not qualify the changed source artifact or a full release. Store-bound fresh preparation is now implemented and unit-tested; full canonical assembly/capacity remain unfinished. Do not resize/renumber the host-shared pool. Current bounded integration authority does not authorize shared-pool changes, broad cleanup, protected-workload eviction or uncertain-effect replay.

Work remaining belongs to the implementation: all-product compatibility and configuration, local RSS/Keykeeper integration and Worklane lane runtime, actual Kotlin release backend, coordinated DB/files/key backups and restores, Caddy issuance/renewal/cutover, migration and crash recovery, independent real-domain browser/Android journeys and two complete clean install/restore attempts. Full-stack acceptance remains **0/2**, not two successful component tests.
