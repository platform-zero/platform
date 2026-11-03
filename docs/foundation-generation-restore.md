# Native encrypted foundation-generation restoration

The Kotlin controller now imports the **compiled foundation + SQL-cache cohort** from an authenticated cold capsule into fresh isolated `q-*` namespaces. Native historical-data readback and restart tests have passed for PostgreSQL, Valkey, ntfy, MariaDB and Memcached. This is a **five-service component restore**, not whole-release restoration or either final qualification cycle. Full-stack count: **0/2**.

A separate [seven-product application adapter](application-generation-restore.md) now adds Forgejo and Planka with historical native readback and four-member fault isolation. The foundation command below retains its strict two-member boundary.

## Interfaces and scope

```text
platform release generation-recovery-check ARCHIVE KEY_FILE CAP_ID SOURCE_Q SOURCE_BUNDLE_SHA EXTRACTED_DIRECTORY
platform release generation-restore-foundation INVENTORY SOURCE_Q SOURCE_BUNDLE_SHA CAP_ID FRESH_TARGET_Q
```

The import command requires the retained source generation/capture records and separate custody key. It is not a complete standalone disaster-recovery bootstrap from an archive alone. It never starts or unfences the source. On success, it leaves **all target members stopped and fenced**. On a caught failure, the controller retains the failed import result and independently attempts reverse-order isolation of every member, even if writing that result fails. Incomplete preparation can prevent isolation; its failure is recorded without generating missing credentials. Fatal process loss retains unresolved intents for explicit stop-only reconciliation. No daemon is started by this command. The acceptance client starts only its newly imported target after whole-cohort success and retires the whole target afterward, including on failures. Failed groups must not be started or replayed.

`GenerationRecovery` checks recovered plaintext against a fresh cryptographic verification, not a caller-authored success file. It verifies the exact source bundle digest, member cohort/order, serialized manifests, input hashes, fingerprints, source process states, completed initializer ledgers/checksums and the complete expected payload set. Every volume passes the strict tar gate.

The foundation cohort of `FoundationRestore` compares source specifications with the compiled recipes and pinned inventory. Other products and changed recipe definitions are rejected by this command; the separate application command selects its own exact four-member cohort. It removes the two initializer processes and their dependency edges from target definitions; it does **not** fabricate successful target initializer ledgers or run database/account/password initialization. Original credentials are copied byte-for-byte. PostgreSQL receives the recovered environment for client credential custody, but starts the existing database directly.

## Explicit compiled whole-cohort projection — source implementation

`ColdRestoreCohort.WHOLE_RELEASE` now selects per-recipe reviewed projections rather than the old fixed three-recipe canonical cohort. `FoundationRestore.bundle` recompiles every member from the pinned inventory, compares its archived definition with that compiler (or its exact daemon-only projection for continued recovery), verifies credential input closure, preserves all volumes/networks/artifact identities, and rejects any retained initializer. Original candidate identity and immutable Kopia snapshot lineage are preserved. Source-only ingress publication is validated as historical metadata but stripped from targets, together with site/assembly authority.

Registered projections include canonical-providers (central identity/Firefly plus Caddy without autosave resume), sealed OpenBao, Caddy, Synapse/Matrix/MatrixRTC/LiveKit, Seafile/Office/Notebook/JupyterHub, and the ten reviewed business/mail recipes, alongside the existing foundation/application cohorts. A recipe must also be registered in the assembly catalog. The standalone Planka whole-cohort projection is distinct from the legacy compatibility projection. No generic `filterNot(oneShot)` fallback admits unknown recipes. Huly, legacy identity/Keykeeper/Matrix-identity and other unreviewed automatic-bootstrap entrypoints remain refused. A private composite's restore support does not establish unique canonical provider ownership or full-release capability closure.

The shared controller exposes `restoreKopiaWholeRelease`; dispatch/transaction ownership remains with the release controller. These changes are source-only with coordinator unit checks requested, not new native restore evidence. Unsupported filesystem metadata and full standalone generation-journal disaster bootstrap remain explicit limitations.

## Import safety

- All members/images are audited before allocation; each target rechecks pristine resources under its runtime lock.
- Capacity reservations include scratch extraction, imported data and verification exports. Source and failed target resources are never evicted.
- The target bundle binds the source archive SHA-256. Immutable group/member import intents precede effects. Ordinary clean-install staging is refused for these restored generations.
- Each runtime compares volume bytes with the authenticated capsule's declared hashes under its runtime lock, before allocation and again around import; it does not adopt a new hash from potentially changed recovery scratch.
- Each runtime writes an import intent and maintenance fence before resource creation/import. It imports only declared volumes into the fresh owned namespace.
- Podman omits mount-root attributes during **import as well as export**. The adapter applies the authenticated root UID, GID, mode and modification time only to the fresh target's dedicated volume root. It does not recursively change arbitrary paths or modify the source.
- Before declaring a member imported, the controller re-exports its volumes and compares the complete canonical entry trees: paths, types, owners, modes, byte counts, file hashes and nanosecond-resolution modification times (including negative epochs). This does not claim complete ACL/xattr or unsupported-link equivalence.
- Exclusive completion markers are written only after every volume comparison passes. Missing/corrupt completion evidence blocks ordinary startup and maintenance release. Failure leaves partial data and fences retained; there is no implicit replay.
- No target daemon starts in the import command, no boot units are enrolled, and no public routes/outbound publication are activated.

Source initialization ledgers remain in the recovered source evidence. Targets have no declared initializer and no fabricated `runtime.jobs`. The capsule verifier's `functionalRestoreVerified:false` remains unchanged: it is a cryptographic verifier, not the native application evaluator.

## Executed native proof

Source generation: `q-f4dc52665920`.

Source capsule: `cap-c938db00fc81`, archive SHA-256 `97e88fa24fe418cd4d365945e19b6e2137b1437701e33e00a5aca49caac054a8`.

First passing receipt: **`p0v3-generation-restore-b695492eeb3c`**.

Earlier passing receipt, after authenticated per-volume hash binding under the runtime lock: **`p0v3-generation-restore-a0e84930f38e`**.

That historical target: `q-a0e84930f38e`, bundle SHA-256 `6dcea213ef681f00d4eb4ccc0d35115dce1b02c820eae83da1d6bfa87fc46a29`. The earlier passing target/bundle remain retained as historical evidence; this hardening does not retroactively change that execution.

The probe verified:

- Original PostgreSQL row and matching authenticated Valkey value.
- Original ntfy message, including unchanged message ID, time and expiry, through the native HTTP polling API; the expected record came from the authenticated source SQLite state. Expired source messages are not renewed or silently substituted.
- Original MariaDB committed row, absence of the rolled-back row, no anonymous/remote root accounts and passwordless-root rejection.
- Memcached native set/get and empty cache after restart. Its ephemeral contents are not claimed as durable restored state.
- The same historical native readback after stopping/restarting all five restored daemons.
- No initializer replay, source startup, source fence release or source configuration/ledger changes.

The target was retired with fences:

- foundation: `d3f7f1e5-dd9d-447f-a43b-05c8173ce795`
- SQL-cache: `cd364a08-2674-47a9-a598-3e9e316c5f4d`

The protected fleet remains **33 enabled/active deployments and 109 declared running daemons**. All prior fences were unchanged. **23 fences** were retained at that checkpoint, including eight member targets across four restore attempts. The [subsequent fault-recovery increment](import-fault-recovery.md) brings the census to **35**, including actual controller-kill and caught integrity-failure targets and two more passing five-service restores. The latest is `p0v3-generation-restore-f22a7f08bbac`, executed on the reproducibly rebuilt final controller artifact. The two component successes occurred across a hardening change; they are not a frozen-candidate qualification streak.

## Preserved failures and corrections

1. **`p0v3-generation-restore-c8abf1f0c214`**: the first native import correctly failed readback because Podman left the volume root owned by UID/GID 0 with mode 0755. No application started. The adapter was repaired to apply authenticated root attributes before re-export comparison. Both target members remain fenced; the failed import was not replayed.
2. **`p0v3-generation-restore-74119974eff5`**: imports and historical application readback passed before and after restart, but the Memcached probe used a stale pre-restart IP and failed with `OSError`. The probe now resolves the owned container's current private-network address for every request. The overall attempt remains failed and retired; a new target produced the passing receipt above.

Neither failure was relabelled as success. Those early attempts did not test actual process interruption. The [later scoped controller-kill and integrity-failure tests](import-fault-recovery.md) now exercise failure handling natively; they are not host power-loss or whole-stack recovery tests. Unit simulations, native fault probes and functional component restoration remain separate evidence.

## Ownership-bound follow-up

The [owned-generation lifecycle](owned-generation-preparation.md) now supplies a fresh source with validated process/state/input/route ownership sealed into its bundle. Final source `q-24e5ebfbf463`, capsule `cap-c5c4393773c3` and restored target `q-8f46b3c9b457` passed native install/capture/restore checks. The authenticated source ownership record is retained, but its site/route policy is not inherited as authority over the private restore namespace. Earlier fixtures remain stopped and unchanged. The retained fence census is now 43; full-stack qualification remains 0/2.

## Still unfinished

Whole-release `ReleaseEffects`, remaining application-specific imports/crypto/permission journeys, coordinated schedules/retention, post-snapshot exclusion and broader fault cases, canonical central wiring, lane/client integrations and the two fresh complete install/restore cycles remain open. This adapter does not authorize public activation.
