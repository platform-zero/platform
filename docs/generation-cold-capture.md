# Generation-bound encrypted cold capture

The Kotlin controller now captures **every declared state volume and runtime input** of a successfully staged, isolated private generation. This is a real capture/verification actuator, **not a completed restore backend or full-release backup claim**. It does not establish that every application's external keys, client state, in-memory work or authoritative recovery requirements are declared. Full-stack qualification remains **0/2**.

## Commands

```text
platform release generation-capture Q_ID BUNDLE_SHA256 CAP_ID
platform release generation-verify-capture Q_ID BUNDLE_SHA256 CAP_ID
platform release capsule-verify ARCHIVE KEY_FILE CAP_ID Q_ID BUNDLE_SHA256
```

`CAP_ID` is a fresh `cap-<12 lowercase hex>` identity. The standalone verifier needs the capsule, custody key and expected identity bindings, not running source services. It never extracts or imports data.

## Recovery preparation and root-metadata correction

[Authenticated extraction and strict tar inspection](generation-recovery-preparation.md) are now implemented, without runtime import in the capsule layer itself. A separate [compiled foundation-generation adapter](foundation-generation-restore.md) now has native import/readback proof. Native inspection found that the initial Podman exports omitted root-directory attributes. The earlier capsules below remain authenticated historical captures but are not structurally sufficient for strict restoration. New captures preserve an observed explicit root header; do not backfill or infer attributes for an older capsule.

## Source boundary

- A completed, matching stage and linked successful isolation are required. Current ownership, pinned images, inputs and fence identities are audited again.
- All member runtime locks remain held together throughout export, encryption and verification. `PrivateDeployment.withFrozen` checks exact fences, complete initializer ledgers, present/cleanly stopped daemons and successful initializer exits before the read, then rechecks inputs, ledger bytes and stopped states afterward. A member with no initializer has an explicit absence-bound ledger digest.
- Initializers, send operations, migrations, source startup and fence release are never invoked. Uncertain initialization or a running/unclean/missing daemon rejects capture.
- The capsule includes the sealed generation bundle, exact member manifests, input files, available initializer ledgers and one opaque native tar export per declared volume. It binds observed fingerprints, fence IDs and completed initializers.
- These checks establish a locked cold read of declared resources, **not application queue-drain semantics, universal host quiescence or functional restorability**. The separate strict tar gate validates supported payload structures without extracting them into runtime volumes. The separate compiled foundation adapter consumes this gate; arbitrary product import is not authorized.

## Bounds, confidentiality and custody

A native volume export runs only against the already audited member namespace in the dedicated v3 store. A privileged per-process file-size limit bounds each scratch export plus its root header to 8 GiB; a privileged timeout bounds the export CLI. Exports over 1 GiB are represented by bounded 1 GiB physical segments plus an authenticated ordered volume descriptor; aggregate payload remains capped at 8 GiB. Export is read-only with respect to source application data. An interrupted/timed-out export is inconclusive and cannot produce a passing capture; this is not a general proof of privileged descendant containment.

Payloads are limited to 8 GiB total, 4,096 files and a 1 MiB manifest. Admission reserves three worst-case payload copies for legacy capsule framing, or four for Kopia export/segmentation/staging/repository output, plus 10 GiB headroom and format overhead. These observations do not impose a host-wide filesystem quota or prevent unrelated future disk consumption.

Capsules use a versioned streaming **AES-256-CTR + HMAC-SHA256 encrypt-then-MAC** envelope with separate independent encryption/MAC key halves, a fresh 128-bit IV and a fresh 64-byte custody secret for every capsule. The complete header and ciphertext are authenticated before ZIP parsing. Every payload is subsequently streamed and checked against its exact size and SHA-256 manifest declaration. The reported archive digest must equal the digest of the bytes actually authenticated, with a final bounded file rehash to reject content changes during verification. Wrong keys, altered/truncated/appended ciphertext, wrong identities and payload mismatches fail closed.

- Capsule: `release-generations/Q_ID/captures/CAP_ID/state.cap` under the dedicated v3 tree.
- Custody: `/mnt/media/p0-v3/generation-custody/CAP_ID.key`, separately held in an owned mode-0700 directory and a mode-0600 single-link file.
- Keys are not passed as command-line values or printed. There is no Bao initialization/unseal or token renewal.
- Plaintext volume scratch files temporarily exist in this attempt's private directory. Only these exact scratch exports are deleted after authenticated verification and successful source rechecks. Failures retain partial evidence; source files, action intents and fences are never deleted.
- This is **same-host local custody**, not off-host durability, protection from host root or an installed daily/weekly recovery schedule. It is not a Kopia repository snapshot.

Group capture intents precede export. Results are exclusive/fsynced and cannot overwrite earlier attempts. A failed/incomplete capture cannot be treated as a last-good point. Fresh read-only capture attempts may use new IDs without replaying any source business operation. Authentication always reports `functionalRestoreVerified:false`.

## Executed evidence

Source generation: `q-f4dc52665920`, bundle `68b9cb96cd956e455099fa4692e576c58ac58d48cedb1ce463099b2366286d6e` (the retired foundation/SQL-cache engineering generation).

- Initial native receipt: **`p0v3-capture-308464b7e228`**.
- Latest native receipt: **`p0v3-capture-99b2840a6d58`**, capsule **`cap-99b2840a6d58`**.
- Latest encrypted archive SHA-256: `0476952390f3b84e27a0aa69c4252652b5f2d4b53defd122709c76a257362f6c`.
- Latest manifest SHA-256 (manifest stored inside the encrypted capsule): `4b8bc94034a2a1a2d995d87e6a45b57975cfa2fcf92b4558d7c0315b01774d9b`.

Each captured 12 payloads / 159,259,619 plaintext bytes: four declared state volumes, two manifests, three inputs, two initializer ledgers and the generation bundle. Controller verification and standalone verification passed; wrong-key and tampering checks rejected; scratch exports were removed. Source inputs/ledgers/fences remained unchanged. The protected fleet stayed at **33 enabled/active deployments and 109 declared running daemons**, with all **15 retained fences** unchanged. No source was started or unfenced.

The later run follows the simultaneous scratch-plus-ciphertext admission regression. A subsequent read-only verification of that same capsule also passed the authenticated-byte/final-file-digest cross-check. Earlier evidence remains bound to its own execution, not rewritten as later validation.

Unit tests cover authentication, truncation/tampering/wrong scopes, fresh keys, unsafe file/path rejection, cold-lock requirements, incomplete initialization, absent-ledger semantics, capture failures, all-member lock lifetime and disk headroom. An initial test compilation failure was corrected by adding missing test assertion imports; it ran no native operations and its log is retained.

**Neither capture is an isolated functional restore, a verified recovery point under the completion contract, or either full-stack install/restore cycle.** Guarded capsule extraction and strict tar inspection are now available separately. The foundation/SQL-cache adapter now passes native import and restored readback. Other product imports and crypto checks, complete recovery contracts, coordinated schedules and `ReleaseEffects` integration remain unfinished.
