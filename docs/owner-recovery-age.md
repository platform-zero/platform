# Owner recovery age identity — local setup and independent handoff

`OwnerRecoveryAgeIdentity.issue(generation)` is a one-use recovery-owner operation invoked by core under its generation lock. It pins `/home/gerald/.local/bin/age-keygen` to SHA-256 `c56ef69834e18ca4d3b953117f4481522c35fb6862a5d2871685aa4685893664`. It generates a **new** identity, never asks the user for a recipient, and writes nothing to stdout/stderr or an application mount. On any partial/uncertain issuance, do **not** rerun or regenerate; preserve the intent and seek separate disposition. Core must invoke `verifyLocal(generation)` before passing `publicRecipient(generation)` to the existing `GenerationBaoOfflineCustody.encryptOriginal` as an `ActivationInput`. This wiring belongs to core's generation owner/CLI; no lifecycle edits were made here.

For `q-<12 hex>`, the exact local paths are:

| Item | Path | Access/meaning |
|---|---|---|
| Owner **secret** | `/home/gerald/.local/share/p0-v3-recovery/age/<generation>/identity.txt` | Parent directories 0700; identity 0600, CREATE_NEW; not in `/mnt/media/p0-v3`, the Kopia repository, generation capture or application mounts. **This host still holds the key.** |
| Private binding/attempt | Same directory, `binding.json` and `issue.intent.json` | Identity SHA-256, generation, recipient/inventory/tool SHA-256; no secret bytes in JSON. |
| Public recipient | `/mnt/media/p0-v3/release-bootstrap-anchors/bao/owner-recipients/<generation>.agepub` | One `age1…` line, 0600 CREATE_NEW; `ActivationInput` path and byte SHA-256 passed automatically to Bao export. |
| Public inventory | Same recipient directory, `<generation>.inventory.json` | Schema 1; exact generation, recipient string, recipient-file `ActivationInput`, pinned tool SHA-256, `localIdentityOnly=true`, `independentExportVerified=false`. No claim of offline custody. |
| Bao ciphertext | Generation-local `bao-custody/<generation>-original-init.age` | Existing one-use Bao export; separate from the identity directory. Encrypted bytes alone do **not** prove recoverability. |

**No independently owner-controlled off-host/removable destination has been demonstrated.** Existing `/mnt/media/p0-v3/kopia-custody` and `generation-custody` are not separate offline custody. The generated key is *local only*. An actual off-host export and a second-machine/offline recipient+decryption readback, with a separate owner-controlled attested handoff, remain separate **offsite-readiness gates**, deferred from local 2/2. Local 2/2 instead requires actual protected decryption of the original encrypted Bao export with this 0600 local identity, matching original init bytes/hash and a genuine isolated RESTORE. Neither `issue`, `verifyLocal`, nor the Bao encrypted-export result may set `operatorOfflineHandoffAcknowledged` to true.

When the operator later provides a mounted, owner-controlled, independently retained destination, core should stop effects/hold the owner lock and create an export intent identifying its verified device/failure domain. Export **once**, as the owner, without shell tracing or a screen/log capture. For example, with `GEN=q-...` and `DEST` an audited empty 0700 directory on the separate device (not `/mnt/media/p0-v3`):

```sh
set +x
umask 077
set -C  # noclobber: never overwrite an uncertain earlier export
SRC="/home/gerald/.local/share/p0-v3-recovery/age/$GEN/identity.txt"
PUB="/mnt/media/p0-v3/release-bootstrap-anchors/bao/owner-recipients/$GEN.agepub"
# Check exact GEN, owner, directories, separate mount and destination before proceeding.
# NEVER display the private file, send it to chat, or place it in an app volume.
( cd "$DEST" && cat "$SRC" > identity.txt )
chmod 600 "$DEST/identity.txt"
/home/gerald/.local/bin/age-keygen -y "$DEST/identity.txt" | cmp - "$PUB"
# Flush/safely unmount the independent destination; separately verify it on another machine.
```

The `cmp` output must be empty; nonzero exit means **stop**. The destination identity is itself secret: encrypt/physically secure it using owner-controlled independent custody and test decryption of the actual Bao export **off this host** before treating it as disaster-recovery evidence. On a separate offline machine with the pinned age binary and owner-approved recovery medium, `age -d -i /secure/identity.txt -o /secure/bao-init.json /secure/<generation>-original-init.age` writes sensitive unseal shares/root material to a private 0600 file; keep it out of logs/CLI arguments except file paths, never print contents, and delete only under a documented key-handling policy. An isolated RESTORE still requires owner-authorized original-share use and native Bao/CID/leaf readbacks; local decrypt alone or a hash-only handoff is not authorization. Managed Pi may reuse existing authorized host-broker subscription custody under the local-only candidate policy; no separate project key or fresh manual PKCE is demanded solely for that managed path. This does not assert independent offsite key custody. Keep the source and target journals and the original encrypted export intact after uncertainty.
