# Authenticated recovery preparation — not a functional restore

The controller can now extract a capsule into a **fresh private directory**, then inspect every volume tar without importing it or executing anything from it. The separately scoped [foundation-generation restore adapter](foundation-generation-restore.md) now implements import journals and native five-service readback. Generic/whole-release application restoration and remaining client journeys are unfinished. Full-stack qualification remains **0/2**.

```text
platform release capsule-extract ARCHIVE KEY_FILE CAP_ID Q_ID BUNDLE_SHA256 FRESH_PRIVATE_DIRECTORY
platform release volume-tar-inspect PRIVATE_TAR EXPECTED_UID_AND_GID
```

The extractor first authenticates and validates the whole capsule without plaintext writes. It then authenticates again, requires the same archive digest before writing, uses exclusive private file creation, checks every recovered payload hash and size, and fsyncs data/directories. Admission checks the destination filesystem for payload space, 512 MiB metadata allowance and 10 GiB protected headroom; capsule paths are limited to eight components. This is not a filesystem quota or protection from concurrent unrelated disk consumption. Absolute paths, traversal, duplicate names, file/parent conflicts, the reserved manifest namespace and existing destination reuse are refused. No links or archive-provided permissions are installed by this ZIP extraction: outputs are regular mode-0600 files in owned mode-0700 directories.

An exception retains partial private output. **Neither directory existence nor a recovered manifest alone establishes completed extraction.** The caller must retain successful invocation evidence and revalidate payloads before any later import. Recovered files include plaintext databases and credentials; they must remain private and must not be served publicly or committed to Git.

## Structural tar gate

`VolumeTar` is a bounded, read-only USTAR/PAX parser. It checks header checksums, block alignment, terminators, payload sizes, hierarchy, unique normalized paths, numeric owner/group, modes and file-content digests. It rejects links, devices, FIFOs, sparse/GNU extensions, unsupported PAX attributes, privilege bits, unexpected owners, dangling metadata and trailing nonzero data. An explicit root directory is mandatory. The supported UID and GID are equal; other ownership contracts require a separately implemented adapter, not a relaxed invocation.

This gate does **not** unpack the tar, prove database consistency or establish that an application's full recovery requirements are declared. Canonical entry digests cover paths, types, POSIX owners/modes, lengths and bytes; they do not claim complete ACL/xattr or application semantics.

## Segmented and controller payloads — current source, runtime unverified

`CapsuleManifest.volumes` describes canonical ordered `.tar.part-0000` segments, total archive bytes and SHA-256. Empty `volumes` is omitted from serialization, preserving existing manifest hashes. Each physical segment remains at most 1 GiB; the aggregate physical payload and each reconstructed archive remain bounded by 8 GiB. Segmentation is transport framing, not a replacement encryption/deduplication engine: production snapshots still belong to Kopia. Captures retain the original tar until authenticated success and now reserve extra scratch space for segmentation.

`GenerationRecovery` authenticates the exact physical file set and every segment before `RecoverySegments` exclusively creates reconstructed archives. Reassembly checks per-part hashes again while streaming, final size/hash, free disk plus 10 GiB headroom and 512 MiB metadata allowance. Partial outputs remain retained; they cannot be silently overwritten on retry. Tar inspection and native import/re-export compare nanosecond timestamps, including negative epoch times, as well as file content, UID/GID, modes, root metadata and complete hierarchy. Unsupported links, ACLs/xattrs and sparse formats remain rejected rather than claimed preserved.

Default-omitted `controllerFiles` permits only the explicitly declared `controller/rss-qualification/...` subtree. Original invocation fixtures, feed observations and checkpoint bytes are restored into the fresh target controller only after cohort import; no enabled schedule, activation permit, live socket or process authority is inherited. The inert RSS lock-file marker is data, not a restored kernel lock. Every directory is private, files are bounded/single-link, and import uses CREATE_NEW. The enclosing release lifecycle must quiesce RSS writers before capture; copying a concurrently mutating controller tree is not a supported consistency strategy.

Tests added for framing, corruption, ordering, headroom, interruption, replay, original controller fixtures and nanosecond equality are coordinator-run unit requests. The historical native results below do **not** validate these changes.

## Native-discovered capture defect and repair

Native inspection found that `podman volume export` exports the directory's children but omits the volume root itself. Thus the earlier capsules `cap-308464b7e228` and `cap-99b2840a6d58` authenticate their payloads, but **lack the original root attributes needed for strict restoration**. They remain retained; they have not been rewritten, backfilled or promoted to recovery points. The validator continues to reject those child-only tars.

`ColdVolumeExport` now reads the mount root's UID, GID, POSIX mode and modification time before and after export, under the existing stopped-source runtime lock. It uses only the dedicated, validated v3 volume namespace and refuses non-directory roots. It prepends a standard root-directory tar header to the private scratch export. The kernel export-size bound reserves space for that header; the scratch remains bounded and is not a source-volume mutation. New capture is required rather than inferring missing historical metadata.

The new capsule **`cap-c938db00fc81`**, receipt **`p0v3-capture-c938db00fc81`**, contains 12 payloads / **159,261,667 bytes**, including the four explicit root headers. Archive SHA-256:

`97e88fa24fe418cd4d365945e19b6e2137b1437701e33e00a5aca49caac054a8`

Native extraction/inspection **`p0v3-extraction-6724a66ec19f`** passed; the final guarded build also passed as **`p0v3-extraction-9aac1112c9c3`**, including destination-capacity admission and archive-digest binding before plaintext writes. Both validated:

| Volume | Validated entries, including root |
| --- | ---: |
| PostgreSQL | 1,002 |
| Valkey | 6 |
| ntfy | 3 |
| MariaDB | 208 |

Every recovered payload matched its authenticated digest. Reusing the destination was denied without overwriting its contents. No volume import, service startup, initializer replay, fence release, boot enrollment or public activation occurred. The capture census retained the protected 33 deployments / 109 daemons and all 15 fences.

Failures are retained:

- `p0v3-extraction-e18e732ba6ed`: the first ad hoc runner used Java 17 against Java 21 bytecode. No controller extraction executed. The reusable harness now explicitly selects Java 21 and a scrubbed private environment.
- `p0v3-extraction-fac391106a09`: authenticated extraction succeeded, then strict PostgreSQL tar inspection rejected the missing root. This exposed the capture defect; the requirement was preserved, not weakened.

`platform/scripts/test-capsule-extraction.py` records intents, CLI-tree hashes, private outputs and results. It refuses optimized Python before effects. These are recovery-preparation engineering checks, **not either final install/restore cycle**.
