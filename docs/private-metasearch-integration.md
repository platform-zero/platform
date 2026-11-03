# Private SearXNG integration

`searxng-r2` runs pinned SearXNG `2026.10.30-ffa88e3ba` and a private HTTPS nginx frontend. At introduction it added private runtime coverage for a 28th selected family: **53 daemons in 21 supervised deployments, plus OpenBao within that daemon count**. See [the current runtime inventory](private-runtime.md) for subsequent additions. This is not completion of the 39-family release. **Full-stack acceptance remains 0/2.**

## Actual functionality

The native upstream SQLite engine searches a persistent synthetic SQLite FTS5 corpus. This is real query execution, not a fixed-response mock: term, exact-phrase, unrelated-term, empty-result and two-page queries return different, checked results. The 15 documents were generated solely for this deployment; no existing documents, media, browser history or owner information were imported.

The native engine opens SQLite with `mode=ro` and binds query parameters. Its volume is owned by UID 977; it is not claimed to be a kernel-enforced read-only volume. A journalled one-shot initializer refuses an existing database or interrupted pending file, commits and checks SQLite integrity, then fsyncs and atomically installs the database. Completed initialization is never silently replayed.

All default upstream engines are removed with `keep_only: []`, then only `private corpus` is configured. Native `/config` is checked to contain exactly that engine. Autocomplete and image proxying are disabled. **No public search provider was queried or tested.** The deployment uses an internal-only network with no host port bindings. Public activation requires explicit authentication/rate-limit/egress decisions; the fixture's native limiter is disabled and must not be mistaken for a public-instance policy.

The browser performs an actual native POST search and checks both rendered result titles, then performs an empty-result search. Result links point to reserved `example.invalid` fixture destinations and are never followed. Chromium requests are restricted to `https://search:8443`, with downloads disabled. Private CA and hostname/leaf verification precede browser launch; system-CA verification rejects the private certificate. No shared trust store is changed.

Both daemons run non-root, with read-only roots, dropped capabilities and the dedicated AppArmor profile. The upstream root entrypoint is bypassed in favour of direct Granian execution; no image-time certificate or ownership mutation is needed. Native HTML search uses POST and nginx access logging is disabled. This does not claim searches are absent from every possible client-side history or diagnostic.

## Evidence

Protected receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-metasearch-b614ecc12aaf`: native JSON and Chromium workflows before/after ordinary clean restart.
- `p0v3-metasearch-0ea24b1b85ec`: the same workflows with actual pinned systemd restart, unchanged container IDs, new start timestamps, unchanged initializer journal and unchanged SQLite bytes. The final browser screenshot was inspected.
- **`p0v3-metasearch-7a8eab5b7e1e`**: latest supervised repeat, additionally requiring HTTP 200 for the browser's empty-result response.

Manifest SHA-256: `d7034f5960b96db88a90f74f9d12176369f3cd1f3e3fca406e052290980f697a`.
Certificate SHA-256: `0e42b2342e7e4c006a1baf61e5815b633e7c6876c6e2122efa12b0964aa6ea48`.
Initial corpus SHA-256: `6be230d328b483e5f51b501d618b71b1e1c6abfd5a541824837e6661071d5483`. Recovery tests subsequently add uniquely named synthetic records; they do not alter existing documents.
Controller tree: `5f09b14f8cb818a62186e00400516898cf897d0434a6641fdb47b110eb5c69b8` (tenth immutable snapshot).

The original `searxng` deployment is stopped and retained. Its native default search form used GET, while the browser probe required POST; failed receipts `p0v3-metasearch-347c6bc7083e` and `p0v3-metasearch-7ac0f2fdcf35` remain failed. A new revision explicitly selected POST rather than silently replacing immutable inputs.

## Reproduction

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
python3 platform/scripts/test-private-searxng.py --supervised
```

Fresh preparation: `runtime prepare-searxng INVENTORY NEW_NAME`. The Python harness rejects optimized Python before effects and finalizes receipts fail-closed on later errors. New deployments do not reuse an existing corpus directory.

Source implementation: `SearxngRuntime.kt`, `SearxngRuntimeTest.kt`, `scripts/test-private-searxng.py`, and `../acceptance/scripts/SearxngBrowserProbe.java`. Upstream engine/configuration behaviour was checked against [the pinned SQLite engine](https://github.com/searxng/searxng/blob/ffa88e3ba/searx/engines/sqlite.py), [settings loader](https://github.com/searxng/searxng/blob/ffa88e3ba/searx/settings_loader.py), and [container entrypoint](https://github.com/searxng/searxng/blob/ffa88e3ba/container/entrypoint.sh). Upstream licensing is AGPL-3.0-or-later.

## Encrypted isolated recovery

`SearxngRecovery.kt` and `scripts/test-searxng-encrypted-restore.py` now implement and exercise the exact supported offline recipe:

1. Verify the source unit's manifest binding, create a synthetic pre-snapshot record, disable its boot unit and persist a durable backup fence. Ordinary apply is rejected while fenced. Hold the runtime lock throughout capture and verify stopped container IDs/start times, journal, inputs and database bytes remain unchanged.
2. Require that the stopped corpus volume contains only `documents.db`; unexpected WAL, journal or other state is not silently discarded. Capture the stopped SQLite database, original recipe, all application inputs and TLS keys into a complete checksum manifest. Kopia creates an encrypted snapshot, verifies 100% of files and exports it. A fresh repository connection using an incorrect password is explicitly rejected.
3. Verify the exact exported file set and every checksum before preparation. Import **the exported database**, not the live source or in-memory capture, into an empty isolated target under its runtime lock. There is no archive extraction or arbitrary path handling: the only database destination is the fixed `documents.db` name.
4. Replace corpus initialization with a manifest-bound, read-only recovery guard. Never seed or migrate the restored corpus. Native guard-command checks reject missing/incomplete/foreign markers, a dangling in-progress symlink and a completion symlink even when its destination contains the correct manifest. SQLite integrity and expected columns are checked before the serving processes start.
5. Verify the pre-snapshot record through native search, exclude a post-snapshot source record, run the full restored API/Chromium suite, and prove separate source/target writes persist across target restart and a source systemd restart. Target-to-source TCP connections to both services are rejected.
6. Stop and retain the restore target; release only the known source fence generation and resume source supervision. Unknown fence identity fails closed. Receipt finalization also fails closed on operation or cleanup errors. Protected repository passwords remain local fixture recovery material, not production/off-host custody.

Receipts:

- `p0v3-search-restore-b76922a78b7a`, snapshot `k529b0ee74b75806258052ea3f6e9899d`: initial fenced functional recovery.
- `p0v3-search-restore-0404732edb76`, snapshot `k1f77b3fdf988368dfa692e08f0cb4e87`: adds wrong-password and symlink-marker denial.
- `p0v3-search-restore-6f1ff86e07ec`, snapshot `kaa4756289eb1e2fbd8fdc099b551cc58`: also verifies source supervised restart and persistent divergent records. Archive manifest SHA-256 `93339bab05285a490bc1c4043bf662448955f39ff0635d1085841f1ed4cabd25`; restored browser receipt `p0v3-metasearch-1a765394ec2d`.

- **`p0v3-search-restore-9add4861f32f`**, snapshot **`kc0dcfe4127891fa1329e55a5e8d1429a`**: latest complete repeat, including the single-file capture precondition. Archive manifest SHA-256 `885eea4030d2fda778832d46c5bd6d7b84135aafc41e3ec0a5b9b29dc87586d4`; restored browser receipt `p0v3-metasearch-25ec0d2b1245`.

All `sxrestore-*` targets are stopped. Markers bind the source manifest, not a unique snapshot; exported manifest checksums and native record checks provide snapshot-specific evidence. No new selected family or independent full-stack acceptance pass is claimed.

```sh
python3 platform/scripts/test-searxng-encrypted-restore.py
# Preparation only, after verified export:
# runtime prepare-searxng-restore INVENTORY RECOVERED_DIRECTORY NEW_NAME
```

## Not yet done

Public metasearch, external-engine failure/rate-limit handling, production authentication/SSO, reviewed egress, real-domain HTTP-01/renewal, off-host/whole-stack recovery, indexing of authorized application data, Android and independent acceptance remain unfinished. Restart persistence alone is not backup restoration; the separately scoped recovery evidence above does not complete a full-release restore. This two-daemon unit was tested separately, not as a 53-daemon whole-fleet restart; no host reboot or crash watchdog is claimed.
