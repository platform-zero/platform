# RSS v1 content, live polling and guarded delivery transport

`src/main/resources/rss-packs/v1/` contains byte-for-byte copies of the nine archived `feeds.d/*.json` content packs from `/home/gerald/huly-oidc-20260923/stack.config/mastodon-rss/feeds.d/`. The archived directory was read only. `manifest.json` pins individual SHA-256 hashes and declares **pending-independent-content-review**: copying content is not editorial, rights, security or account approval. 47 feeds have distinct bot account names; analysis and state-media packs are retained, not silently omitted. No archived deployment scripts were copied.

`RssPacks.load()` verifies all nine hashes and feed/account uniqueness. The independently implemented `RssPublisher` is a pure draft/checkpoint state machine: first fetch never backfills, staging never drafts and checkpoints observed items, restore never changes state or drafts, subsequent active polls can only produce attributed drafts **if** the pack manifest is independently changed to reviewed. Acknowledged drafts dedupe after serialized-state reload. Publication now additionally requires the installed release-bound schedule authority; `reviewStatus` remains pending and production drafts are suppressed. Test-only injected review exercises the later-item behavior without network effects. Read-only native pack qualification can preview attribution without attaching any sender or approving publication.

`RssStateStore` persists first-poll checkpoints, pending drafts and single-send claims with checksums, fsynced atomic replacement, a retained previous image and lock-file serialization. It refuses state reset on reinstall, corrupt state and linked state roots. The worker fsyncs a claim **before** HTTP. A crash or ambiguous response after claiming requires reconciliation; it never automatically retries that POST, even within one hour. Other posts for the affected feed pause until the claimed item is reconciled. Mastodon's [status API](https://docs.joinmastodon.org/methods/statuses/#create) says keys are retained **for up to one hour**, not a guaranteed retry window. Old unclaimed pending work also remains held for review after one hour. Existing state files remain readable because the new nullable claim field defaults to absent.

## Implemented transport and worker

`RssTransport.kt` implements bounded HTTPS responses, secure RSS 2.0/RSS 1.0 RDF/Atom parsing, bounded gzip decompression, a maximum of three validated redirects, per-account private token loading, bot-account verification, attributed Mastodon POSTs with stable idempotency keys, and response-account/status-ID verification before acknowledgement. XML DTDs, external entities, schemas and XInclude are disabled. Cross-host redirects are denied except the observed NPR move to `feeds.npr.org`; same-host HTTPS redirects retain the port. Long titles are code-point-truncated to a conservative 500-character status limit without truncating attribution or the article URL. Exception reports expose feed IDs and exception types, not credentials or response bodies.

Rest of World's published feed includes unescaped ampersands in thumbnail URL attributes. A narrowly scoped adapter for that feed escapes bare ampersands while preserving existing entities, CDATA and comments; it still goes through the same secure XML parser. Archived feed-pack bytes and URLs are not changed.

CLI (from the workspace root after `installDist`):

```sh
platform/build/install/p0-v3-platform/bin/p0-v3-platform rss initialize /mnt/media/p0-v3/rss-staging-state
platform/build/install/p0-v3-platform/bin/p0-v3-platform rss poll staging /mnt/media/p0-v3/rss-staging-state
platform/build/install/p0-v3-platform/bin/p0-v3-platform rss poll restoring /mnt/media/p0-v3/rss-staging-state
```

Initialization is once-only and refuses existing state. Restoring performs no network requests. The former ambient `rss poll active` path is rejected: possession of tokens, a caller-selected gate and editorial review cannot authorize publication. Private Mastodon provisions and verifies all 47 per-feed bot tokens; no worker has been activated in this implementation phase.

## Installed scheduling and explicit reconciliation source

`RssSchedule.kt` implements immutable enrollment, pinned controller service/timer rendering, release activation, permanent suspension, serialized ticks and explicit uncertain-send reconciliation. `scripts/install-rss-schedule.py <schedule-root> <binding-sha256> [--enable-timer]` installs the two units using the existing owned supervision helpers. It never initializes checkpoints, releases publication authority, or runs a poll. Enabling a timer is not public activation. These runtime operations have **not** been executed.

The private `RssScheduleBinding` includes the exact deployment binding, transaction journal, original state and per-account token directories, HTTPS Mastodon origin, controller tree digest, candidate artifact-closure path/digest, non-root owner UID and a bounded 300–86400-second interval (default 900). Enrollment refuses existing schedule roots and requires an already initialized, readable original state directory. It does not migrate/reset the historical 46-checkpoint state.

CLI registration is via `RssScheduleCommands`:

```text
rss schedule-enroll <new-schedule-root> <private-binding.json>
rss schedule-units <schedule-root> <binding-sha256>
rss schedule-tick <schedule-root> <binding-sha256>
rss schedule-pause <schedule-root> <binding-sha256>
rss reconcile <schedule-root> <binding-sha256> <state-checksum> <feed-id> <item-id> <remote-status-id>
```

There is deliberately no release/enable-publication CLI. The release controller invokes `RssSchedule.release` only with an exact ACTIVATION_STARTED journal and matching durably consumed Acceptance permit. Ticks require COMMITTED, the identical deployment/permit/claim prefix, candidate-pinned controller/images, a currently running original (not recovered) generation and an exact activated host. Authority is reobserved before each feed/claim and immediately before POST, after bot identity verification. Independent content approval is still mandatory. Shared schedule locking ensures `pause` waits out any in-flight tick and prevents later sends; suspension is permanent for that enrollment, not a timeout-driven resume mechanism. A new qualified release is required to reopen publication.

Each timer invocation polls only current feeds; missed ticks never replay in a burst. Failed fetches do not advance checkpoints. Durable attempted claims block the affected feed in **all** modes, including staging; staging cannot silently acknowledge an uncertain post. A crash, timeout, malformed response or interrupted send retains uncertainty. Explicit reconciliation verifies the original author-owned remote status/source under the exact state checksum; a 404 or mismatch never clears a claim or authorizes retry. No schedule or reconciliation has touched the unresolved Washington Post checkpoint.

## Native pack adapter source (not executed evidence)

`acceptance/runners/rss-pack-analysis-native.py` serves all nine `rss-pack-*` native cases. It uses the pinned compiled `rss pack-observe install|restore <pack> <fixture-state> <original-feed-items.json>` command, actual feed parsing and attributed draft previews, read-only bot identity/zero-status checks, real invalid-bearer denial, and the compiled publication/restore gates. INSTALL creates a separate invocation-owned staging fixture, never the installed publisher state. RESTORE reads the original included fixture/checkpoint and original account IDs without fetching feeds or initializing state; it compares the independent source oracle exactly. The coordinated generation snapshot must include `rss-qualification/<original-invocation-id>/` and the scoped bot credentials. Missing fixtures, unresolved feeds, changed attribution or identity, or an unfenced restore fail rather than passing on a healthcheck.

Publisher/jobs native fault adapters still require a distinct owned synthetic feed/Mastodon harness for scheduled POST and lost-ack reconciliation. Real pending-review pack tokens must not be used to bypass production activation during qualification. The read-only pack adapter does not claim those missing semantics. All new source remains runtime-unverified; unit execution is coordinator-owned.

## Actual live polling

The real Kotlin CLI has polled all 47 original feed URLs. After fixing RDF, gzip, redirects and the malformed thumbnail attributes, **46 feeds successfully checkpointed**; the latest poll observed **1,297 articles**, sent **zero posts**, and retained an empty outbox. Washington Post's original national-feed URL times out with the JVM HTTPS client; that failure is reported and does not advance its checkpoint. Its account and pack remain present. The program exits nonzero when any feed fails rather than calling a partial poll successful. State is retained at `/mnt/media/p0-v3/rss-staging-state` for restart/reinstall testing.

The actual compiled Mastodon transport now passes **read-only identity verification against all 47 native private bot accounts**. `rss verify-accounts <https-origin> <private-token-directory>` checks identities without enabling publication. The native integration also checks scoped access, zero feed statuses, unchanged pack/checkpoint bytes, private-CA rejection and the real sender's pre-HTTP publication gate; see [private social integration](private-social-integration.md). Native synthetic direct-message posting/streaming/idempotency is separately tested with interactive fixture accounts, not the RSS bots. No reviewed RSS POST or public posting acceptance is claimed. [Coordinated encrypted social/RSS recovery](private-social-integration.md#coordinated-encrypted-recovery) now restores PostgreSQL, stopped Valkey, media, keys, all 47 bot credentials and the actual 46-checkpoint/zero-pending state in isolation. Native state verification rejects reinstall reset and proves restoring mode has no fetch/send; duplicate checking leaves recovered bytes unchanged. Source checkpoints remain unchanged and restore targets are stopped. Off-host custody, independent feed approval and full-release recovery acceptance remain outstanding. Scheduling/publication/reconciliation now have source implementation as described above, but no installed/live validation or publication approval is implied. Full-stack attempts remain **0/2**.
