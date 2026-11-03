# Private Mastodon and RSS-account integration

Mastodon 4.7.4 is now a running private component, not a public social service or completed RSS publisher. The fleet reaches **26/39 selected families plus OpenBao, 45 daemons in 19 supervised deployments**. Full-stack clean-install/restore acceptance remains **0/2**.

## Deployment

`MastodonRuntime.kt` prepares `mastodon-r4` using acquired, immutable Mastodon and streaming images, separate PostgreSQL and authenticated persistent Valkey, and an Element-image nginx TLS frontend. Six daemons run on one internal-only network, without published ports, extra capabilities or writable image roots. Rails/Sidekiq/streaming use UID 991; nginx uses 101; database/cache use 999. AppArmor, resource limits, exact image/ownership/mount audits and durable initializer journals apply.

Five one-shots initialize PostgreSQL, the application role/database, native migrations/seeds, two synthetic interactive accounts, and the 47 selected RSS accounts. Rails uses native `tootctl` account creation; RSS profiles and narrowly scoped Doorkeeper tokens are provisioned through the application's native models in a Rails runner. Initialization is never silently replayed. Web and worker daemons do not mount the bootstrap credential volume.

- Private origin: `https://social:8443`; CA/hostname/exact certificate verification for API probes, narrowly pinned SPKI for Chromium.
- `LIMITED_FEDERATION_MODE=true`, no allowed remote domains, and an internal Podman network. No external federation, public routing, physical-device access or outward RSS posting.
- Native registrations are closed and verified through `/api/v2/instance`.
- Only `localhost.invalid` is allowlisted for the synthetic email-domain validation. SMTP points at loopback port 9; email delivery is not implemented or claimed.
- Real P-256 VAPID keys are generated; a unit test signs/verifies with the resulting key pair. No web-push subscription or external push delivery is exercised.
- Native `tini` supervises Puma and Sidekiq. Clean systemd restarts retain containers, PostgreSQL/Valkey data and all initialization records.

`mastodon` and `mastodon-r2` are retained stopped failed recipes: synthetic email MX validation initially failed, then Sidekiq rejected an absolute ready filename. The latter recipe also exposed direct-PID-1 Puma's non-clean shutdown. `mastodon-r3` passed native social journeys with the corrected readiness filename and native init supervisor; it is now stopped. No recipe or existing runtime input was silently replaced.

## Native browser and authorization evidence

`acceptance/scripts/MastodonBrowserProbe.java` and `scripts/test-private-mastodon.py` exercise:

1. Two fresh browser contexts, native email/password login and OAuth authorization-code/S256 PKCE.
2. Wrong verifier rejection, successful exchange and rejection of authorization-code replay.
3. Owner/read-only account identity verification; the read-only token cannot post.
4. A **direct**, synthetic mention of the local reader, with duplicate requests returning the same status ID under the same idempotency key.
5. Native authenticated WebSocket streaming delivery of the mention notification.
6. Reader API and actual browser readback; anonymous access to the direct status is denied.
7. Clean restart, unchanged initialization journal, fresh login and persisted browser readback.

These private mentions are not end-to-end encrypted. The synthetic `owner` is not the real owner; this does not prove Keycloak SSO or mandatory owner password-change/TOTP enrollment. No full social feature suite or Android acceptance is claimed. The separate coordinated recovery below now proves private database, media, cache, keys, bot-token and RSS-state recovery.

Receipts:

- `p0v3-social-e94abd22f397`: earlier r3 native flow and restart.
- `p0v3-social-e727005ece8b`: r4 native flow and restart; persisted screenshot inspected.
- `p0v3-social-af787db05e31`: actual pinned systemd restart, same containers/new start times and no initializer replay.
- `p0v3-social-373f48c39a77`: additionally verifies wrong PKCE verifier and authorization-code replay denial, before and after pinned systemd restart.
- **`p0v3-social-014078337962`**: final repeat with browser downloads explicitly disabled and the same complete native/systemd checks.

The unit is `p0v3-private-mastodon-r4.service`, using controller tree `e40d0426576cca7c68b6a137a51e212bd384b4acb15822eb57b97f16942dc113`. Existing units/controllers were not upgraded. This is boot/shutdown supervision, not a watchdog or host-reboot test.

## All nine RSS packs, still silent

The pinned selection produces **47 distinct native bot accounts**, preserving every account name, feed identity, display name, source URL and pack. Profiles are locked, not discoverable/indexable, and explicitly describe unofficial staging with publication disabled. Each bot has a separate `read:accounts write:statuses` token. Native admin access and profile mutation using these publisher tokens are denied.

The bootstrap volume retains credentials in mode-0600 files, not in container logs or web-mounted storage. Exported probe token files are protected under their private receipt directory. They are **not** installed into an active worker or schedule. These long-lived fixture tokens are not a production rotation/custody design.

`MastodonRssSender.verifyAccount` and `rss verify-accounts HTTPS_ORIGIN PRIVATE_TOKEN_DIRECTORY` provide a read-only native transport preflight, without opening the publication gate. `RssAccountProbe.java` uses the actual compiled `JdkRssHttp`, sender and CLI against all 47 accounts. System JVM trust rejects the private CA; process-scoped trust and a process-local hosts file permit verified HTTPS without host trust/DNS changes.

The integration checks all bots have zero statuses, exact source attribution, distinct native IDs and nine-pack membership. An empty status request reaches native validation but creates no post. Calling the real sender's `send` still fails with `RSS publication review pending` **before any HTTP request**. The probe never calls the internal review-bypassing test seam. Pack bytes and existing RSS checkpoints remain unchanged.

Receipts:

- `p0v3-social-rss-326ad56ce449`: first native accounts/transport/gate pass.
- `p0v3-social-rss-23ed9177a391`: repeated after systemd restart, same accounts/tokens and no feed posts.
- `p0v3-social-rss-fab25597a4e3`: explicit native registration closure, exact pack mapping and post-negative-test account readback.
- **`p0v3-social-rss-e78e72a8ef38`**: final repeat after the latest supervised restart; all 47 identities remain silent and unchanged.

The pre-existing live-feed result remains 46/47. The Washington Post feed is still unavailable; its selection/checkpoint was not replaced or advanced. Independent content review, real publication/reconciliation, scheduling, off-host custody and full-release recovery acceptance remain outstanding.

## Coordinated encrypted recovery

`MastodonRecovery.kt` and `runtime prepare-mastodon-restore` accept only the exact acquired-image source recipe, a different deployment name and protected recovered inputs. Repeated preparation refuses changed recovered bytes. PostgreSQL role/database initialization is allowed on the empty target; migrations, account creation and token generation are replaced with read-only restoration guards. Before application startup, recovered token identities must bind to all 47 configured accounts, feed IDs and packs, existing native users and the original restricted scopes. Valkey also refuses missing, incomplete or foreign-manifest completion markers.

`scripts/test-mastodon-encrypted-restore.py` performs a real coordinated operation:

1. Native source browser readback of an existing direct message and generated 128×128 PNG, including decoded pixels and stored-media SHA-256.
2. Disable source supervision, enter a durable source maintenance fence, prove normal startup denial, and stage only PostgreSQL. Hold the deployment lock and the actual RSS POSIX state lock during capture.
3. Capture a custom-format PostgreSQL dump, stopped Valkey AOF/data, uploads, private bootstrap credentials/token map, all configuration/keys, the source recipe, protected OAuth fixture and existing RSS state/checkpoints. Include a complete hash manifest inside the encrypted snapshot.
4. Create a Kopia encrypted repository, verify 100% of snapshot files, export to a private directory and compare the complete recovered inventory and hashes. Verify frozen process identities/start times and source state before releasing the fence and resuming supervision.
5. Restore into fresh private volumes under a target runtime lock, using `pg_restore --role=mastodon --exit-on-error`. Validate regular-file-only tar inventories and exact restored content/modes before completion markers. Test native denial of missing, incomplete and wrong-manifest cache markers without replaying application initializers.
6. Fresh native browser OAuth/PKCE and message/image readback, followed by new restored messages/media and a clean restart. Stored image SHA-256 remains `23518238062aa3f54b208802dd75de4a75dd79e018ec8d63abef6b4ca7d5adb0`.
7. Native authenticated Valkey readback of a pre-snapshot synthetic marker, post-snapshot exclusion and divergent source/restore writes surviving restarts. PostgreSQL-backed source-only messages are absent from the restore, and restored-only messages are absent from the source. Restore-to-live-source TCP is denied.
8. Verify all 47 recovered bot credentials through the actual publisher transport, retaining zero feed statuses and the publication gate. `RssRecoveryProbe.java` reads the actual restored checksum/state, rejects reinstall reset, proves restoring mode performs no fetch/send, and checks deduplication without changing the recovered state. A **separate fresh synthetic store** tests first-poll silence; it never replaces the restored or source checkpoints.
9. Leave the source enabled/active and stop the isolated target, retaining data and diagnostics.

The actual recovered state has **46 checkpoints and zero pending posts**; no live uncertain-send recovery is claimed. Source checkpoints and all nine packs remain unchanged. Private local snapshots/exports are not off-host custody, unattended schedules, SSO recovery or independently accepted full-stack restoration.

Receipts:

- `p0v3-social-d8773d529234`: source generated-media journey and pinned systemd restart.
- `p0v3-social-restore-145b5c477a6a`, snapshot `k9ab891f0f2013685af73ce2c5a4d145f`: initial coordinated recovery.
- `p0v3-social-restore-2b152cca9d4b`, snapshot `k7e5999cd3064d2b8741731d9c6e307e9`: additionally tests missing/incomplete/foreign markers and locked import.
- `p0v3-social-restore-cf2bc67d2868`, snapshot `kae6975e0d1c58cabf682cc3e14d2b78e`: additionally verifies native Valkey state and divergence.
- **`p0v3-social-restore-f8ce8a9c8659`**, snapshot **`k078df19d4a586965c5f5587198524542`**: final pass with exact feed/pack token binding and fail-closed probe receipts. Restored browser readback: `p0v3-social-d58ff5e976c7`; restored writes: `p0v3-social-e3fdacfe0cf9`; recovered bot verification: `p0v3-social-rss-a8068fa74508`.

### Retained failure and reporting correction

`p0v3-social-restore-243ec607f696` failed during a late fresh-login check after hitting native login throttling; its target is stopped and its failed receipt retained. Upstream limits were not changed or cleared. The browser now honors `X-RateLimit-Reset` for one login retry only when the delay is within ten minutes; it never automatically retries message/media writes.

That failure exposed an earlier sub-probe's `passed:true` being retained when a later browser check failed. Both social probe wrappers now use the unit-tested `probe_receipt.py` finalizer: exceptions/interruptions force failure, and persistence errors propagate. Original partial receipts `p0v3-social-ec8cf410fa40` and `p0v3-social-d8ad85f9d040` were **not rewritten**; each has a checksum-bound `receipt-invalidated.json` explicitly marking it failed. Readback/recovery requires a completed, non-invalidated fixture. None of these artifacts constitutes independent acceptance.

## Validation

Platform, Keykeeper and acceptance JVM checks pass, as do **23 Python unit tests** and Python compilation. Platform unit-only line coverage is **3036/3295 (92.14%)**; native integration probes are not included in that figure. Final audits verify all 19 units enabled/active, all 45 declared daemons running with the expected runtime security settings, and no active maintenance fences. OpenBao remains operational/unsealed; only Mastodon was restarted in these tests.

## Reproduction

From the workspace root, with the offline platform distribution built:

```sh
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
$CLI runtime prepare-mastodon platform/release/downloaded-candidate-inventory.json mastodon-r4
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/mastodon-r4.json
python3 platform/scripts/test-mastodon-rss-accounts.py
python3 platform/scripts/test-private-mastodon.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-social-e727005ece8b --supervised
```

For coordinated recovery, use the existing media-bearing fixture:

```sh
python3 platform/scripts/test-mastodon-encrypted-restore.py \
  --fixture /mnt/media/p0-v3/image-acquisition-receipts/p0v3-social-d8773d529234
```

A fresh media-bearing journey can be created with `test-private-mastodon.py --with-media --supervised`; this registers new OAuth applications and remains subject to upstream rate limits. `--verify-fixture` performs readback rather than creating another message; cross-deployment use requires `--recovered-inputs` and exact Kotlin recovery-recipe/input validation.

Use `--supervised` only after the pinned unit is installed/enabled. Reuse the protected fixture to avoid repeatedly registering OAuth applications; upstream registration/login rate limits remain intact. Do not print fixture inputs, bootstrap files or token files. All three effectful social Python probes reject optimized execution. A service restart and these implementation-authored probes do not count as an independent full-stack acceptance cycle.
