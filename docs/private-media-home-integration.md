# Private media, chores and virtual-home integration

Three additional acquired, immutable application images now run under the Kotlin private deployment runtime. These are internal-only component deployments, **not full-stack acceptance**. No existing host media, physical devices, host network or unrelated application data is mounted.

## Jellyfin

`JellyfinRuntime.kt` prepares `jellyfin-r4` with separate configuration, cache and media volumes. A journalled non-root initialization job generates a three-second, 440 Hz PCM WAV fixture using the image's bundled FFmpeg. It never downloads third-party media or mounts existing media. Initial XML configuration is copied into the application's writable configuration volume; the image root remains read-only.

```sh
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
$CLI runtime prepare-jellyfin platform/release/downloaded-candidate-inventory.json jellyfin-r4
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/jellyfin-r4.json
python3 platform/scripts/test-persistent-jellyfin.py
```

The API harness performs the native first-user wizard with a generated fixture credential, disables remote access/automatic port mapping, disables plugin repositories through the supported configuration API, creates a fixture-only music library, streams the actual audio under authentication and marks it as a favourite. After clean stop/restart it authenticates again and verifies the library/favourite plus byte-identical streaming.

Successful receipt: **`p0v3-jellyfin-50c44fa5db5a`**. Stream SHA-256: `b6c868771c6f4100a3d44384cf5e26fe039a574e9d5bc601da56f863b7cbdcb9`.

Real failures exposed and fixed:

- The wizard's `GET /Startup/User` must run before its update: that GET creates the initial user record.
- `/health` and `/System/Info/Public` can answer while Jellyfin's temporary startup HTTP server is transitioning to the real application. Readiness now uses `/Users/Public`; the restart journey verifies authenticated API access separately.
- Startup completion can have a library scan already running. The harness waits for it to settle, requests a new scan and waits for metadata extraction, rather than assuming an item listing means its tags are ready.
- First-start migrations can repopulate/re-enable the default plugin repository even when seed XML disables it. The harness explicitly disables it through the authenticated API and verifies it remains disabled after restart. All earlier attempts were confined to a no-egress internal network, so no plugin was acquired. **Preparation/apply alone does not complete wizard provisioning or prove this post-migration setting.**

Unsuccessful `jellyfin`, `jellyfin-r2` and `jellyfin-r3` deployments are stopped with diagnostic data retained. Only `jellyfin-r4` remains running.

## Donetick

`DonetickRuntime.kt` prepares the pinned Donetick binary with protected YAML/JWT configuration, persistent SQLite/local storage, raw password-reset URL logging disabled, and the hosted bridge disabled. Signup is enabled only for this internal fixture; this is not public owner onboarding or an SSO configuration. The pinned binary uses its built-in startup migrations; a version change is not permitted through idempotent `apply-private`.

Configuration was checked against `selfhosted.yaml.example` and `config.go` in the actual image. API shape was checked against that running image's Swagger schema and frontend client, rather than assuming older upstream examples match it.

```sh
$CLI runtime prepare-donetick platform/release/downloaded-candidate-inventory.json
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/donetick.json
python3 platform/scripts/test-persistent-donetick.py
```

Successful receipt **`p0v3-donetick-125f9e70480d`** proves local account signup/login, chore creation, completion with notes, and completion-history readback after clean stop/restart. The actual create route is `/api/v1/chores/`; the probe uses it directly instead of following an authentication-bearing redirect. Notifications are disabled for the generated chores, and external transport is unavailable on the internal network.

## Home Assistant

`HomeAssistantRuntime.kt` runs the pinned Python application directly as UID 1000, without its root-oriented image init wrapper. A journalled one-shot copies configuration into a private volume. Only explicitly selected local components are configured; `default_config`, hardware discovery and cloud integrations are not enabled. The latitude/longitude of zero and UTC are **synthetic fixture settings**, not inferred details of the owner's home.

The configuration defines two virtual `input_boolean` entities and a real automation: turning on `private_probe` causes `private_result` to turn on.

```sh
$CLI runtime prepare-homeassistant platform/release/downloaded-candidate-inventory.json homeassistant-r2
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/homeassistant-r2.json
python3 platform/scripts/test-persistent-homeassistant.py
```

Successful receipt **`p0v3-homeassistant-0e63c35fabec`** proves native onboarding, unauthenticated API denial, native password login-flow/code exchange, actual automation execution and restored virtual-entity states after clean stop/restart. It does not touch physical devices.

The first readiness probe used `/`, which correctly redirected to onboarding and was therefore rejected by the no-redirect health client. The replacement recipe checks `/manifest.json`. The runtime now permits safe filename dots in readiness paths while continuing to reject dot-segment traversal, query strings and encoded path tricks, with unit regression coverage. The application journey separately waits for Home Assistant's authenticated `RUNNING` state; a served frontend manifest does not prove all integrations have initialized. The original `homeassistant` deployment is stopped and retained.

## Limits

All receipts are private under `/mnt/media/p0-v3/image-acquisition-receipts/`. These three new applications have **not** passed encrypted backup/restore, browser or Android journeys. Their fixture credentials are not human owner onboarding, and the API probes are not independently reviewed release approvals. Reboot supervision, public HTTPS, all-product SSO, generic transactional updates/backups and the remaining product families are still unfinished. **Full-stack clean install/restore acceptance remains 0/2.**
