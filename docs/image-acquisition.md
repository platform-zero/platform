# Actual candidate acquisition and private integration evidence

The full-stack deployment is still incomplete. This document records **executed work**, not an accepted release.

## Downloaded artifacts

55 upstream candidate images were downloaded into the dedicated rootful Podman 5.4.2 store:

- graph: `/mnt/media/p0-v3/release-runtime/graph`
- run: `/run/p0-v3-release-runtime/store`
- network definitions: `/mnt/media/p0-v3/release-runtime/network-config`
- private acquisition receipts: `/mnt/media/p0-v3/image-acquisition-receipts/`

`release/downloaded-candidate-inventory.json` records their immutable selected manifest references, image IDs, architecture, discovery tags and sources. These are **candidate** selections; downloading and checking image identity does not attest cross-product compatibility, upstream signatures, security audit, native OIDC behavior or full product functionality. SOGo is a third-party source-built image, not an official upstream container. Its [private native calendar/contact integration](private-sogo-integration.md) now passes browser/API authorization and supervised persistence; mail remains unavailable. Huly v0.7.426's current upstream compose selects Silo object storage rather than the old MinIO process. Its [private native integration](private-huly-integration.md) now passes issue/description, indexing, outsider denial and supervised persistence; coordinated recovery, migration and production-security review remain unfinished. Valkey 7.2.15 is deliberately selected for the Redis 7.2 compatibility target rather than blindly using newest 9.x.

The lists `release/*candidates.json` and `release/candidate-images.json` are acquisition inputs, not deployment files. `scripts/acquire-candidate-images.py` checks the dedicated store, pulls explicit version tags for discovery and records content-addressed identities. Deployment must use `pinnedImage`/a reviewed release lock, never discovery tags. Rerunning acquisition refuses to replace a receipt when the same tag changes image ID.

The Kotlin CLI now implements `images stage <downloaded-candidate-inventory.json>` through `ImageStaging.kt`. It validates the entire inventory before side effects, checks the dedicated graph/run roots, inspects cached selected-platform digests, pulls missing artifacts only by digest, and verifies image IDs, manifest digests, OS and architecture. Its earlier real execution verified all 54 candidates. A subsequent pinned RabbitMQ 4.2.9 support candidate brings the acquisition inventory to 55; a subsequent real `images stage` verified all 55 content-addressed images. RabbitMQ was used only in a retained unsuccessful office recipe and is not required by the corrected CE memory-first runtime. The [office runtime](private-office-integration.md) separately uses an offline, digest-pinned derived image with native fonts/themes/API assets generated once; build receipt `p0v3-office-build-4bc54d566526` binds that artifact and its source Containerfile, without claiming a signed release. It does not start services, accept compatibility or replace signed release validation.

Redpanda's `docker.redpanda.com` pull failed with an unauthenticated rate-limit error. Pulling the same `redpandadata/redpanda:v24.3.6` version from Docker Hub succeeded; both the failure and change are intentional, not a silent success claim.

A Keykeeper runtime was built from a pinned Temurin 21.0.13 JRE base and `keykeeper/build/install/p0-v3-keykeeper`, with UID/GID 65532 and no build-network access. Manifest digest: `sha256:0249aeb5dcb06396499b7b73a502fb741ee8a8b764b52c56be76c0de32d2c309`. Starting it without required configuration correctly failed; this is a packaged runtime, **not** a working public Keykeeper deployment. Rebuilding source changes the manifest identity.

## Additional mail-family candidate

The main inventory still contains its original 55 entries, including the retained Docker Mailserver candidate. `release/mail-native-candidate.json` separately acquires the official Stalwart 1.0.1 candidate as `mail-stalwart`; it does not replace an inventory entry or a signed release selection. The private mailserver family now has native Stalwart component evidence, while public/production selection and whole-release compatibility remain unaccepted.

Selected digest: `ghcr.io/stalwartlabs/stalwart@sha256:103bf1f76d4ed27ada7eae1744236bb3c01c2a0bda97303baa59a2e5bf18623d`; image ID `b4d02342a10b348cb3102bf172fc81cdb9cfc550e435b80f13ff1762c0c8137e`. Receipts are under `/mnt/media/p0-v3/image-acquisition-receipts/mail-native-candidate/`. The official image declares the non-root `stalwart` account (UID/GID 2000). Acquisition/inspection alone is not compatibility evidence. The separate [private mail integration](private-mail-integration.md) now records actual SMTP/IMAP persistence and denials for `mail-r9`, without public delivery or SOGo wiring. Offline build receipt `p0v3-mail-build-6f1e3d2ba6f0` verifies the original and both derived images contain byte-identical native executables. `images/mail-bootstrap/Containerfile` removes the file capability by copy/compare/move, rather than granting a runtime capability. Serving digest: `localhost/p0v3-mail-server@sha256:418138750a79ff8a41c33f6aa9bd3513c8986e4926423cbb9449ff34ba8ccad1`. Bootstrap digest: `localhost/p0v3-mail-bootstrap@sha256:4bf167ae8a50da33fd8981247deda2195cf3cb835ecddfbb0a983ce74d8cff9c`. This does not authorize runtime WebUI/rule/ASN downloads; the integration documents blocked early-candidate attempts and corrected controls.

Stalwart 1.0 uses a different data-store/configuration API from 0.16; implementation must use its actual versioned native interfaces, not old TOML examples. Its documented bootstrap/recovery listener binds all interfaces and has permissive CORS; bootstrap must remain isolated and temporary. Automatic WebUI/rule downloads, public delivery and privileged runtime shortcuts are not approved by acquiring this candidate. See the upstream [configuration](https://stalw.art/docs/configuration/) and [bootstrap](https://stalw.art/docs/configuration/bootstrap-mode/) documentation.

## Actual Caddy execution

The downloaded Caddy 2.11.7 image failed to execute with all capabilities dropped: its executable's file capability requires `NET_BIND_SERVICE` in the bounding set. Adding only that capability while retaining UID 65532, no-new-privileges and the other dropped capabilities fixed execution. The lock and Quadlet renderer now support that Caddy-only exception; broad capabilities remain rejected. The later Huly-specific derivative retains the exact executable bytes but removes the file-capability xattr, and runs with an empty bounding set. Its derived Elasticsearch/plugin, unchanged KVS/Node bridge and Caddy image identities and build receipts are recorded in [Huly evidence](private-huly-integration.md); older pinned deployments were not silently changed.

The actual image successfully ran `caddy adapt` on the staging HTTP-01 configuration with `--network=none`, read-only root and no published ports. Output is retained privately as `caddy-adapt-output.json`. No certificate was requested and no public listener was opened.

## Executed Caddy → ntfy → encrypted Kopia → isolated ntfy restore

`scripts/test-private-ingress.py` uses the acquired digest images, a uniquely named internal network and newly created named volumes. It publishes a message **through real Caddy to real ntfy**, stops ntfy to make SQLite consistent, snapshots its cache through a real encrypted Kopia filesystem repository, verifies all snapshot files, restores to a separate fresh volume, starts a separate ntfy/Caddy pair and verifies both the original message and a new restored-only message. It confirms that the restored-only message is absent from the source instance.

The first bare stopped-cache copy roundtrip passed. The subsequent encrypted Kopia extension initially failed twice because restoring directly to the mounted root attempted to create a placeholder outside the writable mount. Restoring to `/restore/data` and pointing the restored ntfy cache there fixed it. Successful encrypted attempts: `p0v3-ingress-b5e9ef393336` (snapshot object `k23d31561889168de814c1f324e04726f`) and the subsequent exact selected-platform-digest run `p0v3-ingress-5368bd1dae41` (snapshot object `k2b9c0df16cbbabe9a6a7ec67c8610c9a`). Private receipts record failures as `passed:false`; failed artifacts were retained rather than erased.

Containers and the uniquely named test network are removed after each run. Source/restored volumes, encrypted repository, repository config and mode-0600 recovery-password file are retained for diagnosis/recovery. No public ports, remote posts, production data or shared Podman store are involved.

**This is three-product private component evidence. It counts as neither of the two required full-stack clean installs. Full-stack acceptance remains 0/2.**

## Executed Keycloak → PostgreSQL → encrypted Kopia → separate-network identity restore

See [private identity integration](private-identity-integration.md). The optimized Keycloak 26.8.1 image and PostgreSQL 17.11 now pass real HTTP-form onboarding, mandatory password reset/TOTP, PKCE exchange, and login after encrypted logical-dump restoration into a fresh database and a separately networked Keycloak. The optional `--chromium` journey now also passes real rendered-browser onboarding and restored login. This is still not Android, public HTTPS or full-stack acceptance.

## Continue implementation without waiting for an operator-authored lock

Next work is compatibility verification and actual product configurations using these artifacts, local service builds (RSS and Keykeeper integration), Worklane's separate human-lane runtime, database/identity wiring, real release lifecycle and all-product acceptance. Missing public activation inputs do not block any of that engineering. Do not ask the operator to perform upstream selection, image acquisition or software implementation.
