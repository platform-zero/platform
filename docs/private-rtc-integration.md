# Private LiveKit SFU: actual encrypted media and isolated configuration recovery

**Component evidence only. Full-stack acceptance remains 0/2.** LiveKit is now the 25th provisionally covered logical family. Seventeen private deployments run 38 daemons; this is not a complete 39-family release.

## Runtime

`LiveKitRuntime.kt` prepares `livekit`: the acquired LiveKit **1.13.11** image plus a private nginx TLS frontend using the already-acquired Element image's nginx binary. No upstream entrypoint or automatic downloader runs. Both daemons are non-root, capability-free, read-only-root, AppArmor-confined, memory/PID bounded and on a dedicated internal Podman network with **no published ports**.

- Protected generated API key/signing secret; development mode disabled.
- Automatic room creation disabled. The control plane must explicitly create rooms.
- Bounded participant count and UDP range 50000–50020; private ICE/TCP 7881 and signaling 7880.
- No external address discovery, TURN, configured webhooks or recording. No public NAT/TURN functionality is claimed.
- `https://rtc:8443` provides verified private TLS and WebSocket proxying. HTTP 8080 exposes only health; application paths return 404.
- `PrivateWebPki` produces a per-deployment CA/hostname certificate; no shared trust-store changes. Issuing key discarded, 365-day validity, renewal still unimplemented.
- Rooms, participants and active calls are deliberately **ephemeral**; no fictitious volume or persistence marker is added.

## Browser evidence, including client-side media E2EE

`acceptance/scripts/LiveKitBrowserProbe.java` uses the actual upstream LiveKit JS SDK **2.15.6**, its actual E2EE worker and native Chromium peer connections in two isolated browser contexts. This is an SDK transport fixture, **not the Element Call UI**.

The flow creates scoped, short-lived fixture JWTs through the private test controller. It does not implement a production identity/token issuer.

1. Native RoomService rejects an invalid/expired token and rejects participant attempts to create/delete rooms.
2. A correctly signed sender and subscription-only receiver join a private room. Invalid-signature browser admission is rejected.
3. The sender publishes a canvas video track and a generated 440 Hz Web Audio tone. No microphone/camera capture occurs; receiver playback is silenced.
4. Both peers use the SDK's native `ExternalE2EEKeyProvider` and worker. Initially the authorized receiver has a **wrong media key**: RTP bytes arrive for audio/video, but no video frames decode, video dimensions remain zero and decoded audio stays silent.
5. Supplying the correct key to the receiver's native key provider enables decoding without replacing either peer connection. The test observes red pixels followed by blue pixels from the remote decoded video—not a copied sender canvas or synthetic receiver result.
6. A receiver-side Web Audio analyser measures a nonzero tone around 430.66 Hz (the FFT bin nearest 440 Hz), and actual RTP audio bytes/video frame counts are positive. The source run measured RMS about 0.176.
7. Native selected ICE candidates are checked against the actual private SFU address and DTLS reports connected. The SDK's peer connections are wrapped only to force `iceServers:[]`, prohibiting public STUN/TURN use; transport/stats are still native Chromium.
8. Reliable data delivery and disconnect/participant removal succeed. **The data-channel fixture is transport-encrypted, not claimed as application-level E2EE.**
9. The complete flow repeats after a clean service restart with a new explicitly created room.

Chrome's `totalAudioEnergy` stat stayed zero even when decoded audio was demonstrably present. It is retained honestly in receipts, not fabricated or used as proof. The test requires native inbound audio bytes **and actual decoded sample RMS/frequency**. Chrome needed a real attached audio element to activate remote audio decoding; its volume is zero, and the analyser's output path also uses zero gain.

The upstream browser artifacts are pinned by archive SHA-512 and individual SHA-256, not a moving URL:

- UMD: `71ede404c69bf43c94bf158d979a796a2b546fc8c18256634e75a741b486435f`
- E2EE worker: `6c1aa2363ceb3a7720700c47ebc8d6716ed6ea696306e7a7e0ea24e35b4902fa`

`acquire-livekit-browser-sdk.py` retrieves the fixed npm 2.15.6 archive, checks both artifacts before writing, extracts only exact regular-file members without filesystem extraction, and refuses changed caches, duplicates, symlinks or unexpected redirects. No browser downloads or runtime network dependency resolution are allowed.

## Encrypted recovery

`LiveKitRuntime.prepareRestore` accepts only the exact supported acquired-image recipe, a different target name and protected recovered inputs. It never regenerates recovered keys and rejects changed inputs on repeated preparation.

`test-livekit-encrypted-restore.py`:

- Audits the pinned source unit/manifest, disables/stops only that source unit and holds its deployment lock.
- Captures all configuration/TLS/API-key inputs and the source manifest, with an encrypted hash inventory.
- Creates a fresh encrypted Kopia repository, verifies 100% of files and exports into an empty protected directory.
- Checks the exact exported file set/hashes, frozen source identities/start times and unchanged inputs; resumes the original enabled/active unit.
- Prepares a separate target from recovered bytes; performs real browser E2EE audio/video, wrong-key denial, API authorization and restart checks there.
- Creates source-only and target-only rooms to prove independent state. Confirms target→source TCP denial while source endpoints are live.
- Stops the restored target, retaining its data/diagnostics and encrypted repository.

This recovers **server API credentials, TLS keys and configuration**. It does not back up active calls, client media keys, recordings or Matrix conversation state. Recovered media tests use fresh client media keys. Repositories/exports are local, not off-host backups; protected plaintext exports remain for diagnostics.

## Receipts

Under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-rtc-a453657b1cf4` — initial real media, DTLS, authorization and restart; predates client media E2EE checks.
- `p0v3-rtc-e1463758e8c4` — source client media E2EE and wrong-key rejection, before/after restart.
- **`p0v3-rtc-634d66142bb1`** — final source rerun, with probe/harness hashes and explicit wrong-key RTP counters: over 42 KB received but zero decoded frames, followed by successful video/tone decoding with the correct key.
- `p0v3-rtc-restore-f463e9278c1d` — first encrypted configuration recovery, snapshot `kb160e9821b731b5488211364e58e40dd`; predates E2EE recovery checks.
- **`p0v3-rtc-restore-002050ae7203`** — encrypted recovery plus native E2EE media, snapshot `k128b5c13bff18da02412595603630d10`; restored browser receipt **`p0v3-rtc-ee50737743de`**.
- **`p0v3-boot-1c4edea42fa6`** — all seventeen units/38 daemons restarted, same container IDs and unchanged initialization journals, six pinned controller versions. Host not rebooted.

The restored received-video screenshot was visually inspected. Both `rrestore-*` targets are stopped. Earlier failed browser receipts are retained; no initializer replay or credential reset was needed.

## Reproduce

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
platform/build/install/p0-v3-platform/bin/p0-v3-platform runtime prepare-livekit \
  platform/release/downloaded-candidate-inventory.json
python3 platform/scripts/acquire-livekit-browser-sdk.py
python3 platform/scripts/test-private-livekit.py
python3 platform/scripts/test-livekit-encrypted-restore.py
```

`p0v3-private-livekit.service` pins controller tree `8215f29fc90871ab003b9f47bfa54aa7c934c788a6d6fb6a715f74b3ea4315ef`. Existing units were not upgraded silently. Kotlin recovery and SDK acquisition have unit tests; operational browser/restore results do not contribute to unit coverage.

## Still missing

Matrix OpenID/RTC authorizer integration, MAS/SSO, Element Call, production client media-key distribution, Android calls, public Caddy HTTPS, NAT/TURN, abuse/rate controls, production key/certificate rotation, off-host recovery and independent full-stack acceptance remain unfinished. This fixture must not be presented as a complete Matrix calling deployment.
