# Private native mail component — not public delivery

The active **`mail-r9`** deployment runs native Stalwart 1.0.1 as UID/GID 2000, with one persistent RocksDB volume, one completed guarded initializer and one serving daemon. There are no published ports, runtime capabilities, host inboxes or public delivery routes. All identities and messages are synthetic. This adds private component coverage for the mailserver family: **38/39 families**, not a complete release; independent full-stack acceptance remains **0/2**.

## Evidence

- Manifest SHA256: `9a22aab7e1c4b131b4cc23bf46c46e386c24233f9fc70c4c1fa0ca6bbab379d8`.
- Direct creation/persistence pass: `p0v3-mail-74104b5f6019`.
- Strengthened supervised repeat: **`p0v3-mail-dd5abc459248`**.
- Immutable controller: `b5733a68081703cfe0fe57c6c2b0bc5fc32f97a04e0be3183ce46a63c5ed96ae`.
- Offline derived-image/native-byte verification: `p0v3-mail-build-6f1e3d2ba6f0`.
- Read-only fleet census: `p0v3-fleet-f3a1cc8cbd94`, **32 enabled/active units, 104 running declared daemons**. This is not a fleet restart, host reboot or application-availability check.

Protected evidence lives under `/mnt/media/p0-v3/image-acquisition-receipts/`. The probe proves native authenticated SMTP submission, native IMAP subject search and exact Message-ID/body/binary-attachment readback, unchanged UID/UIDVALIDITY/full stored-message hash across a real stop/start, unchanged container ID and changed start time, unchanged inputs and initializer ledger. Alice and the outsider cannot find Bob's received message in their own inboxes. Alice's password cannot authenticate as Bob. Anonymous submission, wrong SMTP password, forged authenticated envelope sender, external relay, retired recovery-admin authentication and ordinary-user management API access are rejected. All three listeners verify the exact private leaf/CA; default trust and wrong-hostname verification fail. Serving logs contain no resource-download activity.

Safe read-only/restart repeat:

```sh
python3 platform/scripts/test-private-mail.py --name mail-r9 --supervised
```

**Never repeat `--create` or remove any send intent.** `/mnt/media/p0-v3/mail-probe-state/<manifest>.json` binds the fixture to the immutable manifest. Adjacent `.message`, `.send-intent` and `.send-outcome` records retain the exact submitted bytes, hash and SMTP acceptance. Creation uses exclusive, fsynced files; missing acknowledgement requires reconciliation, not SMTP replay. Repeats require the accepted outcome and exact intent/body binding.

## Runtime and provisioning

`MailRuntime.kt`, `runtime/mail-bootstrap.py`, and `runtime prepare-mail` implement the recipe. SMTP 2465, IMAP 2993 and HTTP 8443 use implicit TLS on the dedicated internal network. The fixture domain `p0v3.example.org` is under the reserved example domain; no DNS records or public routes were changed. There is only a local delivery route/queue/schedule. SMTP authentication and sender matching are required; relaying is disabled. Fixture users have explicitly replaced permissions, no management privileges, and 32 MiB/100-message quotas.

The native executable is byte-identical to the acquired official image. Its file capability prevented execution with dropped capabilities. The offline recipe copies/compares/moves the binary to remove the xattr instead of granting runtime privilege. The serving image is `localhost/p0v3-mail-server@sha256:418138750a79ff8a41c33f6aa9bd3513c8986e4926423cbb9449ff34ba8ccad1`; the Python/OpenSSL bootstrap image is `localhost/p0v3-mail-bootstrap@sha256:4bf167ae8a50da33fd8981247deda2195cf3cb835ecddfbb0a983ce74d8cff9c`. The original upstream and Docker Mailserver acquisition records remain unchanged.

Initialization requires PID 1, a fresh store and an exclusive intent. Native recovery API changes are individually recorded before each write; failures retain state and are never replayed. Passwords are generated fixtures, hashed using SHA-512 crypt; the serving daemon receives neither bootstrap credentials nor plaintext user input files. Readiness requires the native store and exact generation marker. Normal serving has no recovery environment/admin. Shutdown must succeed before the ready marker is written.

### Native default-resource traps

Stalwart's recovery startup inserts a built-in WebUI application before its API is available. Creating a different disabled application does **not** disable it. Both runtime environments now force HTTP(S) through a closed loopback proxy, with exceptions only for the local/private service. The initializer discovers and validates the exact built-in application, then disables that object before serving. A bootstrap download attempt is thus refused locally; this is not a claim that the native binary never attempts a fetch. The dedicated internal network remains a second boundary. No WebUI, spam-rule or ASN/Geo download is authorized.

Updating the synthesized `Asn/Disabled` singleton is a native no-op: it does not persist an object, so normal startup later inserts download-enabled defaults. The recipe instead creates the disabled singleton explicitly. Spam rule updates are disabled with a persisted null rules URL. Native source inspection at tag `v1.0.1` established these behaviors (`common/src/manager/defaults.rs`, `services/src/lib.rs`, `jmap/src/registry/set.rs`). The source archive checksum is retained with the build receipt. Serving-log checks are evidence for the observed run, not a general packet-capture proof.

## Retained failures and uncertainty

- `mail-r1`: native binary execution failed with `Operation not permitted`; file capability removed without changing binary bytes or granting capabilities.
- `mail-r2`: native domain validation rejected `localhost.invalid`; a fresh revision uses the reserved example-domain namespace.
- `mail-r3`: native listener creation required `name`, despite documentation describing it as read-only.
- `mail-r4`: SMTP accepted a fixture but the Message-ID search timed out. The accepted send record remains; no resend. This candidate is stopped and maintenance-fenced.
- `mail-r5`: tracer variant is `Stdout`, not the display label `Console`.
- `mail-r6`: delivery expiration uses the native defaults, not the invalid `ttl` property.
- `mail-r7`: ingestion was confirmed in native logs, but Message-ID search still timed out. Logs also exposed blocked WebUI/ASN download attempts. It is stopped and maintenance-fenced; never silently release it.
- `mail-r8`: resource controls were corrected. Exact Message-ID HEADER searches still failed with and without angle brackets. Native subject search finds the message, and exact fetched headers/content are checked independently. Read-only repeat passed as `p0v3-mail-dfdead55836f`; no resend occurred. This revision is now stopped.
- A helper unit test found `InterruptedError` was caught as `OSError` during readiness. The initializer now propagates interruption immediately; the fix is deployed in fresh `mail-r9`, not written over earlier inputs.

Failed initializer volumes, manifests, native logs and action records remain intact. Original Huly r8/r9 and JupyterHub r7 fences are also unchanged. The Message-ID HEADER-search discrepancy remains an explicit compatibility limitation; no general IMAP conformance claim is made.

## Separate SOGo integration

The standalone fixture above is unchanged. A fresh [SOGo/mail composite](private-sogo-mail-integration.md) now proves actual SOGo SMTP delivery, IMAP/browser and Sent-copy persistence, cross-user/native SOPE transport denials, calendar/contact journeys and five-daemon supervised restart. Its [coordinated encrypted recovery](private-sogo-mail-recovery.md) now also passes restored mail/calendar/contact/browser journeys, exact attachment bytes, native denials, restart and write isolation. It is a separate recovery scope, not an in-place migration or recovery of `mail-r9`.

Supplementary recovery testing found indexed subject search returning both the direct-mail and SOGo fixture subjects. The backend probe now bounds candidate count and requires exactly one exact Subject/Message-ID identity before reading the payload. Duplicate identities fail closed; this is not a claim of RFC phrase-search or general IMAP conformance. The failed probe and hash-bound read-only reconciliation are preserved in the recovery evidence.

## Tests and remaining scope

`MailRuntimeTest.kt` checks the native recipe, scoped permissions, local-only routing, resource controls and immutable input contract. Fifteen helper unit tests cover completion, refusal/replay guards, rejection/incomplete acknowledgement, interruption, timeout, forced shutdown, API bounds/correlation, unexpected built-ins and optimized-Python refusal. `python3 platform/scripts/check-mail-unit-coverage.py` reports **108/109 executable lines (99.08%), unit only**. The full Python suite now has 107 passing tests; platform JVM checks and its >=90% unit-only line gate pass.

**Not covered by this standalone receipt:** SOGo SMTP/IMAP/browser wiring (now separately tested in the composite; existing `sogo-r2` still has mail disabled), owner enrollment/TOTP/application passwords, public DNS/MX/SPF/DKIM/DMARC, spam/abuse operations, aliases/delegation, general IMAP conformance, mobile/Android clients, native WebUI, coordinated encrypted mailbox/configuration recovery, migration/rollback, public TLS or full-stack acceptance. TLS is not message E2EE. Reviewed deployed RSS publication remains the remaining uncovered family; its publication gate is unchanged. Worklane and whole-release orchestration/recovery are still unfinished.
