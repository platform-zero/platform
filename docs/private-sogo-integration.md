# Private SOGo: native calendar/contact journeys

`sogo-r2` supplies private component coverage for SOGo, bringing the selected-family total to **37/39**, plus OpenBao and Keykeeper. **Full-stack acceptance remains 0/2.** This is calendar/contact coverage, not working mail integration.

A subsequent [separate SOGo/mail composite](private-sogo-mail-integration.md) now passes native SMTP delivery, IMAP/browser and Sent-copy persistence, native SOPE TLS/cross-user denials, calendar/contact journeys and five-daemon supervised restart. Its [separate coordinated encrypted recovery](private-sogo-mail-recovery.md) also passes native restored workflows, denials and write isolation. It does not modify or recover this standalone fixture; current family coverage is 38/39, not independent full-stack acceptance.

## Runtime

`SogoRuntime.kt` and `runtime prepare-sogo INVENTORY [NAME]` prepare an immutable private deployment with four daemons and two guarded initializers:

- PostgreSQL 17, verified TLS for remote connections, persistent database volume, scoped application principal.
- Native Memcached, UDP disabled, confined to this dedicated internal network. It is not an authenticated or encrypted cache service.
- Unmodified native SOGo 5.12.12-1, one bounded worker, persistent GNUstep home, SQL identities/profiles/calendar/contact data. The image's root entrypoint, supervisor, cron and extra sogo-tool-plus service are not run.
- Native Apache, running as UID/GID 994 on HTTPS 8443, serving the packaged resources and proxying SOGo. No privileged bind capability is required.

Every container has a nonzero UID, read-only root, empty capability sets, no-new-privileges, private AppArmor profile and bounded resources. No ports are published. Native SOGo and Apache binaries and browser bundles were not patched. HTTP between Apache and SOGo, and Memcached traffic, are limited to the dedicated network; not every internal hop is encrypted.

The first guarded job initializes PostgreSQL. The second creates a non-superuser application role, the database and three synthetic identities with PostgreSQL-generated bcrypt hashes (cost 12). The application can read but cannot update the identity table. The initializer's password is cleared and login disabled. Neither serving process receives the bootstrap environment. Initializer logs, ledgers and protected credentials remain retained; they must never be replayed.

PostgreSQL's remote non-TLS connections are rejected. SOGo inherits libpq `PGSSLMODE=verify-full` and the dedicated database CA. Native probes establish that the application connections actually use TLS, and reject plaintext, wrong CA, wrong hostname, the retired initializer credential and privileged SQL operations.

The HTTPS boundary rejects foreign Hosts and Origins, strips the proxy authentication header, and does not enable proxy-trusted authentication. Native wrong-password and anonymous requests fail. The authentication cookie `0xHIGHFLYxSOGo` is host-only, Secure and HttpOnly; Apache adds SameSite=Lax. The native JavaScript XSRF cookie is readable by JavaScript and is **not marked Secure**. This is an explicit production-hardening gap, not a claim of complete production browser security. The current fixture has only its private HTTPS listener and no public routes.

## Native evidence

Latest supervised pass: **`p0v3-sogo-b511c08e3583`** under `/mnt/media/p0-v3/image-acquisition-receipts/`.

It verifies:

- Native CalDAV event creation and conditional update, native CardDAV contact creation, and owner readback.
- Native stale-ETag rejection (412) with unchanged content. The original exclusive write intents and returned statuses are verified on repeats.
- Bob and the separate outsider cannot read Alice's private event or contact; anonymous access and incorrect passwords fail.
- Actual native browser login, calendar rendering and contact rendering, using a fresh browser before and after restart. The saved fixture date is selected explicitly, so later repeats do not require creating a new event.
- Scoped database privileges, unchanged bcrypt identity rows and actual native Memcached use.
- An actual systemd stop/start of all four daemons, changed start times, stable container IDs, unchanged runtime inputs/initializer ledger and unchanged native object bytes/ETags.

Earlier direct passes: `p0v3-sogo-858ebf00b4fc` and strengthened `p0v3-sogo-0793f9fe5667`. Original API creation/restart diagnostic `p0v3-sogo-dd5d1c90aa79` deliberately remains `passed:false, diagnosticOnly:true`; browser coverage was not available at that point.

Manifest SHA-256: `b92970f80d31c41aa6162c068841ba385397b05da7fc92a11f86381abacaecb0`.

The enabled/active unit is `p0v3-private-sogo-r2.service`, pinned to the twenty-second controller snapshot, `72e8f062350904fd5ef1021f8f90cc14a6395c1043200d582ade391485beb53a`. Older units were not repinned. Boot integration is not a crash watchdog or a host-reboot test.

Read-only fleet census `p0v3-fleet-186b7d599576` records **31 enabled/active units and 103 running declared daemons**. It is not a new whole-fleet restart or proof of application availability. The retained `huly-r8`, `huly-r9` and `jupyterhub-r7` fences remain intact.

## Repeat without writing fixtures again

```sh
python3 platform/scripts/test-private-sogo.py --name sogo-r2 --supervised
```

Do **not** repeat `--create` or delete its intents. Creation is exclusive, manifest-bound and recorded outside immutable inputs in `/mnt/media/p0-v3/sogo-probe-state/`. Each business write has a durable pre-request intent and an exclusive outcome. Failed or uncertain writes require explicit reconciliation, not blind retries. Repeats validate existing outcomes and do not create/update calendar or contact objects.

The Python probe refuses optimized Python before imports. Browser credentials travel through stdin, not command-line arguments. The browser uses the verified private leaf's SPKI only after CA/hostname/leaf validation; it does not disable HTTPS validation globally. Namespace entry drops supplementary groups and enables no-new-privileges. Logs, screenshots and object bodies remain protected fixture evidence, not public output.

## Retained failures

- `sogo-r1` remains stopped, with failure receipt `p0v3-sogo-failed-8b88721f160e`: Apache's `unixd` module is built in and cannot be loaded explicitly. Concurrent native initial schema creation also raced. r2 removes the invalid module directive, supplies `OCSAdminURL` and uses one worker; no failed initializer or source volume was reset.
- The first probe failed during read-only audit because optional manifest defaults were omitted. No fixture write occurred; the audit now uses the manifest's defined defaults.
- Browser diagnostics `p0v3-sogo-efa4e07bc7d9` and `p0v3-sogo-29986e0dcce1` failed on native selector assumptions. The native username field has a generated name, and the event title includes a privacy icon. The corrected verifier reads the visible native UI; it never recreated the event/contact.

## Deliberately unfinished

SMTP/IMAP integration is unavailable: the mail UI route returns 503, native SMTP/IMAP endpoints point at a closed loopback port, notifications/forwarding/vacation/Sieve are disabled and no public mail is sent. Mail-server product compatibility is still being engineered; it is not an operator-credential blocker.

Real-owner onboarding, central SSO/TOTP, sharing/delegation journeys, ActiveSync/mobile, production cookie/cache policy, coordinated encrypted database/home/configuration recovery, off-host custody, migrations and transactional rollback remain outstanding. These implementation-authored component receipts are not independent acceptance.
