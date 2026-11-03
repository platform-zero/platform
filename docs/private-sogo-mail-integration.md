# Private SOGo + native mail composite

**`sogo-mail-r2` now passes native SOGo SMTP delivery, IMAP/browser readback, sender Sent-copy persistence, native transport denials and five-daemon supervised restart.** Calendar/contact workflows also pass in this same composite. A subsequent [coordinated encrypted composite recovery](private-sogo-mail-recovery.md) now passes native restored workflows, attachment bytes, denials, restart and write isolation. This is private synthetic component evidence, not public mail, production onboarding, off-host custody or independent full-stack acceptance (**0/2**).

The original `sogo-r2` calendar/contact fixture and `mail-r9` standalone mail fixture remain unchanged. This is a separate recovery scope with fresh fixture identities and state, not an in-place migration. Logical-family coverage remains **38/39**; this closes a cross-service wiring gap without adding another family.

## Evidence and safe repeats

- Manifest: `91446ebefe3e8fc30021d501b7a108c673e791e187a9c8abb7c7410faacadc24`.
- Direct mail lifecycle: `p0v3-sogo-mail-25077cb6b10e`.
- Strengthened supervised mail lifecycle: `p0v3-sogo-mail-25a506821bfc`; latest repeat after the calendar/contact test: **`p0v3-sogo-mail-104aa792b5e1`**.
- Same-composite calendar/contact/SQL/TLS/browser supervised pass: **`p0v3-sogo-3f8332437e04`**.
- Backend SMTP/IMAP/attachment persistence and denials: `p0v3-mail-646cb75e7a36`.
- Guarded native SOGo send diagnostic: `p0v3-sogo-mail-browser-75bbf4a2dcda`; intentionally `passed:false, diagnosticOnly:true`, not a component acceptance receipt.
- Controller: `2ed3e5e9c4fc4a8ad2a0558285f93fb7736bedefc398ed221ebe30b938559c84`.
- Source hashes, validation logs and retained r1 failure/fence metadata: `p0v3-sogo-mail-engineering-15ded4d51dd2`.
- Latest read-only census `p0v3-fleet-76f661b89a89`: **33 enabled/active units, 109 running declared containers**. No whole-fleet restart or host reboot is claimed.

```sh
python3 platform/scripts/test-private-sogo-mail.py --name sogo-mail-r2 --supervised
python3 platform/scripts/test-private-sogo.py --name sogo-mail-r2 --supervised
python3 platform/scripts/inspect-private-sogo-mail.py --name sogo-mail-r2 --outgoing
```

**Do not repeat `--create`, `--send`, or `--resume-compose`.** Mail actions remain under `/mnt/media/p0-v3/mail-probe-state/<manifest>.json*`; calendar/contact actions remain under `/mnt/media/p0-v3/sogo-probe-state/`. Exclusive, fsynced compose/send intents and outcomes are outside immutable runtime inputs. The send outcome is required on repeats. No message or initializer is replayed.

## What the native journey proves

1. A direct SMTP fixture, including a binary MIME attachment, reaches Bob's mailbox. Its body and attachment entry are rendered by SOGo in a fresh real Chromium session. Attachment bytes are checked through native IMAP; attachment download through the SOGo UI is not claimed.
2. Alice logs into native SOGo, opens its real compose action, and sends through SOGo's native authenticated/XSRF-checked application endpoint. The native backend then uses authenticated implicit-TLS SMTP to Stalwart. **Message fields and final submission use the application API from the authenticated browser, not keyboard entry and the composer Send button. `browserComposeUi:false` is deliberate.**
3. Bob receives that distinct SOGo-generated message. Alice has the native Sent copy. IMAP checks verify one matching message in each folder, matching Message-ID, exact subject/body, and absence in the outsider's inbox.
4. Fresh Chromium sessions render both the incoming attachment fixture and SOGo-generated message. Bob's exact message resource returns content to Bob, while authenticated Alice and outsider sessions receive 403/404 without the nonce.
5. All five daemon IDs remain unchanged while their start timestamps change through actual pinned-unit stop/start. Recipient/Sent UID, UIDVALIDITY and raw-message hashes remain unchanged. Runtime inputs and all initializer ledger bytes are unchanged.
6. Calendar/contact checks separately prove conditional CalDAV creation/update/stale-ETag denial, CardDAV, native browser readback, cross-user denial, scoped PostgreSQL privileges/TLS, unchanged bcrypt identity rows and persistence through another five-daemon supervised restart.

The standalone mail probe additionally covers anonymous/wrong-password/sender/relay/admin denials. Public recipients are not delivered to; the native route remains local-only. Invitations, notifications, forwarding, vacation, Sieve and auxiliary mail accounts remain disabled.

## Runtime and trust boundaries

`SogoMailRuntime.kt` composes five daemons (`database`, `cache`, `mail`, `sogod`, `groupware`), three guarded jobs and three persistent volumes (`database`, `mail`, `home`). No host ports or runtime capabilities are granted. Existing UID/GID, AppArmor, read-only roots and resource bounds remain in force.

The same generated, distinct fixture passwords are provisioned into SQL authentication and Stalwart, without making the database bootstrap or mail recovery-admin environments available to serving processes. Separate filenames prevent bootstrap environment and CA shadowing. External-login identity uses the primary `p0v3.example.org` email address. Password input is validated before PKI generation; the namespace is reserved synthetic data, with no public DNS changes.

Only SOGo's container receives the private mail CA at `/etc/ssl/certs/ca-certificates.crt`; **host trust is not changed**. Database and ingress certificates retain independent CAs. SMTP and IMAP URLs require implicit TLS and default peer verification. The persistent mail spool is explicitly `/home/sogo/spool`, not an unwritable system directory or ephemeral temporary path.

`sogo_native_tls_probe.py` invokes the actual installed SOPE `NGActiveSSLSocket` through the Objective-C runtime, not a replacement Python TLS client. On both SMTP and IMAP ports:

- the private CA and `mail` hostname succeed;
- the same peer addressed by an unlisted IP hostname is rejected;
- a capability-free, read-only client using the same native image and stock trust store rejects the private CA with certificate-verification failure.

No credentials are sent during these transport tests. These checks run before and after restart. They complement the actual SOGo SMTP/IMAP journey; they are not a general protocol-conformance or packet-capture claim.

## Retained failures and credential incident

- Initial backend-probe support assumed every role had an environment file. It failed before fixture creation; optional fields were corrected.
- `p0v3-sogo-mail-browser-84cc2a8dea62`: the native subject overlay intercepted a click. The probe now clicks the real message button by its observed accessible label. No message was recreated.
- `p0v3-sogo-mail-browser-ddaf258b5b1e`: Playwright's separate Node API client could not resolve `groupware`, before connection. The original compose intent remains. A hash-bound, one-use reconciliation recorded this preconnection failure; no intent was deleted. That API client path was removed.
- **The Node error trace included a synthetic session cookie and was inadvertently exposed in diagnostic tool output.** Native logout was requested, old-cookie readback returned a login form rather than mailbox data, and the entire r1 candidate was subsequently stopped and maintenance-fenced. No production credential was involved. Future SOGo diagnostic logs redact cookie/authorization headers and known fixture passwords; unit tests exercise this behavior. The protected original evidence remains retained, not silently erased.
- `p0v3-sogo-mail-browser-fcc1c984955a`: a direct compose request returned HTTP 500; it was not retried. No send intent existed. `sogo-mail-r1` is stopped and fenced, with its data and earlier reconciliation retained.
- Fresh r2 adds the explicit persistent spool and uses SOGo's native compose UI request rather than guessing its request semantics. `p0v3-sogo-mail-browser-1b8de8f9b1f2` timed out waiting for a hidden submenu **before clicking compose**. An explicit hash-bound one-use pre-action reconciliation allowed opening the native speed-dial menu. The corrected action succeeded once; its resume marker is consumed and must not be removed.

All six retired-candidate fences (`huly-r8`, `huly-r9`, `jupyterhub-r7`, `mail-r4`, `mail-r7`, `sogo-mail-r1`) remain in place. The first composite recovery target `smrestore-0609bbce6070` has an additional retained fence. Later component passes do not rewrite failed diagnostics into successes; see the [recovery failure and reconciliation record](private-sogo-mail-recovery.md).

## Unit validation

The Kotlin composite contract tests verify separate bootstrap credentials/CAs, shared distinct fixture identities, dependency ordering, local-only mail configuration and persistent spool placement. Invalid credential inputs are rejected before PKI generation. Diagnostic-redaction, action-guard and optimized-Python refusal tests pass. The full Python unit suite is **107 tests** after recovery/selector regressions. JVM unit-only line coverage is **3852/4168 (92.42%)** for platform, **576/617 (93.35%)** for Keykeeper and **159/167 (95.21%)** for acceptance. Native browser/protocol tests are separate from those coverage figures; Worklane's private unit-only gate was also rerun at the recovery checkpoint: **142 tests, 90.31% line coverage**, not live lane acceptance. All four repository diff checks pass.

## Remaining work

Pending-draft and off-host recovery, transactional migration/rollback, production identity/TOTP/application passwords, owner enrollment, full keyboard-driven composer/attachment submission, sharing/delegation/mobile/ActiveSync, public mail/DNS/abuse operations and public TLS remain unaccepted. The native SOGo JavaScript-readable XSRF cookie still has the previously documented missing Secure flag; the authentication cookie is Secure/HttpOnly. Memcached remains unauthenticated on the dedicated private network. Native Message-ID HEADER-search compatibility limitations from the standalone mail component remain; bounded indexed candidates plus exact fetched headers are used explicitly. Supplementary recovery testing also found subject searches returning both known fixture subjects; the exact-header selector rejects duplicate identities rather than choosing the first candidate.

Reviewed RSS publication, Worklane integration and the live whole-release transaction/recovery backend are still unfinished. None of these component receipts satisfies the two independently reviewed clean-install/functional-restore cycles.
