# Private coordinated SOGo/mail recovery

**A fenced, encrypted three-volume/configuration restore now passes native mail, calendar/contact, browser, authorization and restart checks.** This is the separate `sogo-mail-r2` synthetic composite, not recovery of standalone `sogo-r2` or `mail-r9`, off-host disaster recovery, migration, or independent full-stack acceptance. Family coverage remains **38/39**, full-stack acceptance **0/2**.

## Evidence

Protected receipts are beneath `/mnt/media/p0-v3/image-acquisition-receipts/`:

- Latest complete coordinated restore: **`p0v3-sogo-mail-restore-ac436b6d1c5a`**, including all final archive/oracle/selector checks and all three native lifecycle probes in one run.
- Source: `sogo-mail-r2`, manifest `91446ebefe3e8fc30021d501b7a108c673e791e187a9c8abb7c7410faacadc24`.
- Isolated target: `smrestore-ac436b6d1c5a`, manifest `8f23a571b49d72889fae2ea5b9325ba405623a5e983d2ffe62c3d2835f14d0fb`.
- Kopia object: `k4f7caec8de41f1d3a09b8137d8f09df9`.
- Archive manifest SHA-256: `6b293fceb90cff9f62b1c972bad11a8df57dcfd668e668a0097327a58055eecb`.
- Restored backend attachment/authorization/restart: **`p0v3-mail-579b615249ac`**.
- Restored native SOGo mail/browser/transport/authorization/restart: **`p0v3-sogo-mail-8b5704f0d992`**.
- Restored native calendar/contact/browser/SQL/TLS/restart: **`p0v3-sogo-0fb1e8d18b6a`**.
- Earlier successful composite restore: `p0v3-sogo-mail-restore-0e352d471cc7`, with native receipts `p0v3-sogo-mail-35aaf0deda57` and `p0v3-sogo-2f1c8437f38f`. Its supplementary backend pass `p0v3-mail-bae839f85136` is recorded separately in `supplemental-backend-r2.outcome.json`, not retroactively inserted into that earlier receipt.
- Source hashes, validation logs and failure references: **`p0v3-sogo-mail-recovery-engineering-0b166050a975`**.
- Final read-only census: **`p0v3-fleet-76f661b89a89`**, 33 enabled/active units and 109 running declared daemons. No fleet restart, host reboot or sealed-vault availability claim.

The source unit was explicitly stopped/disabled only for capture, then reenabled and started with its existing pinned controller. All four restore targets are retained **stopped and not enrolled in boot supervision**. No existing controller was repinned.

## Capture and import boundaries

`SogoMailRecovery.kt` accepts only the exact supported composite recipe and a fresh `smrestore-*` name. Its `runtime prepare-sogo-mail-restore INVENTORY RECOVERED_DIRECTORY NEW_NAME` command prepares inputs and guarded processes; it does **not** itself capture or import application data.

The native harness, `platform/scripts/test-sogo-mail-encrypted-restore.py`:

1. Audits the source and its pinned unit, creates distinct synthetic mail/calendar markers with exclusive fsynced intent/outcome records, then stops the five daemons and disables the unit.
2. Enters the durable backup fence, confirms ordinary startup is refused, holds the runtime lock, and verifies every declared source process is stopped.
3. Captures PostgreSQL's cold cluster, Stalwart's RocksDB/native configuration and SOGo's home/spool together. Memcached is disposable and is not treated as authoritative state. Exact private runtime inputs, including certificates, keys and fixture credentials, are captured; the runtime controller's action/initializer ledgers are not imported into the target.
4. Bounds each streamed tar archive to 1 GiB. Traversal, duplicate names, links, special files, privileged modes, foreign UID/GID and reserved control-marker collisions are rejected. Import explicitly restores the validated root-directory mode: a pre-existing sticky bit must not silently survive extraction.
5. Creates an isolated encrypted Kopia repository, verifies 100% of snapshot files, rejects the wrong password, restores into a new directory without overwrite, and checks all exported hashes and archive inventories.
6. Recaptures stopped source volumes and checks exact tree equality, unchanged inputs/initializer ledger, unchanged container IDs/start times and continued stopped state before releasing its own fence and resuming the source.
7. Provisions fresh target volumes/network, enters a restore fence and imports while holding its runtime lock. Empty-volume checks and in-progress markers prohibit partial-import replay. Missing, foreign, broken-symlink and symlinked-completion markers are actually rejected using the native images.
8. Replaces destructive jobs with checks: PostgreSQL must contain a cold version-17 cluster; the scoped application role must see all three identities while the initializer remains NOLOGIN; Stalwart must contain its store and original generation; home/spool must have its own source-manifest-bound completion marker. A new home guard precedes SOGo startup. Database initialization, account seeding and mail bootstrap are never rerun.

The earlier successful receipt's `ownership-and-root-mode-validation.json` additionally binds all twelve retained source/stable/imported/exported archives to fixed declared owners and exact trees. The latest complete run enforces these ownership and reserved-marker checks directly; extraction commands remain identical.

## Functional proof, not just readable files

- Existing native SOGo-generated recipient and Sent messages survive, with exact Message-ID, subject/body, UID/UIDVALIDITY and raw-message hashes through target restarts.
- Fresh browsers render the restored received-message/attachment entry and SOGo-generated message. Exact-resource cross-user denial, native SOPE CA/hostname denial and scoped database/TLS checks continue to hold.
- Existing calendar/contact fixtures, conditional-write outcomes and bcrypt identities are read back; no fixture creation is substituted for recovery.
- The backend test fetches the original binary attachment through native IMAP and compares its decoded bytes. `original-to-restored-mail-comparison.json` also verifies the original source receipts' UID/UIDVALIDITY and raw-message hashes against the restored attachment message and both SOGo recipient/Sent copies. It also rejects anonymous/wrong-password/forged-sender/relay/admin access, verifies all three listener certificates, and checks no serving resource-download activity. It performs **no SMTP DATA submission**.
- New pre-snapshot mail/calendar markers exist in the target. Source writes made after capture are absent there; target-only writes are absent from the source. Both branches' expected records persist through the native restart journeys.
- Target network-namespace TCP attempts to source mail, database and ingress fail.
- `--restored-from` binds readback to the original protected fixture records, exact serving recipe, unchanged inputs and source-bound guards. Mutation flags are rejected for restore targets. Expected fixture metadata remains an out-of-band test oracle; it is not imported as application data or used to recreate objects.

## Retained failures and reconciliation

- **`p0v3-sogo-mail-restore-0609bbce6070`** stopped during guarded import: the newly mounted PostgreSQL directory retained mode `1700` rather than the captured `0700`. The strict archive checker rejected it. Explicit validated root-mode restoration fixes this; the failed target is still stopped with fence **`99ab0c6d-c3be-4f14-a375-f2419c95d145`**, data and markers intact. No partial import was retried.
- **`p0v3-sogo-mail-restore-1dbc3a8a2dcb`** restored mail and passed its native restart/browser checks, but calendar verification looked for an intent under the target manifest instead of the source oracle. The path was corrected; that entire receipt remains failed and its target remains stopped. Fresh backup/restore trials, with new marker identities, produced the successful receipts above.
- **`p0v3-mail-28cafb84fa3e`**, supplementary backend readback for the earlier `0e352d471cc7` restore, failed before restart because indexed `HEADER SUBJECT` search returned both `Private mail <nonce>` and the known `Private SOGo mail <nonce>` message. Read-only source inspection confirmed this behavior; it was not a duplicate delivery. `native-search-compatibility.json` records the finding. The helper now bounds candidates, fetches headers and demands exactly one exact Subject/Message-ID identity; duplicates or unexpected identity headers fail closed. This does not claim RFC phrase-search or general IMAP conformance.
- The failed supplementary intent/outcome remain. A separate hash-bound `supplemental-backend-readonly-reconciliation.json` authorized only readback and restart using the corrected selector. The subsequent pass did not delete an intent, resend a message, replay an initializer or turn the earlier failed receipt into success.

The six older retired-candidate fences remain intact, plus the failed restore fence above. The census now records all retained maintenance fences, not only the original candidate list.

## Unit validation and limits

All three JVM checks pass: platform **3852/4168 (92.42%)**, Keykeeper **576/617 (93.35%)**, acceptance **159/167 (95.21%)**. The Python suite has **107 passing tests**. `check-sogo-recovery-unit-coverage.py` measures unit-only executable lines: archive helper **37/37**, restore-oracle helper **39/39**, exact-header selector **22/22**. Mail-bootstrap unit coverage remains **108/109 (99.08%)**. Native browser/protocol tests do not count toward these coverage figures. Worklane's isolated unit-only gate also passed: **142 tests, 11842/13112 lines (90.31%)**, using the existing private Rust 1.88.0 toolchain outside a Herdr pane. No remote lab acceptance or release/dist publication was invoked.

A new invocation of the encrypted recovery harness is **effectful**: it makes new synthetic markers, temporarily stops the source and creates a fresh isolated target. It is not a read-only repeat. Existing fixture `--create`, `--send` and consumed reconciliation actions must never be replayed.

Still unproven: unsent/in-memory draft durability, full keyboard-driven composition and UI attachment download, production identity/TOTP/application-password/session-revocation recovery, public delivery/DNS/abuse operations, off-host custody and artifact availability, scheduling, migrations/rollback and whole-release consistency. Plaintext staging/export evidence is retained under protected local directories; the fixture Kopia key is local custody, not a production key-management design. Existing SOGo XSRF-cookie and unauthenticated-cache limitations remain. No public routes, RSS publication, owner data or unrelated host services were activated or altered. The two successful component restores are not independently reviewed full-stack clean installs and do not count toward either required acceptance cycle.
