# Private systemd boot/shutdown supervision

Thirty-three dedicated system units are now **installed, enabled and active** for the existing 109 declared private service containers (38 selected families plus OpenBao and Keykeeper). Seafile's backend contains the upstream loopback-coupled Seahub/fileserver pair; this count is not an OS-process census. This closes the absence of boot/shutdown integration for these deployments; it does not complete the 39-family stack or register the full release backend. **No shared-host reboot was performed. Full-stack acceptance remains 0/2.**

## Installed scope

Units are named `p0v3-private-<deployment>.service` for:

- `foundation-r3`, `identity-r2`, `observability`
- `forgejo-r2`, `planka-r3`, `sql-cache`
- `jellyfin-r4`, `donetick`, `homeassistant-r2`
- `notebook-r2`, `qbittorrent`, `matrix-r2`, `opensearch-r2`, `firefly-r2`, `bookstack-r3`, `knowledge-identity-r4`, `livekit`, `openbao-r4`

- `mastodon-r4`, `matrix-identity-r4`, `searxng-r2`, `erpnext-r7`, `crowdsec-r4`, `seafile-r4`, `files-office-r7`
- `keykeeper-identity-r4`, `node-metrics-r2`, `backup`, `huly-r10`, `jupyterhub-r8`, `sogo-r2`

Stopped failed candidates, standalone Synapse, quarantined restore targets and unrelated host services were not enrolled. No shared sudoers, AppArmor or network policy was changed by this work.

`RuntimeBootUnits.kt` renders the units. Each runs as the existing non-root runtime owner, using the already-authorized passwordless Podman delegation. This host-side controller therefore is **not a new privilege-isolation boundary**. The applications retain their separate existing container confinement.

Each unit:

- Requires the dedicated storage/run mounts and orders startup after network-online and AppArmor.
- Pins the exact deployment name and SHA-256 of its private manifest; changed bytes or a mismatched embedded deployment name fail before live effects.
- Executes a **root-owned, content-addressed controller distribution**, rather than the mutable workspace build.
- Calls the existing audited DAG apply on start and reverse-dependency graceful stop on shutdown.
- Uses `Type=oneshot`, `RemainAfterExit=yes`, bounded startup/shutdown timeouts, and `Restart=no`.
- Uses `KillMode=process` so systemd does not indiscriminately kill container descendants when the controller exits; actual container shutdown is the audited `boot-stop` operation.
- Does not pull images, update applications, schedule backups, delete volumes or expose ports.

These are **boot/shutdown units, not crash watchdogs**. An `active (exited)` unit means its startup completed; it does not prove every daemon is still healthy. Use the private runtime status/audit and real application checks for current state. No periodic reconcile timer races a stopped-source snapshot.

## Pinned controller

Original twelve units' controller tree SHA-256:

`47e21a2bbc22c7e1a11388224a32458a42480857eb0fbdd6d990a524e43fa399`

Location:

`/mnt/media/p0-v3/runtime-supervision/releases/<tree-sha256>/`

The later `opensearch-r2` unit uses controller tree `0b5e802e0bee63cfe3b6edc4ac08d8803dbfa8d7a8965c47d71051378d864b95`. The later `firefly-r2` unit uses controller tree `7c5ba70e11b4fa39ff04f4739731ac98cd453742d397db42494d17a4f8b81b67`. `bookstack-r3` uses controller tree `89061fb049f867b3a28c62e1209328ef9a6931ad2fdd487829a6c106688d12e5`. `knowledge-identity-r4` uses controller tree `5cb5068f4519d49ef3646861305e831d8cd08cdb1318c9f6fcc9263476c6adb5`. `livekit` uses controller tree `8215f29fc90871ab003b9f47bfa54aa7c934c788a6d6fb6a715f74b3ea4315ef`. `openbao-r4` uses controller tree `60aee905f1ae5bfad60f9a70f7e6c0d08c0da23c1fb008e364c389d3e60ba3d6`. The earlier units were not silently upgraded. [Durable maintenance](private-maintenance.md) now blocks new-controller startup; old pinned controllers also fail closed on its unexpected control record. Native proofs used separate, subsequently disabled `fence-*` fixture units, not upgrades of the then-active eighteen units. The lifecycle test now verifies each unit against its own pinned controller and reenables the installed unit; it does not assume the current workspace build equals every installed snapshot.

`controller.json` binds every distribution path, installed mode and file hash. The installer snapshots source bytes, rejects symlinks/unexpected files, checks root ownership/modes/content, and validates generated units with `systemd-analyze verify`. It refuses all conflicting existing named units before installing any unit. Controller staging can remain after an interrupted installation; it is not silently pruned. The host Java 21 installation remains a prerequisite, not part of this controller tree hash.

A repeated identical installation preserves the existing controller and units. Changed controller code or manifests require explicit replacement review; this installer deliberately has no overwrite/update switch. This is **not** transactional application upgrade/rollback.

## Actual execution evidence

`platform/scripts/test-private-boot-supervision.py` exercises the real installed units, not mocked systemd:

1. Verifies each installed unit against its pinned controller/manifest, reenables all eighteen units, and proves no daemon identity or start timestamp changed. The original twelve-unit runs also tested repeated identical installer execution.
2. Executes a real notebook kernel and saves its actual output.
3. Restarts only the eighteen named services through `systemctl`.
4. Proves declared daemons have new start timestamps but unchanged container IDs and no published ports. The latest full-fleet execution covered 39 daemons; the added Mastodon/delegated Matrix units' six daemons each, SearXNG's two, ERPNext's eight, CrowdSec's one, Seafile's five, the office composite's seven, the Keykeeper composite's four, node metrics' two, Kopia's one, Huly's fourteen, JupyterHub's four, SOGo's four, mail's one and the SOGo/mail composite's five were exercised separately, not misreported as a new 109-container full-fleet run.
5. Proves durable initialization journals are unchanged. The latest run also checks every retained completed initializer's identity/start timestamp, and that removed completed helpers remain absent.
6. Checks all eighteen units remain enabled and active, then reads back the notebook's saved output.

Passed receipts under `/mnt/media/p0-v3/image-acquisition-receipts/`:

- `p0v3-boot-8d900aebe496`
- `p0v3-boot-9835334dd59a`, including the explicit initializer non-replay checks for the original twelve units
- `p0v3-boot-3259121b360d`, covering thirteen units, 25 daemons and two pinned controller versions
- `p0v3-boot-4ca5250adfa9`, covering fourteen units, 28 daemons and three pinned controller versions
- `p0v3-boot-d8dd2b3a360e`, covering fifteen units, 31 daemons and four pinned controller versions
- `p0v3-boot-130e3ec9b66f`, covering sixteen units, 36 daemons and five pinned controller versions
- `p0v3-boot-1c4edea42fa6`, covering seventeen units, 38 daemons and six pinned controller versions
- **`p0v3-boot-bed6a9f978ec`**, covering the then-current eighteen units, 39 daemons and seven pinned controller versions; explicitly verifies OpenBao is sealed afterward and needs manual unseal
- **`p0v3-social-373f48c39a77`**, a separately scoped actual restart of the new `mastodon-r4` unit: six same containers/new start times, no initializer replay and native browser readback. Its controller is `e40d0426576cca7c68b6a137a51e212bd384b4acb15822eb57b97f16942dc113` (eighth pinned snapshot). That milestone totalled 19 units/45 daemons. See [social evidence](private-social-integration.md).
- **`p0v3-matrix-id-a6b945eabfbe`**: actual six-daemon `matrix-identity-r4` unit restart, same container IDs/new start times, unchanged initializer journal, native Element login/readback and fresh-device identity recovery. Controller `627a977269b0c6ab0938ea068d7d9c7b31f8d25206257ecce45f1247360480cb` is the ninth snapshot. That milestone totalled 20 units/51 daemons. See [delegated Matrix evidence](private-matrix-identity.md).
- **`p0v3-metasearch-0ea24b1b85ec`**: actual two-daemon `searxng-r2` unit restart, unchanged IDs/corpus/journal, new start times, and native API/browser search. Controller `5f09b14f8cb818a62186e00400516898cf897d0434a6641fdb47b110eb5c69b8` is the tenth snapshot. That milestone totalled 21 units/53 daemons. See [private metasearch evidence](private-metasearch-integration.md).
- **`p0v3-erp-eb61f4c8ec33`**: actual eight-daemon `erpnext-r7` restart, same containers/new start times, unchanged initializer journal and native business-record, realtime, queue and authorization checks. Controller `afa06bafd78ad227bbc75e8d32c8aa7d1afe839a1fceda89285a6096aa2faa9e` is the eleventh snapshot. That milestone totalled 22 units/61 daemons. See [ERP evidence](private-erp-integration.md).
- **`p0v3-guard-75a499afb60e`**: actual `crowdsec-r4` restart with unchanged initializer journal, native detection/decision-stream/expiry/revocation and persistent decision ID. Controller `2eb888108b9f6803fddfe6333a65b2663029ae2f69278510e2e7ff438c016e32` is the twelfth snapshot. That milestone totalled 23 units/62 declared daemons. See [security evidence](private-security-integration.md).
- **`p0v3-files-bf5018497e7d`**: actual five-container `seafile-r4` restart, unchanged initializers, browser/API file transfer, persistent content and sharing/denial/revocation. Controller `8ce06500bd74ee4579cd8c399872efe4668614076167c7a4b3f3b6c24f239029` is the thirteenth snapshot. That milestone totalled 24 units/67 declared service containers. See [file evidence](private-files-integration.md).
- **`p0v3-office-a7db57627181`**: actual seven-container `files-office-r7` restart, native DOCX edit/save/read-only denial, unchanged initializers and durable callback uncertainty protection. Controller `f84b69eb195a932f469309bb8eff74164001db3efe7d36db9e37438cf7dba25a` is the fifteenth snapshot; the fourteenth, for r6, is retained with its unit disabled/stopped. That milestone totalled 25 units/74 declared service containers. See [office evidence](private-office-integration.md).
- **`p0v3-keykeeper-id-307d71a6b52f`**: actual four-container `keykeeper-identity-r4` restart, fresh native browser OIDC/TOTP and saved-record/revoked-grant verification. Controller `605ab6c4f898e95fab15408f4a9d860e468354e51fc4ae2a3cfc79038334e209` is the sixteenth snapshot. That milestone totalled 26 units/78 declared service containers. OpenBao deliberately starts sealed: native vault requests return 503 until explicit operator unseal. Unit active/transport readiness is not operational availability. See [Keykeeper evidence](private-keykeeper-integration.md).
- **`p0v3-node-67d7390bbdc5`**: actual two-container `node-metrics-r2` restart, mTLS scrape/query, live synthetic input changes, native alert firing/resolution and historical TSDB readback. Controller `f96c08db85039c90bea3aeb00ca4d11c13a56b118705aef11e2f7981b1b65478` is the seventeenth snapshot. That milestone totalled 27 units/80 declared service containers. There are no host telemetry mounts or public ports; a subsequent separate encrypted recovery is documented in [node metrics evidence](private-node-metrics.md).
- **`p0v3-backup-1dfba839cf09`**: fresh native Kopia API snapshot, networkless read-only repository restoration with exact bytes and wrong-password denial, followed by the actual `backup` unit restart with unchanged snapshot records/container ID/initializer journal. Controller `d5b5c06a49b9b5f0cc61f3f54148a488b92efa6f0edd753e79596ea2e75954b3` is the eighteenth snapshot. At that point the fleet totaled 28 units/81 declared service containers; the full-fleet script includes this addition. Only a synthetic source is mounted, not other deployments. See [backup service evidence](private-backup-integration.md).

Earlier harness failures are retained: deployments without one-shots correctly had no initialization journal, and the notebook probe correctly rejected a filename outside its bounded fixture pattern. Neither was counted as a pass.

These checks prove systemd lifecycle execution and one functional persistence journey, **not all-product acceptance, a host reboot, an encrypted restore or either full-stack cycle**.

## Operator commands

```sh
# Enroll a newly prepared/running deployment, or repeat an identical controller installation.
# Existing units with a DIFFERENT pinned controller deliberately reject replacement.
python3 platform/scripts/install-private-boot-units.py --activate opensearch-r2

# Exercise only the enrolled v3 workloads; does not reboot the host.
python3 platform/scripts/test-private-boot-supervision.py

systemctl status p0v3-private-notebook-r2.service
sudo -n systemctl stop p0v3-private-notebook-r2.service
sudo -n systemctl start p0v3-private-notebook-r2.service
```

For maintenance intended to survive a host reboot, explicitly disable the affected unit as well as stopping it. A stopped-but-enabled unit will start at the next boot. Existing direct CLI tests may temporarily stop/apply containers without updating systemd's oneshot status; they do not encounter an automatic watchdog, but that status must not be used as live-health evidence.

The installer's Python safety checks cannot be bypassed with `python -O`: optimized execution is explicitly rejected before effects. Python unit tests mock root/systemd effects; the new installer measured **99% executed-line coverage with Python's standard-library trace** in that unit-only run. This historical installer-only measurement is separate from the current platform Kotlin JaCoCo gate (**3733/4041 lines, 92.38%**). The current Python suite passes 82 tests, including native Hub helper unit/coverage gates and a runner for nineteen mock-based Huly Node tests and their >=90% line-coverage gate (98.80% across the five Huly runtime JS helpers). No real lifecycle/browser tests are included in those unit coverage figures.

## Huly addition and earlier census

`p0v3-huly-fbb2ba95f277` passes native issue/description/indexing and outsider-denial checks around the actual `huly-r10` unit stop/start, with fourteen changed daemon starts and unchanged IDs, immutable inputs and initializer ledger. The nineteenth pinned controller is `e72621f91f088447b17f6405a53e6ae598cd6f54b955416ffdbf00fa612f09e4`; no older unit was repinned. See [Huly evidence](private-huly-integration.md).

Read-only census `p0v3-fleet-2e3538bcfca5` verifies 29 enabled/active units, 95 running declared containers, no published ports, non-root/read-only roots, no-new-privileges and capability sets matching manifests. Matrix's older Caddy retains its declared `NET_BIND_SERVICE` exception; Huly has no capabilities. The stopped failed `huly-r8` and `huly-r9` candidates retain their intentional maintenance fences. This is not a whole-fleet restart, host reboot or proof that sealed OpenBao is available.

## JupyterHub addition and earlier census

`p0v3-hub-3057c800abd2` verifies two native saved kernel outputs, isolated user origins/cookies, cross-user and control-plane denial, foreign-Origin/Host checks and the actual `jupyterhub-r8` unit stop/start. Four container IDs, native user IDs, the persistent cookie secret and runtime inputs remain unchanged. The twenty-first controller snapshot is `4bb2777cb0bc9c9f6e512bf86317b67d9ccc4b145aade0b47508fd8e7e6abd1f`.

The earlier r7 unit is disabled/stopped and fenced after a negative test exposed Caddy directive ordering; two earlier component receipts have explicit invalidation sidecars. Its twentieth controller snapshot was retained, not silently repinned. See [JupyterHub evidence](private-jupyterhub-integration.md).

Read-only census `p0v3-fleet-5a188ca7f72a` verifies 30 enabled/active units and 99 running declared service containers with no published ports. Retired `huly-r8`, `huly-r9` and `jupyterhub-r7` retain maintenance fences. This is not a 99-container fleet restart, host reboot or proof of sealed-vault availability.

## Latest SOGo addition and census

`p0v3-sogo-b511c08e3583` verifies native calendar/contact browser/API journeys, authorization and SQL/TLS denials, retained conditional-write outcomes and unchanged bcrypt identities around an actual four-container `sogo-r2` stop/start. The twenty-second controller snapshot is `72e8f062350904fd5ef1021f8f90cc14a6395c1043200d582ade391485beb53a`. Mail remains explicitly unavailable; see [SOGo evidence](private-sogo-integration.md).

Read-only census `p0v3-fleet-186b7d599576` records 31 enabled/active units and 103 running declared daemons. It is not a whole-fleet restart, host reboot or proof of sealed-vault availability. All three retired-candidate fences remain intact.

## Remaining work

### Native mail addition

`mail-r9` uses pinned controller `b5733a68081703cfe0fe57c6c2b0bc5fc32f97a04e0be3183ce46a63c5ed96ae`. Supervised receipt `p0v3-mail-dd5abc459248` proves actual SMTP/IMAP message/attachment persistence and denials through unit stop/start, with unchanged IDs, input hashes and initializer ledger. Read-only census `p0v3-fleet-f3a1cc8cbd94` records **32 enabled/active units and 104 running declared daemons**. The earlier 31/103 census remains historical. Retired `mail-r4` and `mail-r7` have additional retained maintenance fences; the three earlier fences remain unchanged. See [mail limitations and failures](private-mail-integration.md).

### SOGo/mail composite addition

`sogo-mail-r2` uses controller `2ed3e5e9c4fc4a8ad2a0558285f93fb7736bedefc398ed221ebe30b938559c84`. Supervised mail receipt `p0v3-sogo-mail-25a506821bfc` and calendar/contact receipt `p0v3-sogo-3f8332437e04` each verify five actual daemon stop/starts, unchanged IDs/inputs/initializer ledger and native persistence. Latest repeated mail receipt `p0v3-sogo-mail-104aa792b5e1` passes again after the calendar/contact lifecycle. Read-only census `p0v3-fleet-5d0d5d0ad232` records **33 enabled/active units and 109 running declared daemons**. `sogo-mail-r1` is additionally stopped and fenced; all five earlier fences remain. See [scope and retained failures](private-sogo-mail-integration.md).

The subsequent [coordinated encrypted SOGo/mail restore](private-sogo-mail-recovery.md) passed in a separate target, now stopped and not enrolled. Source capture used the existing pinned unit without repinning it. Final census `p0v3-fleet-76f661b89a89` still records 33 enabled/active units and 109 running daemons, plus seven retained fences including the failed first restore import.

Full-host reboot recovery remains untested to avoid disrupting the protected shared installation. Crash monitoring, durable release-maintenance/freeze coordination, unattended backup scheduling, full transactional upgrades/rollback, the remaining logical family (reviewed deployed RSS publication), production mail identity and whole-release coordinated recovery, Worklane/TUIOS/Pi deployment, owner/agent integration, public TLS and independent two-cycle acceptance are still unfinished.
