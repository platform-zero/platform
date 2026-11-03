# Private JupyterHub — isolated users, native kernels and restart persistence

## Implementation-only recovery projection

`JupyterHubRuntime.coldRestoreSpec(compiled)` now provides a pure same-cohort daemon projection for the generation recovery compiler. Before native startup it requires the recovered Hub SQLite database and cookie secret, both user work directories, and exact stopped lifecycle journals with no pending journals. Missing state is not silently regenerated. All three volumes and all four serving processes remain declared. D03 must first prove exact compiler equality and cold volume/input restoration; this function does not authorize arbitrary archived entrypoints or upgrades. Historical receipts below do not validate changed source. Production identity, quota/retirement policy and qualified Hub adapters remain unfinished.

`jupyterhub-r8` adds private component coverage for JupyterHub, distinct from the existing personal notebook. JupyterHub supplied the thirty-sixth selected family; with the later [SOGo integration](private-sogo-integration.md), the current total is **37/39**, plus OpenBao and Keykeeper. **Full-stack acceptance remains 0/2.**

## Actual deployment and security boundary

`JupyterHubRuntime.kt` uses the immutable JupyterHub and notebook 6.1.1 cohort already acquired, plus the file-capability-free Caddy image introduced for Huly. Four containers run as UID/GID 1000, with read-only roots, empty capabilities, no-new-privileges, resource bounds, the private AppArmor profile and no published ports:

- `controller`: native Hub and its native configurable-http-proxy, with a persistent SQLite/cookie-secret volume.
- `alice`, `bob`: separate notebook containers, PID namespaces, persistent home volumes and per-user API/control credentials.
- `hub`: private HTTPS ingress, with explicit certificates for `hub`, `alice.hub` and `bob.hub`.

Neither Hub nor notebooks receive a Podman/Docker socket or arbitrary host mounts. This is a bounded two-slot spawner, not dynamic container provisioning. A third synthetic identity, `outsider`, is preprovisioned without an allocated notebook slot. Identity credentials are protected fixtures, **not real-owner onboarding or production SSO/TOTP**.

Untrusted notebook code must not share the Hub's browser origin. Native Hub subdomain routing and host-only `__Host-` secure/HttpOnly cookies separate login and notebook origins. The login origin rejects `/user/*`; each notebook origin accepts only that user's path and rejects foreign Origins. Scoped browser resolver mappings supply private hostnames without modifying shared DNS or trust stores.

Each notebook's fixed-command lifecycle agent:

- Accepts no arbitrary command, environment or request body.
- Requires its own dedicated PID namespace and a per-user bearer credential over verified HTTPS.
- Admits control connections only from its own namespace or the Hub controller; peer notebook control traffic is rejected before TLS handshake.
- Records starting/running/stopping/stopped state durably, refuses replay after incomplete/failed state and never normalizes forced shutdown into success.
- Gracefully terminates the native server, reaps remaining descendants in its own PID namespace, and reports failure if escalation is needed.

The agent is not a privilege boundary against code already executing as that same notebook user; its control credentials/journal are in that user's container. Isolation from the other user and Hub comes from separate namespaces, mounts, credentials, browser origins and native OAuth scopes.

Native server API tokens retain only the Hub's server scopes. Real tests prove valid token identity, successful own-server access, denial of another user's contents and denial of Hub administrative user listing. The other user's notebook is absent from the caller's own home. These are not claims of production network policy, arbitrary-user admission or whole-stack write freezing.

### Native compatibility details

- The Hub executable is `/srv/venv/bin/jupyterhub`, not `/usr/local/bin/jupyterhub`.
- The single-user extension overrides file-based TLS settings. Explicit native CLI certificate/key options preserve HTTPS; no TLS verification was disabled.
- configurable-http-proxy uses the incoming public hostname for backend TLS verification. Per-user leaf certificates therefore contain both the internal name and that user's public-private subdomain, never the other user's or Hub's identity.
- The fixed environment includes native OAuth access scopes, host-prefix cookie mode, public URLs and user root directories.
- CHP shares the controller namespace. Its fallback route uses `127.0.0.1:8081`, avoiding a loop through notebook-origin ingress when a server is stopped. Remote notebook-to-Hub API traffic explicitly uses verified HTTPS. Ingress-to-controller HTTP is confined to the dedicated network; this is not a claim that every internal hop uses TLS.

## Native evidence

Latest supervised component pass: **`p0v3-hub-3057c800abd2`**, under `/mnt/media/p0-v3/image-acquisition-receipts/`.

The proof includes:

1. Native Hub login, native single-user OAuth and JupyterLab on separate user origins.
2. Actual kernel WebSocket execution for each user, with distinct nonce-bearing output, saved through the native contents API and rendered in the native notebook UI.
3. Fresh browser readback without re-executing the fixture, both before and after an actual four-container systemd restart.
4. Bidirectional authenticated browser denial. Active foreign servers return native 403; a stopped foreign server is concealed by the Hub's specific authenticated 404 response. Owner readback subsequently proves the notebook still exists.
5. Native server-token scope and control-plane denial checks, separate-home checks, private CA/hostname/leaf checks, default-trust denial, wrong-Host denial, login-origin notebook denial and foreign-Origin rejection on both user routes.
6. Changed daemon start times, unchanged container IDs/inputs, and unchanged native user IDs and persistent cookie secret.

Direct-controller restart proof: `p0v3-hub-20b711ec1f2d`.

Original r8 notebook creation diagnostics: `p0v3-hub-browser-69b4191a9863` (Alice), `p0v3-hub-browser-797235b48bea` (Bob). Browser diagnostics deliberately remain `passed:false, diagnosticOnly:true`; only the separately scoped lifecycle wrapper issues a component pass. No implementation-authored receipt constitutes independent acceptance.

## Repeating safely

```sh
# From the workspace root; reads existing fixtures, never recreates them:
python3 platform/scripts/test-private-hub.py --name jupyterhub-r8 --supervised
python3 platform/scripts/inspect-private-hub.py --name jupyterhub-r8 --user alice --mode verify
python3 platform/scripts/inspect-private-hub.py --name jupyterhub-r8 --user bob --mode verify
```

Do not repeat `create` or remove intents. Protected state under `/mnt/media/p0-v3/hub-probe-state/` is separate from immutable runtime inputs. Both effectful probes reject optimized Python before imports/effects. Credentials travel through protected files/stdin, not command-line arguments.

Manifest SHA-256: `e8bf66798dcdbb505837ced743081f90e5b36c6457ccf833b7278e7c6d388405`.

`p0v3-private-jupyterhub-r8.service` is installed, enabled and active with the twenty-first immutable controller snapshot: `4bb2777cb0bc9c9f6e512bf86317b67d9ccc4b145aade0b47508fd8e7e6abd1f`. The retired r7 unit is disabled/stopped and its twentieth snapshot remains untouched. This oneshot unit is boot/shutdown integration, not a crash watchdog. No older unit was repinned.

Earlier read-only census `p0v3-fleet-5a188ca7f72a` confirms **30 enabled/active units and 99 running declared service containers**, with no host ports and confinement matching manifests. It is not a whole-fleet restart, host reboot or proof that sealed OpenBao is available. The two retained Huly maintenance fences remain intact, and retired `jupyterhub-r7` is now fenced as well.

## Failures, reconciliation and unit coverage

Earlier Hub candidates remain stopped and retained. The recorded failures exposed executable-path assumptions, ingress/proxy loops, native TLS-option precedence, backend certificate hostname requirements and missing native OAuth scopes. r6's real restart failure (`p0v3-hub-403c7d3c9909`) identified the stopped-server fallback loop; r7 corrects it. The earlier r7 wrapper (`p0v3-hub-30087b0fe68e`) failed rather than silently accepting an unexpected status; the corrected verifier recognizes the Hub's specific authenticated resource-concealment response.

A subsequent negative test (`p0v3-hub-browser-9455a92d4be2`) found that Caddy sorted `handle` ahead of the user-origin `respond` guard. r8 uses explicit `route` ordering and now verifies both user-origin rejections before and after restart. Earlier component receipts `p0v3-hub-868b7d8e526c` and `p0v3-hub-c2308212e228` have protected hash-bound `invalidation.json` sidecars; their original observations were preserved, not rewritten into success. The r7 unit was disabled/stopped and fenced with ID `7ca52b6e-c932-457c-8056-f0cac9228ae5`. Never silently release this fence or reuse those superseded passes.

The r6 initial notebook preflight omitted its XSRF header and failed before writing. Browser readback, native authenticated contents/session reads and direct synthetic-home inspection independently established absence. A hash-bound exclusive reconciliation sidecar authorized one resume, preserving the original intent and started marker. Those r6 records and notebooks remain retained; r7 and r8 have separate fresh intents. No uncertain notebook execution was blindly repeated.

Seventeen mock-only unit tests cover lifecycle, credential/peer checks, native configuration and spawner behavior. Enforced unit line coverage is **168/169 (99.41%)** for `hub-agent.py` and **85/85 (100%)** for `hub-config.py`; browser/container tests are excluded. The complete Python suite passes 79 tests. Platform JVM coverage is **3688/3992 (92.38%)**. Resource packaging now excludes generated Python bytecode caches; previously pinned controller trees are not silently modified.

## Unfinished scope

Production identity/TOTP and owner enrollment, dynamic user provisioning/retirement, quotas and hostile-user resource/network policy, coordinated encrypted Hub/home/configuration restoration, migrations, transactional upgrades/rollback, public TLS/renewal, off-host recovery, Android and independently reviewed full-stack installs remain unfinished. Native saved-output persistence is not backup restoration, and two synthetic users do not establish production onboarding.
