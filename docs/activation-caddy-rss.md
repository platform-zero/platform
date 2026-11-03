# Activation authority, transactional Caddy and RSS reconciliation

This source increment is **unit-tested, runtime-unverified**. No controller distribution was installed, no native endpoint was contacted, and no real activation permit was consumed. The full release executor, canonical assembly and runner matrix are still incomplete; qualification remains **0/2**.

## Production activation authority

`QualifiedActivationAuthorization.real` is the concrete Platform adapter for `ReleaseActivationAuthorization`. It uses the pinned Acceptance distribution's `activation-verify` and `activation-consume` commands, not a supplied passing assessment or a trusted signature alone.

`ActivationEvidenceBinding` pins the product inventory, case manifest, candidate and artifact-closure files, qualification journal/head and Acceptance controller tree. The artifact closure contains:

- `schemaVersion: 1`;
- `controllers`, with exact `platform` and `acceptance` distribution descriptor digests;
- `images`, mapping artifact IDs to immutable registry references and local image IDs;
- `assets`, mapping auxiliary artifact IDs to content digests.

The raw closure digest must equal `CandidateIdentity.artifactsSha256`. Choosing a different verifier cannot silently retain the old candidate binding. Both controller distributions are rehashed; Platform must itself be executing from its declared installed JAR. Runtime image/reference pairs must belong to the frozen closure. A closure declares identities; it is not an acquisition or compatibility attestation.

The local verifier subprocess has a clean environment, fixed Java 21, bounded stdout/stderr and deadline, no shell interpolation, and private retained diagnostics. Timeout/interruption stops only its own process tree and never authorizes a retry of activation.

Acceptance re-verifies the complete current passing streak under its qualification journal lock. The permit selects the **second** qualified installation, binds its bundle, candidate, functional-restore snapshot, site, restricted configuration, transaction and accepted journal head. Consumption requires the exact seven-entry transaction history ending in `ACTIVATION_STARTED`, including its permit digest and the same qualified snapshot. The journal chain is recomputed, not trusted from a caller-supplied flag.

Consumption is an exclusive, fsynced record per generation in the fixed production namespace:

```text
/mnt/media/p0-v3/release-activation-consumptions/<q-generation>.consumed.json
```

Caller-selected alternate namespaces are rejected. The record retains the permit, consumption binding and exact claim journal. A partial file or lost acknowledgement is not reusable authority. Platform checks the durable record before returning to `ReleaseTransaction`, which alone sequences opening writes and releasing outbound last.

Before verification and consumption, Platform also reobserves the original owned canonical-v2 generation, completed staging, complete capabilities, exact live images/inputs, running processes and absence of retirement, pending snapshots or backup leases/failures. A private recovery is not promotion authority. It rechecks the actual restricted Caddy route revision, not merely a caller's label for an open configuration.

**Integration boundary:** the concrete authority exists, but the full `ReleaseEffects` backend/public release request dispatcher is not registered. Production qualification still refuses incomplete official-client classification and the empty real case manifest. Unit fixtures exercise successful authority with simulated completed policy; they are not native qualifications.

## Transactional Caddy adapter

`TransactionalCaddy` operates on one explicitly owned route group in an existing HTTP server. Its production factory binds the journal to `/mnt/media/p0-v3/caddy-transactions/<site>`; changing directories cannot bypass an uncertain operation. It does not configure listeners, DNS, issuers, account keys or certificate renewal. `LocalCaddyTransport` is restricted to an explicitly selected `http://127.0.0.1:<port>` admin endpoint; deployment must keep that admin endpoint inside the trusted controller boundary. It is not a public or independently authenticated admin API.

The adapter:

1. Reads `/config/` with a bounded response and root ETag.
2. Checks the expected configuration and owned-slot digests and exact approved `datamancy.net` hosts; apex/wildcard and conflicting/catch-all unrelated ownership are refused.
3. Persists a private immutable intent and per-site pending claim before dispatch.
4. Sends one `PATCH` replacing that server's route array with the root ETag in `If-Match`.
5. Observes the resulting owned slot, records the outcome and clears only the exact pending claim.

Unrelated routes, listeners, issuers and settings are preserved. Rollback compares the exact current owned slot with the recorded revision; it is not a blind reload of an old global configuration. Failed/lost acknowledgements leave pending state. Explicit reconciliation reads current state and records applied/not-applied; it **never resends the PATCH**. Divergent owned state remains blocked.

Restricted revisions require a high-entropy `__Host-p0v3_acceptance` cookie and return 503 otherwise, including for reads. Clients must set this as a secure, host-only, path-`/` cookie. Caddy credential logging must remain disabled. The control cookie is removed before proxying while application session cookies are preserved. Route revisions with no gate are low-level activation effects, not authority; there is no standalone CLI exposing an ungated cutover.

Implementation checked the cached Caddy 2.11.3 source for `PATCH`, root ETag comparison and header replacement semantics. This is source inspection, not a native compatibility run.

## RSS uncertain-send reconciliation

`MastodonRssSender.reconcile` resolves an already-attempted pending post using only GET requests. It requires an exact current outbox checksum, active (not staging/restore) mode and an explicit remote status ID. Under the state lock it verifies:

- the pinned feed/account and draft idempotency key;
- the token's actual bot identity;
- the remote status ID, owning account, public visibility and non-reblog status;
- creation within the attempted-send time window (two-minute clock-skew allowance);
- exact author-owned source text and empty spoiler text, without guessing from rendered HTML.

The source endpoint requires `read:statuses`; insufficient scopes are refused, not silently regenerated. A matching observation advances only that pending item's checkpoint and retains a checksummed reconciliation record. A 404, timeout, wrong identity/text, clock rollback or missing source does **not** clear the send claim or permit resubmission. This confirms observed delivery, not independent attribution of the original HTTP request to the server's idempotency cache.

Unclaimed drafts can no longer be acknowledged. Interrupted sends preserve the interrupt flag and the durable uncertain claim. RSS HTTP deadlines now include response-body completion. State files require current-user ownership and a single link. Empty reconciliation metadata is omitted from serialization, preserving old checksum/wire behavior. The existing state-size bound and a 256-record reconciliation bound fail closed rather than deleting history.

All nine packs/47 accounts, attribution, first-poll silence and checkpoints are unchanged. No feed poll, post or reconciliation touched real RSS state; the Washington Post checkpoint was not advanced. Installed RSS scheduling and whole-release publication integration still require implementation.

## Unit validation

Offline Java 21 `check jacocoTestReport --offline` passed for both changed repositories:

| Repository | Unit tests | Unit line coverage |
| --- | ---: | ---: |
| Platform | 279 passed; 0 skipped/failing | 6,386 / 7,045 = 90.65% |
| Acceptance | 51 passed; 0 skipped/failing | 1,102 / 1,127 = 97.78% |

Keykeeper and Worklane source did not change in this increment, so their suites were not redundantly rerun. Their preceding unit-line results remain 93.35% and 90.31%, respectively; these are not new executions. Python sources did not change and were not rerun. Native tests remain explicitly excluded.

Final logs are `/tmp/p0v3-activation-caddy-rss-final-platform.log` and `/tmp/p0v3-activation-caddy-rss-final-acceptance.log`. Positive authority and transport tests use synthetic private records and injected responses; subprocess tests run only test-owned local fixtures. These results do not qualify an installed controller or authorize publication.
