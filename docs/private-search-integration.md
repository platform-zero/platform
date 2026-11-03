# Private OpenSearch — real indexing, authorization and persistence

**`opensearch-r2` is running** OpenSearch 3.9.0 from its acquired immutable image. This adds one logical family: the private runtime now has **25 daemons across 22/39 families**, in thirteen systemd-enrolled deployments. This is component integration, not full-stack acceptance: **0/2**.

## Implementation

- `OpenSearchRuntime.kt`: a single-node deployment with journalled configuration and security initialization, UID/GID 1000, read-only image, dropped capabilities, no-new-privileges and the dedicated AppArmor profile.
- Two owned volumes hold configuration and index data. No host directories or ports are exposed.
- The security plugin remains **enabled**. No upstream demo installer, demo certificates, default users or password-based authentication is enabled.
- `PrivateSearchPki.kt` generates an independent private CA and signed node/operator certificates for each fresh preparation. TLS hostname verification remains enabled. No shared trust store is modified; private keys become protected runtime inputs/secrets, not command-line values or printed output.
- HTTP requires a client certificate. The operator certificate is privileged. The node's HTTP identity is restricted to cluster-health access and cannot read/write indexes through HTTP. **Its certificate also authenticates node transport, so it is not an end-user credential and must not be distributed as one.**
- The operator private key is mounted only into the initialization helper, not the running node.
- `node.store.allow_mmap: false` avoids changing shared-host `vm.max_map_count`. Heap is 512 MiB, container memory limit 2 GiB.
- Before security initialization, readiness permits only a verified TLS response explicitly reporting security uninitialized. After the successful security initializer writes its marker, readiness requires an authenticated successful cluster-health request.

The initial `opensearch` candidate failed because upstream JVM GC logging targeted a read-only image path. Its state was retained. The corrected fresh `opensearch-r2` recipe redirects that GC log into the private writable temporary directory. No changed recipe was silently applied over the failed candidate.

## Actual product tests

`platform/scripts/test-persistent-opensearch.py` performs native HTTPS API actions:

1. Verifies the server CA and `opensearch` hostname; confirms requests without client certificates fail TLS authentication.
2. Confirms the node identity can read cluster health but receives HTTP 403 for index creation and document search. The rejected index was not created.
3. Creates a real index with explicit text, integer and keyword mappings, then indexes three synthetic documents.
4. Executes a combined full-text/range query and verifies the precise hit and stored document content.
5. Deletes a document and verifies search results, document values and deletion after a clean stop/start.
6. Verifies initialization-journal bytes do not change on restart and index authorization remains enforced.

Passed receipts:

- `p0v3-search-c39ccc45807f`
- `p0v3-search-552f0f135daa`
- **`p0v3-search-b8dd4993f02b`**, after the expanded systemd lifecycle test

All receipts live under `/mnt/media/p0-v3/image-acquisition-receipts/`. Test data contains only synthetic text; no existing documents, accounts or workspaces were imported.

## Boot integration

`p0v3-private-opensearch-r2.service` is installed, enabled and active. It uses controller tree:

`0b5e802e0bee63cfe3b6edc4ac08d8803dbfa8d7a8965c47d71051378d864b95`

The earlier twelve units retain their original controller snapshot; they were **not silently upgraded**. The expanded lifecycle probe renders each unit using its own pinned controller, verifies unchanged unit/manifest bindings, and reenables existing units without trying to replace them with the current workspace build.

Receipt **`p0v3-boot-3259121b360d`** proves all thirteen units restarted **25 daemons**, preserving container identities, completed-initializer identities/start times and initialization journals. A real notebook execution/readback also passed. This did not reboot the shared host and is not a full-stack reinstall or restore.

## Reproduction

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./platform/gradlew -p platform check installDist --offline
CLI=platform/build/install/p0-v3-platform/bin/p0-v3-platform
$CLI runtime prepare-opensearch platform/release/downloaded-candidate-inventory.json opensearch-r2
$CLI runtime apply-private /mnt/media/p0-v3/runtime-deployments/opensearch-r2.json
python3 platform/scripts/test-persistent-opensearch.py
python3 platform/scripts/test-private-boot-supervision.py
```

An identical preparation preserves credentials; changing the recipe requires another deployment name or a future reviewed transactional update. The retained failed `opensearch` name is not silently reusable.

## Limits and remaining work

- This is not a clustered search deployment or public/end-user search service. Owner/agent identity integration remains unfinished.
- The certificates expire after 365 days. The temporary issuing key is discarded; renewal/rotation requires explicit reprovisioning and is not automated. This is private component PKI, not the production certificate lifecycle.
- Native OpenSearch snapshots, encrypted export, isolated cluster restoration and post-restore divergence tests are **not implemented or accepted**. Restart persistence is not a backup.
- The generic single-user restore adapter is not being presented as an OpenSearch database/cluster backup solution.
- OpenSearch 3.9 is **not substituted for Huly's Elasticsearch 7.14.2 dependency**.
- Seventeen selected families, other required integrations, public TLS, complete release orchestration and independent acceptance remain unfinished.

Latest platform Kotlin unit coverage: **2622/2837 lines, 92.42%**. PKI orchestration unit tests use a fake cryptographic command effect and verify cleanup/input selection; real certificate generation, TLS and search checks are separate integration evidence and do not inflate unit coverage.
