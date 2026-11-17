package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Sealed at PREPARED; a caller cannot substitute a different generation/site/configuration at activation. */
@Serializable data class ReleaseDeploymentBinding(val generationId: String, val bundleSha256: String,
    val sitePolicySha256: String, val restrictedConfigurationSha256: String) {
    fun validate() {
        require(generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            listOf(bundleSha256, sitePolicySha256, restrictedConfigurationSha256).all { it.matches(Regex("[a-f0-9]{64}")) }) {
            "Exact activation generation, bundle, site and restricted configuration required"
        }
    }
}

/** PREPARED update authority names the source and future generation, not an invented future bundle. */
@Serializable data class ReleaseUpdateBinding(val sourceGeneration: String, val sourceBundleSha256: String,
    val targetGeneration: String, val candidateSha256: String, val sitePolicySha256: String, val intentSha256: String) {
    fun validate() {
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) && targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            sourceGeneration != targetGeneration && listOf(sourceBundleSha256, candidateSha256, sitePolicySha256, intentSha256)
                .all { it.matches(Regex("[a-f0-9]{64}")) }) { "Exact immutable source/update intent required" }
    }
}

/** Native imported and migrated target observation. Caddy route digest is bound afterward,
 * never invented at PREPARED or smuggled through a caller's future deployment field.
 */
data class ReleaseStagedGeneration(val generationId: String, val bundleSha256: String, val sitePolicySha256: String) {
    fun validate() {
        require(generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            listOf(bundleSha256, sitePolicySha256).all { it.matches(Regex("[a-f0-9]{64}")) })
    }
}

interface ReleaseQualificationSnapshotEffects {
    /** Post-real-domain capture and qualified functional restore, distinct from pre-cutover rollback capture. */
    fun verifyQualificationSnapshot(): String
}

interface ReleaseUpdateEffects {
    /** Called once after snapshot verification and staged migration, before restricted cutover. */
    fun bindStagedDeployment(snapshotId: String): ReleaseDeploymentBinding
}

data class ReleaseActivationBinding(val transactionId: String, val lockDigest: String,
    val acceptedJournalHead: String, val deployment: ReleaseDeploymentBinding)

/**
 * Required activation authority, deliberately separate from staged/real-domain journey evaluation.
 * Production implementations must verify the current complete qualification history/evidence, identify
 * its second qualified installation, reobserve live bindings, and consume a single-use permit.
 * There is no permissive implementation or default callback. Unit doubles are not production authority.
 */
interface ReleaseActivationAuthorization {
    /** Read-only verification returns the SHA-256 of the exact permit to consume. */
    fun verify(binding: ReleaseActivationBinding): String
    /** Durable, single-use consumption before any public write, bound to the activation journal claim. */
    fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String)
}

/** Owned update selection is global durable site authority, not an activation callback receipt.
 * select MUST reread the retained consumed permit and exact second-cycle functional snapshot,
 * reserve all overlapping approved hosts under the global site registry lock, and CAS the
 * original active site head before any candidate public writes. No future COMMITTED digest
 * exists yet. finalize reads the real committed journal; failures after COMMITTED are NOT rollback.
 */
interface ReleaseActiveSiteAuthorization : ReleaseActivationAuthorization {
    fun select(binding: ReleaseActivationBinding, permitSha256: String,
        activationJournalHead: String, qualificationSnapshotId: String): String
    fun finalize(binding: ReleaseActivationBinding, committed: JournalRecord, selectionSha256: String)
}

@Serializable internal data class ActiveSiteHead(val ordinal: Int, val revisionSha256: String)
@Serializable internal data class ActiveSiteSelection(val schemaVersion: Int = 1, val ordinal: Int,
    val siteId: String, val hosts: List<String>, val deployment: ReleaseDeploymentBinding,
    val previousHeadSha256: String, val source: ReleaseGeneration,
    val transactionId: String, val activationJournalHead: String,
    val consumedPermitSha256: String, val consumptionSha256: String,
    val qualificationSnapshotId: String, val selectedTrialId: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val fresh: Boolean = false)
@Serializable internal data class ActiveSiteRouteObservation(val schemaVersion: Int = 1,
    val source: ReleaseGeneration, val siteId: String, val hosts: List<String>,
    val upstreams: List<CaddyUpstream>, val configurationSha256: String, val observedSlotSha256: String)
@Serializable internal data class ActiveSiteOperatorApproval(val schemaVersion: Int = 1,
    val source: ReleaseGeneration, val siteId: String, val hosts: List<String>,
    val sitePolicySha256: String, val sourceOwnershipSha256: String,
    val nativeInspectionSha256: String, val routeObservationSha256: String)
@Serializable internal data class ActiveSiteBootstrap(val schemaVersion: Int = 1,
    val approval: ActivationInput, val signature: ActivationInput,
    val nativeInspection: ActivationInput, val routeObservation: ActivationInput,
    val source: ReleaseGeneration, val siteId: String, val hosts: List<String>,
    val sitePolicySha256: String)
@Serializable internal data class ActiveSiteCompletion(val schemaVersion: Int = 1,
    val selectionSha256: String, val committedJournalHead: String, val transactionId: String,
    val target: ReleaseDeploymentBinding)

/** Read-only current-original provenance, never an activation or bootstrap receipt. */
@Serializable internal data class RestoredOriginalRouteAuthority(val source: ReleaseGeneration, val site: String,
    val approvedHosts: Set<String>, val sitePolicySha256: String,
    val head: ActivationInput, val origin: ActivationInput, val completion: ActivationInput?,
    val upstreams: List<CaddyUpstream>, val observedConfigurationSha256: String,
    val observedSlotSha256: String) {
    fun recheck() {
        fun exact(input: ActivationInput, maximum: Int) =
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(input.path), maximum)) == input.sha256
        val siteRoot = ActiveSiteRegistry.BASE.resolve(ReleaseLocks.sha256(site.toByteArray()))
        require(Path.of(head.path) == siteRoot.resolve("head.json") &&
            (if (completion == null) Path.of(origin.path) == Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/$site.route.json")
            else Path.of(completion.path).parent == siteRoot &&
                Path.of(completion.path).fileName.toString().matches(Regex("[a-f0-9]{64}\\.completed\\.json")) &&
                Path.of(origin.path).parent == Path.of("/mnt/media/p0-v3/caddy-transactions").resolve(site)) &&
            exact(head, 65536) && exact(origin, 1048576) &&
            (completion == null || exact(completion, 1048576)) &&
            upstreams.isNotEmpty() && upstreams.map { it.host }.toSet() == approvedHosts - "start.datamancy.net")
    }
}

/** The committed successor's actual public Caddy CAS, not the transaction request's
 * predecessor-upstream proposal, is parsed and compared to a regenerated exact route. */
internal fun originalSuccessorUpstreams(slot: JsonObject, source: ReleaseGeneration,
    owner: BoundSiteOwnership, pin: GenerationPin): List<CaddyUpstream> {
    val handler = slot.getValue("handle").jsonArray.single().jsonObject
    require(handler.getValue("handler") == JsonPrimitive("subroute"))
    val children = handler.getValue("routes").jsonArray.map { it.jsonObject }
    return (owner.approvedHosts - "start.datamancy.net").sorted().map { host ->
        val child = children.single { it["match"]?.jsonArray?.singleOrNull()?.jsonObject
            ?.get("host")?.jsonArray?.singleOrNull()?.jsonPrimitive?.content == host }
        val proxy = child.getValue("handle").jsonArray.single().jsonObject
        require(proxy.getValue("handler") == JsonPrimitive("reverse_proxy"))
        val dial = proxy.getValue("upstreams").jsonArray.single().jsonObject
            .getValue("dial").jsonPrimitive.content
        val route = owner.contract.routes.single { it.host == host }
        require(dial == "p0v3-live-${route.process.replace('/', '-')}:${route.port}" &&
            dial.startsWith("p0v3-live-${source.id}-"))
        val tls = proxy["transport"]?.jsonObject?.get("tls")?.jsonObject
        val ca = tls?.getValue("ca")?.jsonObject?.getValue("pem_files")?.jsonArray?.single()?.jsonPrimitive?.content
        val sha = ca?.let { target ->
            val file = pin.spec.processes.single { it.id == "caddy" }.files.single { it.target == target }
            requireNotNull(pin.inputHashes[file.file])
        }
        CaddyUpstream(host, dial, tls?.getValue("server_name")?.jsonPrimitive?.content,
            ca, sha, host == "notebooks.datamancy.net")
    }
}

/** Global per-site head, not a host-set key: a different site ID with overlapping hosts must
 * be refused under the SAME registry lock. A SELECTED head is pending/deny-by-default until
 * an independently verified matching COMMITTED journal and retained consumed permit exist.
 * Original installed sites need independently pinned bootstrap; a caller cannot create one.
 */
internal class ActiveSiteRegistry(private val root: Path, private val journal: Path?,
    private val siteId: String, private val approvedHosts: Set<String>, private val source: ReleaseGeneration?,
    private val consumption: Path?) {
    private fun journal(): Path = requireNotNull(journal) { "A real selected transaction journal is required" }
    private fun consumption(): Path = requireNotNull(consumption) { "A real selected consumption is required" }
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    private val host = Regex("[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+")
    private val site = root.resolve(ReleaseLocks.sha256(siteId.toByteArray()))
    private val sortedHosts = approvedHosts.sorted()
    init {
        require(root.isAbsolute && root.normalize() == root &&
            siteId.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            approvedHosts.isNotEmpty() && sortedHosts.size == approvedHosts.size &&
            sortedHosts.all { it.matches(host) && it.endsWith(".datamancy.net") && it != "datamancy.net" } &&
            ((journal == null && consumption == null) || (journal != null && consumption != null &&
                journal.isAbsolute && journal.normalize() == journal &&
                consumption.isAbsolute && consumption.normalize() == consumption &&
                consumption.parent == Path.of("/mnt/media/p0-v3/release-activation-consumptions") &&
                consumption.fileName.toString().matches(Regex("q-[a-f0-9]{12}\\.consumed\\.json")))))
    }
    companion object {
        val BASE: Path = Path.of("/mnt/media/p0-v3/release-transactions/active-sites")
        fun real(journal: Path, siteId: String, hosts: Set<String>, source: ReleaseGeneration,
            consumption: Path): ActiveSiteRegistry {
            require(journal.parent.parent == BASE.parent &&
                consumption.parent == Path.of("/mnt/media/p0-v3/release-activation-consumptions"))
            return ActiveSiteRegistry(BASE, journal, siteId, hosts, source, consumption)
        }
        fun realFresh(journal: Path, siteId: String, hosts: Set<String>, consumption: Path): ActiveSiteRegistry {
            require(journal.parent.parent == BASE.parent &&
                consumption.parent == Path.of("/mnt/media/p0-v3/release-activation-consumptions"))
            return ActiveSiteRegistry(BASE, journal, siteId, hosts, null, consumption)
        }
        /** Registry lock is acquired under the release controller root, BEFORE native/member
         * isolation. Ordinal zero has no journal or consumption; nothing is manufactured. */
        fun readOriginalRoutes(source: ReleaseGeneration, siteId: String, hosts: Set<String>,
            sitePolicySha256: String): RestoredOriginalRouteAuthority {
            source.validate()
            require(sitePolicySha256.matches(Regex("[a-f0-9]{64}")))
            val reader = ActiveSiteRegistry(BASE, null, siteId, hosts, source, null)
            return reader.locked { reader.readOriginalRoutesLocked(source, sitePolicySha256) }
        }
        /** Publication reads GLOBAL current owner, not the earlier source transaction's
         * locally committed journal. A superseded source therefore cannot tick. */
        fun requireActive(deployment: ReleaseDeploymentBinding, journal: Path, siteId: String,
            hosts: Set<String>): ActiveSiteSelection {
            require(journal.parent.parent == BASE.parent &&
                journal.fileName.toString() == "transaction.jsonl")
            val consumption = Path.of("/mnt/media/p0-v3/release-activation-consumptions")
                .resolve("${deployment.generationId}.consumed.json")
            return ActiveSiteRegistry(BASE, journal, siteId, hosts, null, consumption)
                .requireCommitted(deployment, requireCompleted = true)
        }
    }
    private fun externalBootstrap(path: Path): ActiveSiteBootstrap {
        ReleasePrivateFiles.directory(path)
        val bytes = ReleasePrivateFiles.read(path.resolve("bootstrap.json"))
        val bootstrap = json.decodeFromString<ActiveSiteBootstrap>(bytes.decodeToString())
        validateBootstrap(bootstrap, path)
        return bootstrap
    }
    /** Pure external Ed25519/old-native/route readback; reference readers may recheck this
     * under their own ledger lock without acquiring the global site lock out of order. */
    internal fun validateBootstrap(bootstrap: ActiveSiteBootstrap, path: Path) {
        require(bootstrap.schemaVersion == 1 && bootstrap.siteId.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            bootstrap.hosts.isNotEmpty() && bootstrap.hosts == bootstrap.hosts.distinct().sorted() &&
            path == root.resolve(ReleaseLocks.sha256(bootstrap.siteId.toByteArray())))
        bootstrap.source.validate()
        val base = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors")
        fun pinned(input: ActivationInput, path: Path): ByteArray {
            require(Path.of(input.path) == path)
            return ReleasePrivateFiles.read(path).also { require(ReleaseLocks.sha256(it) == input.sha256) }
        }
        val approvalBytes = pinned(bootstrap.approval, base.resolve("${bootstrap.siteId}.anchor.json"))
        val signatureBytes = pinned(bootstrap.signature, base.resolve("${bootstrap.siteId}.anchor.sig"))
        val publicKey = Base64.getDecoder().decode(ReleasePrivateFiles.read(base.resolve(
            "trusted-operator-ed25519.pub")).decodeToString().trim())
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(publicKey)))
        verifier.update(approvalBytes)
        require(verifier.verify(Base64.getDecoder().decode(signatureBytes.decodeToString().trim()))) {
            "Original active site lacks external operator signature; no invented old permit"
        }
        val approval = json.decodeFromString<ActiveSiteOperatorApproval>(approvalBytes.decodeToString())
        val nativeBytes = pinned(bootstrap.nativeInspection, base.resolve("${bootstrap.siteId}.native.json"))
        val routeBytes = pinned(bootstrap.routeObservation, base.resolve("${bootstrap.siteId}.route.json"))
        val observed = json.decodeFromString<GenerationInspection>(nativeBytes.decodeToString())
        val route = json.decodeFromString<ActiveSiteRouteObservation>(routeBytes.decodeToString())
        val sourceBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(bootstrap.source.id).resolve("bundle.json"))
        val original = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString())
        SiteOwnerships.checkSealed(original)
        val owner = requireNotNull(original.ownership)
        require(original.request.id == bootstrap.source.id &&
            ReleaseLocks.sha256(sourceBytes) == bootstrap.source.bundleSha256 &&
            original.request.store == RuntimeStore.CANONICAL_V2 && original.ownedUpdate == null &&
            original.recoverySourceKopia == null && original.recoverySourceArchiveSha256 == null &&
            approval.schemaVersion == 1 && approval.source == bootstrap.source && approval.siteId == bootstrap.siteId &&
            approval.hosts == bootstrap.hosts && approval.sitePolicySha256 == bootstrap.sitePolicySha256 &&
            approval.nativeInspectionSha256 == bootstrap.nativeInspection.sha256 &&
            approval.routeObservationSha256 == bootstrap.routeObservation.sha256 &&
            approval.sourceOwnershipSha256 == ReleaseLocks.sha256(json.encodeToString(owner.contract).toByteArray()) &&
            owner.contract.site == bootstrap.siteId && owner.approvedHosts.sorted() == bootstrap.hosts &&
            observed.id == bootstrap.source.id && observed.bundleSha256 == bootstrap.source.bundleSha256 &&
            observed.members.size == original.members.size && observed.members.zip(original.members).all { (audit, pin) ->
                audit.name == pin.member.name && audit.fingerprint == pin.runtimeFingerprint &&
                    audit.maintenanceId == null && audit.existingResources > 0 &&
                    pin.spec.processes.all { process -> audit.statuses.singleOrNull { it.id == process.id }?.let {
                        if (process.oneShot) it.state in setOf("completed", "exited") && it.exitCode == 0
                        else it.state == "running"
                    } == true }
            } && route.schemaVersion == 1 && route.source == bootstrap.source && route.siteId == bootstrap.siteId &&
            route.hosts == bootstrap.hosts && route.configurationSha256.matches(hash) &&
            route.observedSlotSha256.matches(hash) &&
            route.upstreams.map { it.host }.toSet() == owner.contract.routes.map { it.host }.toSet() &&
            route.upstreams.all { upstream -> owner.contract.routes.any { it.host == upstream.host &&
                upstream.dial == "p0v3-live-${it.process.replace('/', '-')}:${it.port}" } }) {
            "Historical site bootstrap differs from external approval, original state or native Caddy audit"
        }
    }
    private fun bootstrapAt(path: Path): Pair<ActiveSiteHead, ActiveSiteBootstrap> {
        val head = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(
            path.resolve("head.json")).decodeToString())
        val bootstrap = externalBootstrap(path)
        require(head.ordinal == 0 && head.revisionSha256 == ReleaseLocks.sha256(
            ReleasePrivateFiles.read(path.resolve("bootstrap.json"))))
        Files.list(path).use { files ->
            require(files.map { it.fileName.toString() }.toList().toSet() ==
                setOf("bootstrap.json", "head.json")) { "Historical bootstrap contains uncertain or foreign state" }
        }
        return head to bootstrap
    }
    /** Independently signed original-state seed. Only this explicit actor can create a missing
     * historical global head; its ordinal ZERO is never an invented activation permit. */
    fun bootstrapOriginal(bootstrap: ActiveSiteBootstrap) {
        require(root == BASE && source == bootstrap.source && siteId == bootstrap.siteId &&
            bootstrap.hosts == sortedHosts && bootstrap.sitePolicySha256.matches(hash))
        validateBootstrap(bootstrap, site) // Pure external approval + native/source graph before site effects.
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(site, NOFOLLOW_LINKS)) { "Original site already selected or bootstrap uncertain" }
            Files.list(root).use { members ->
                val others = members.filter { it.fileName.toString() != "control.lock" }.toList()
                require(others.size <= 128)
                for (other in others) require(currentHosts(other).none(sortedHosts::contains)) {
                    "Externally bootstrapped original overlaps an active or pending hostname"
                }
            }
            Files.createDirectory(site, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
            val bytes = json.encodeToString(bootstrap).toByteArray()
            ReleasePrivateFiles.save(site.resolve("bootstrap.json"), bytes)
            ReleasePrivateFiles.save(site.resolve("head.json"), json.encodeToString(
                ActiveSiteHead(0, ReleaseLocks.sha256(bytes))).toByteArray())
            require(bootstrapAt(site).second == bootstrap)
        }
    }
    /** Historical live-original authority, distinct from an activation selection. It cannot
     * authorize a candidate, mint a permit, or stand in for a COMMITTED site revision. */
    fun requireOriginalBootstrap(expectedSource: ReleaseGeneration, expectedSitePolicySha256: String,
        expectedHosts: Set<String>): ActiveSiteBootstrap = locked {
        require(root == BASE && source == expectedSource && expectedSource.id.isNotBlank() &&
            expectedSitePolicySha256.matches(hash) && expectedHosts.isNotEmpty() &&
            site == root.resolve(ReleaseLocks.sha256(siteId.toByteArray())))
        val (head, original) = bootstrapAt(site)
        require(head.ordinal == 0 && original.source == expectedSource && original.siteId == siteId &&
            original.hosts == sortedHosts && original.hosts.toSet() == expectedHosts &&
            original.sitePolicySha256 == expectedSitePolicySha256) {
            "Original RSS authority needs the exact externally approved, still-current ordinal-zero site"
        }
        Files.list(root).use { entries ->
            entries.filter { Files.isDirectory(it, NOFOLLOW_LINKS) && it != site }.forEach { other ->
                require(currentHosts(other).none { it in expectedHosts }) {
                    "Historical RSS bootstrap conflicts with another approved site"
                }
            }
        }
        original
    }
    private fun currentHosts(path: Path): List<String> =
        if (json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(path.resolve("head.json")).decodeToString()).ordinal == 0)
            bootstrapAt(path).second.hosts else current(path).second.hosts

    private fun <T> locked(block: () -> T): T {
        // Neither a publication read nor an owned selection can create missing legacy site
        // authority. Only an independently pinned bootstrap may create this registry root.
        // ReleaseDispatch holds controller/root lock before this global site-registry lock.
        ReleasePrivateFiles.directory(root)
        require(Files.isRegularFile(root.resolve("control.lock"), NOFOLLOW_LINKS)) {
            "Missing globally locked active-site bootstrap; deny publication"
        }
        return ReleasePrivateFiles.locked(root, block)
    }
    private fun revision(path: Path, pointer: ActiveSiteHead): ActiveSiteSelection {
        require(pointer.ordinal in 1..256 && pointer.revisionSha256.matches(hash))
        val bytes = ReleasePrivateFiles.read(path.resolve("rev-${pointer.ordinal}.json"), 1048576)
        require(ReleaseLocks.sha256(bytes) == pointer.revisionSha256) { "Active-site revision differs from global head" }
        return json.decodeFromString<ActiveSiteSelection>(bytes.decodeToString()).also {
            it.deployment.validate(); it.source.validate()
            require(it.schemaVersion == 1 && it.ordinal == pointer.ordinal &&
            (!it.fresh || it.ordinal == 1 && it.previousHeadSha256 == "0".repeat(64) &&
                it.source == ReleaseGeneration(it.deployment.generationId, it.deployment.bundleSha256)) &&
                it.siteId.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
                it.hosts == it.hosts.distinct().sorted() && it.hosts.isNotEmpty() &&
                it.hosts.all { h -> h.matches(host) && h.endsWith(".datamancy.net") } &&
                it.transactionId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
                it.previousHeadSha256.matches(hash) && it.activationJournalHead.matches(hash) &&
                it.consumedPermitSha256.matches(hash) && it.consumptionSha256.matches(hash) &&
                it.qualificationSnapshotId.matches(Regex("cap-[a-f0-9]{12}")) &&
                it.selectedTrialId.matches(Regex("[a-z][a-z0-9-]{0,95}")))
        }
    }
    private fun current(path: Path): Pair<ActiveSiteHead, ActiveSiteSelection> {
        ReleasePrivateFiles.directory(path)
        val head = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(path.resolve("head.json")).decodeToString())
        val record = revision(path, head)
        // Read every retained immutable revision, not only the mutable head: no old source
        // identity can be substituted underneath an apparently matching current owner.
        val anchored = Files.exists(path.resolve("bootstrap.json"), NOFOLLOW_LINKS)
        val initial = if (anchored) externalBootstrap(path).also { require(it.siteId == record.siteId) } else null
        var predecessor: ActiveSiteHead? = initial?.let { ActiveSiteHead(0, ReleaseLocks.sha256(
            ReleasePrivateFiles.read(path.resolve("bootstrap.json")))) }
        val known = mutableMapOf<String, ActiveSiteSelection>()
        for (index in 1..head.ordinal) {
            val bytes = ReleasePrivateFiles.read(path.resolve("rev-$index.json"), 1048576)
            val digest = ReleaseLocks.sha256(bytes)
            val entry = revision(path, ActiveSiteHead(index, digest))
            require(entry.siteId == record.siteId &&
                if (predecessor == null) entry.fresh && entry.previousHeadSha256 == "0".repeat(64)
                else entry.previousHeadSha256 == ReleaseLocks.sha256(
                    json.encodeToString(requireNotNull(predecessor)).toByteArray())) {
                "Global active-site history is not an exact immutable CAS chain"
            }
            known[digest] = entry
            predecessor = ActiveSiteHead(index, digest)
        }
        require(predecessor == head && known[head.revisionSha256] == record)
        // Orphan revisions or temporary CAS files are uncertain effects, not safe retry slots.
        Files.list(path).use { files ->
            val names = files.map { it.fileName.toString() }.toList()
            val revisions = names.filter { it.startsWith("rev-") && it.endsWith(".json") }
            require(names.contains("head.json") && revisions.size == head.ordinal &&
                revisions.toSet() == (1..head.ordinal).map { "rev-$it.json" }.toSet() &&
                names.all { it == "head.json" || anchored && it == "bootstrap.json" || it in revisions ||
                    it.matches(Regex("[a-f0-9]{64}\\.completed\\.json")) &&
                        it.removeSuffix(".completed.json") in known }) {
                "Active-site registry has an uncommitted or foreign record; reconcile before mutation"
            }
            for (name in names.filter { it.endsWith(".completed.json") }) {
                val selectedSha = name.removeSuffix(".completed.json")
                val original = known.getValue(selectedSha)
                val complete = json.decodeFromString<ActiveSiteCompletion>(ReleasePrivateFiles.read(
                    path.resolve(name), 1048576).decodeToString())
                val originalJournal = TransactionJournal.verify(BASE.parent.resolve(original.transactionId)
                    .resolve("transaction.jsonl")).last()
                require(complete.schemaVersion == 1 && complete.selectionSha256 == selectedSha &&
                    complete.target == original.deployment && complete.transactionId == original.transactionId &&
                    originalJournal.phase == Phase.COMMITTED && originalJournal.hash == complete.committedJournalHead &&
                    originalJournal.deployment == original.deployment &&
                    originalJournal.prevHash == original.activationJournalHead) {
                    "Retained site succession completion changed under current head"
                }
            }
        }
        return head to record
    }
    private fun readOriginalRoutesLocked(expected: ReleaseGeneration,
        sitePolicySha256: String): RestoredOriginalRouteAuthority {
        require(root == BASE && source == expected && journal == null && consumption == null &&
            Files.isDirectory(site, NOFOLLOW_LINKS))
        val sourceBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(expected.id).resolve("bundle.json"))
        require(ReleaseLocks.sha256(sourceBytes) == expected.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(bundle)
        val owner = requireNotNull(bundle.ownership)
        val pin = bundle.members.single()
        require(bundle.request.id == expected.id && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
            owner.contract.site == siteId && owner.approvedHosts == approvedHosts &&
            pin.spec.store == RuntimeStore.CANONICAL_V2 &&
            (pin.spec.ingress?.let { it.site == siteId && it.approvedHosts == approvedHosts } == true ||
                bundle.ownedUpdate != null && pin.spec.ingress == null && pin.spec.nativeIngress == null))
        if (bundle.ownedUpdate != null) OwnedReleaseUpdates.validate(bundle)
        val caddy: TransactionalCaddy
        val caddyPin: GenerationPin
        val binding: CaddySiteBinding
        val headPath = site.resolve("head.json")
        val headBytes = ReleasePrivateFiles.read(headPath, 65536)
        val head = json.decodeFromString<ActiveSiteHead>(headBytes.decodeToString(throwOnInvalidSequence = true))
        val origin: ActivationInput
        val completed: ActivationInput?
        val upstreams: List<CaddyUpstream>
        val expectedSlot: String
        val expectedConfiguration: String?
        if (head.ordinal == 0) {
            require(bundle.ownedUpdate == null && pin.spec.ingress != null)
            caddyPin = pin
            binding = CaddySiteBinding(siteId, "https", "http://127.0.0.1:2019", approvedHosts)
            caddy = TransactionalCaddy.inRuntime(Path.of("/mnt/media/p0-v3/caddy-transactions")
                .resolve(siteId), binding, caddyPin.spec, caddyPin.runtimeFingerprint)
            val (observedHead, bootstrap) = bootstrapAt(site)
            require(observedHead == head && bootstrap.source == expected && bootstrap.hosts == sortedHosts &&
                bootstrap.sitePolicySha256 == sitePolicySha256)
            val routeBytes = ReleasePrivateFiles.read(Path.of(bootstrap.routeObservation.path), 1048576)
            require(ReleaseLocks.sha256(routeBytes) == bootstrap.routeObservation.sha256)
            val route = json.decodeFromString<ActiveSiteRouteObservation>(routeBytes
                .decodeToString(throwOnInvalidSequence = true))
            require(route.source == expected && route.siteId == siteId && route.hosts == sortedHosts)
            origin = bootstrap.routeObservation
            completed = null
            upstreams = route.upstreams.filter { it.host != "start.datamancy.net" }
            expectedSlot = route.observedSlotSha256
            expectedConfiguration = route.configurationSha256
        } else {
            val (observedHead, selected) = current(site)
            for (ordinal in 1 until head.ordinal) {
                val priorBytes = ReleasePrivateFiles.read(site.resolve("rev-$ordinal.json"), 1048576)
                require(Files.isRegularFile(site.resolve("${ReleaseLocks.sha256(priorBytes)}.completed.json"),
                    NOFOLLOW_LINKS)) { "Superseded selection lacks retained completion" }
            }
            require(observedHead == head && selected.siteId == siteId && selected.hosts == sortedHosts &&
                selected.deployment.generationId == expected.id &&
                selected.deployment.bundleSha256 == expected.bundleSha256 &&
                selected.deployment.sitePolicySha256 == sitePolicySha256)
            val actualJournal = BASE.parent.resolve(selected.transactionId).resolve("transaction.jsonl")
            val actualConsumption = Path.of("/mnt/media/p0-v3/release-activation-consumptions")
                .resolve("${expected.id}.consumed.json")
            val currentOwner = ActiveSiteRegistry(BASE, actualJournal, siteId, approvedHosts, null, actualConsumption)
            require(currentOwner.committed(selected.deployment, true) == selected)
            val completionPath = site.resolve("${head.revisionSha256}.completed.json")
            val completionBytes = ReleasePrivateFiles.read(completionPath, 1048576)
            completed = ActivationInput(completionPath.toString(), ReleaseLocks.sha256(completionBytes))
            val requestPath = BASE.parent.resolve(selected.transactionId).resolve("request.json")
            val request = json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(requestPath)
                .decodeToString(throwOnInvalidSequence = true))
            binding = request.ingress.site
            val endpoint = requireNotNull(request.ingress.runtime)
            val publicSpec = ReleaseCaddyEndpoints.spec(request.ingress)
            val publicId = publicSpec.name.removeSuffix("-v2")
            require(publicSpec.name == "$publicId-v2" && publicId in setOf(expected.id, selected.source.id))
            val publicBundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(publicId).resolve("bundle.json"))
            val publicBundle = json.decodeFromString<GenerationBundle>(publicBundleBytes
                .decodeToString(throwOnInvalidSequence = true))
            SiteOwnerships.checkSealed(publicBundle)
            caddyPin = publicBundle.members.single { it.spec == publicSpec }
            require(publicBundle.request.id == publicId && caddyPin.spec.ingress?.site == siteId &&
                caddyPin.spec.ingress?.approvedHosts == approvedHosts &&
                caddyPin.runtimeFingerprint == endpoint.runtimeFingerprint &&
                caddyPin.manifestSha256 == endpoint.manifest.sha256)
            caddy = TransactionalCaddy.inRuntime(Path.of(request.ingress.root), binding,
                caddyPin.spec, caddyPin.runtimeFingerprint)
            require(request.transactionId == selected.transactionId &&
                request.ingress.root == "/mnt/media/p0-v3/caddy-transactions/$siteId" &&
                request.ingress.site == binding &&
                (request.deployment == selected.deployment || request.updatePreparation?.intent?.let {
                    it.targetGeneration == expected.id && it.sitePolicySha256 == sitePolicySha256 &&
                        it.source == selected.source
                } == true))
            val intentPath = Path.of(request.ingress.root).resolve("${request.ingress.activation}.intent.json")
            val intentBytes = ReleasePrivateFiles.read(intentPath, 1048576)
            val intent = json.decodeFromString<CaddyChangeIntent>(intentBytes
                .decodeToString(throwOnInvalidSequence = true))
            val result = json.decodeFromString<CaddyChangeResult>(ReleasePrivateFiles.read(
                Path.of(request.ingress.root).resolve("${request.ingress.activation}.result.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true))
            val slot = requireNotNull(intent.after)
            upstreams = originalSuccessorUpstreams(slot, expected, owner, caddyPin)
            val recreated = caddy.revision(request.ingress.activation, expected.id, upstreams, null)
            require(intent.schemaVersion == 1 && intent.operation == request.ingress.activation &&
                intent.bindingSha256 == ReleaseLocks.sha256(json.encodeToString(binding.copy(
                    approvedHosts = approvedHosts.toSortedSet())).toByteArray()) &&
                slot == recreated && result.operation == intent.operation && result.status == "applied" &&
                result.intentSha256 == ReleaseLocks.sha256(intentBytes) &&
                result.observedSlotSha256 == TransactionalCaddy.digest(slot))
            origin = ActivationInput(intentPath.toString(), ReleaseLocks.sha256(intentBytes))
            expectedSlot = requireNotNull(result.observedSlotSha256)
            expectedConfiguration = null // Later unrelated Caddy writes cannot silently replace the OWNED slot.
        }
        require(upstreams.map { it.host }.toSet() == approvedHosts - "start.datamancy.net" &&
            upstreams.size == approvedHosts.size - (if ("start.datamancy.net" in approvedHosts) 1 else 0) &&
            upstreams.all { route -> owner.contract.routes.any { contract ->
                contract.host == route.host && route.dial ==
                    "p0v3-live-${contract.process.replace('/', '-')}:${contract.port}"
            } })
        val sourceAudit = PrivateDeployment.real(mapOf(pin.spec.name to pin.runtimeFingerprint)).audit(pin.spec)
        require(sourceAudit.name == pin.spec.name && sourceAudit.fingerprint == pin.runtimeFingerprint &&
            sourceAudit.maintenanceId == null && pin.spec.processes.all { process ->
                sourceAudit.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true
            })
        val observation = PrivateDeployment.real(mapOf(caddyPin.spec.name to caddyPin.runtimeFingerprint))
            .audit(caddyPin.spec)
        require(observation.name == caddyPin.spec.name && observation.fingerprint == caddyPin.runtimeFingerprint &&
            observation.maintenanceId == null && caddyPin.spec.processes.all { process ->
                observation.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true
            })
        upstreams.forEach { auditNativeUpstreamCa(caddyPin.spec, it) }
        val (nativeConfiguration, nativeSlot) = caddy.observeOriginalRoute()
        require(nativeSlot == expectedSlot && (expectedConfiguration == null ||
            nativeConfiguration == expectedConfiguration) &&
            ReleasePrivateFiles.read(headPath, 65536).contentEquals(headBytes))
        Files.list(root).use { entries ->
            val other = entries.filter { it != site && it.fileName.toString() != "control.lock" }.toList()
            require(other.size <= 128 && other.all { Files.isDirectory(it, NOFOLLOW_LINKS) })
            other.forEach { require(currentHosts(it).none { host -> host in approvedHosts }) }
        }
        return RestoredOriginalRouteAuthority(expected, siteId, approvedHosts, sitePolicySha256,
            ActivationInput(headPath.toString(), ReleaseLocks.sha256(headBytes)), origin, completed,
            upstreams, nativeConfiguration, expectedSlot).also { it.recheck() }
    }
    /** Read-only admission BEFORE consuming the new activation permit: an old site cannot
     * be inferred from caller source pins or fabricated from an absent legacy registry.
     */
    fun admitOriginal(candidate: ReleaseDeploymentBinding) = locked {
        val original = requireNotNull(source).also { it.validate() }
        val pendingHead = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(
            site.resolve("head.json")).decodeToString())
        if (pendingHead.ordinal == 0) {
            val (head, anchored) = bootstrapAt(site)
            require(head == pendingHead && anchored.siteId == siteId && anchored.hosts == sortedHosts &&
                anchored.source == original && anchored.sitePolicySha256 == candidate.sitePolicySha256 &&
                candidate.generationId != original.id)
            Files.list(root).use { members ->
                val others = members.filter { it != site && it.fileName.toString() != "control.lock" }.toList()
                require(others.size <= 128)
                for (other in others) require(currentHosts(other).none(sortedHosts::contains))
            }
            return@locked
        }
        val (head, previous) = current(site)
        require(root == BASE && head.revisionSha256.matches(hash) &&
            previous.siteId == siteId && previous.hosts == sortedHosts &&
            previous.deployment.generationId == original.id &&
            previous.deployment.bundleSha256 == original.bundleSha256 &&
            previous.deployment.sitePolicySha256 == candidate.sitePolicySha256 &&
            previous.deployment.generationId != candidate.generationId)
        val priorJournal = BASE.parent.resolve(previous.transactionId).resolve("transaction.jsonl")
        val record = TransactionJournal.verify(priorJournal).last()
        require(record.phase == Phase.COMMITTED && record.deployment == previous.deployment &&
            record.prevHash == previous.activationJournalHead &&
            record.activationPermitSha256 == previous.consumedPermitSha256)
        val oldConsumption = ReleasePrivateFiles.read(Path.of("/mnt/media/p0-v3/release-activation-consumptions")
            .resolve("${previous.deployment.generationId}.consumed.json"))
        val priorPermit = json.parseToJsonElement(oldConsumption.decodeToString()).jsonObject
        val claim = priorPermit.getValue("consumption").jsonObject
        require(ReleaseLocks.sha256(oldConsumption) == previous.consumptionSha256 &&
            claim.getValue("generation") == JsonPrimitive(previous.deployment.generationId) &&
            claim.getValue("permitSha256") == JsonPrimitive(previous.consumedPermitSha256) &&
            claim.getValue("activationJournalHead") == JsonPrimitive(previous.activationJournalHead) &&
            priorPermit.getValue("permit").jsonObject.getValue("snapshotId") == JsonPrimitive(previous.qualificationSnapshotId)) {
            "Original site record lacks independently retained activation consumption"
        }
        val completion = json.decodeFromString<ActiveSiteCompletion>(ReleasePrivateFiles.read(
            site.resolve("${head.revisionSha256}.completed.json")).decodeToString())
        require(completion.selectionSha256 == head.revisionSha256 && completion.committedJournalHead == record.hash &&
            completion.target == previous.deployment)
        Files.list(root).use { members ->
            val otherSites = members.filter { it != site && it.fileName.toString() != "control.lock" }.toList()
            require(otherSites.size <= 128)
            for (other in otherSites) require(currentHosts(other).none(sortedHosts::contains)) {
                "Another active or pending site owns an original hostname"
            }
        }
    }
    private fun consumed(binding: ReleaseActivationBinding, permit: String, activationHead: String,
        qualification: String): Pair<String, String> {
        val journal = journal(); val consumption = consumption()
        require(consumption == Path.of("/mnt/media/p0-v3/release-activation-consumptions")
            .resolve("${binding.deployment.generationId}.consumed.json"))
        val bytes = ReleasePrivateFiles.read(consumption, 4 * 1024 * 1024)
        val retained = json.parseToJsonElement(bytes.decodeToString()).jsonObject
        require(retained.keys == setOf("permit", "consumption", "claimJournal"))
        val entry = retained.getValue("consumption").jsonObject
        require(entry.getValue("generation") == JsonPrimitive(binding.deployment.generationId) &&
            entry.getValue("permitSha256") == JsonPrimitive(permit) &&
            entry.getValue("activationJournalHead") == JsonPrimitive(activationHead) &&
            entry.getValue("claimJournalSha256") == JsonPrimitive(ReleaseLocks.sha256(ReleasePrivateFiles.read(journal, 1048576))) &&
            retained.getValue("claimJournal").jsonPrimitive.content == ReleasePrivateFiles.read(journal, 1048576).decodeToString()) {
            "Site selection requires actual durable consumed activation and matching journal bytes"
        }
        val sealed = retained.getValue("permit").jsonObject
        val permitBinding = sealed.getValue("binding").jsonObject
        require(ReleaseLocks.sha256(sealed.toString().toByteArray()) == permit &&
            sealed.getValue("snapshotId") == JsonPrimitive(qualification) &&
            permitBinding.getValue("transactionId") == JsonPrimitive(binding.transactionId) &&
            permitBinding.getValue("lockDigest") == JsonPrimitive(binding.lockDigest) &&
            permitBinding.getValue("acceptedJournalHead") == JsonPrimitive(binding.acceptedJournalHead) &&
            permitBinding.getValue("deployment") == json.encodeToJsonElement(binding.deployment) &&
            sealed.getValue("candidate").jsonObject.getValue("sitePolicySha256") == JsonPrimitive(binding.deployment.sitePolicySha256)) {
            "Qualified second installation or candidate deployment differs"
        }
        val selected = sealed.getValue("secondTrialId").jsonPrimitive.content
        val evaluations = sealed.getValue("evaluationHashes").jsonObject
        require(selected.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            evaluations.size >= 2 && selected in evaluations)
        return ReleaseLocks.sha256(bytes) to selected
    }
    /** Read-only first-install admission never bootstraps an old site or an unobserved route. */
    fun admitFresh(candidate: ReleaseDeploymentBinding) {
        require(source == null && root == BASE && candidate.generationId.matches(Regex("q-[a-f0-9]{12}")))
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(root.parent)
            return
        }
        locked {
            require(!Files.exists(site, NOFOLLOW_LINKS)) { "This site has an active or uncertain owner" }
            Files.list(root).use { members ->
                val entries = members.filter { it.fileName.toString() != "control.lock" }.toList()
                require(entries.size <= 128)
                for (other in entries) require(current(other).second.hosts.none(sortedHosts::contains)) {
                    "An active or pending other site owns a first-install hostname"
                }
            }
        }
    }
    private fun selectFresh(binding: ReleaseActivationBinding, permitSha256: String, activationHead: String,
        qualificationSnapshotId: String): String {
        val journal = journal()
        binding.deployment.validate()
        require(source == null && root == BASE && journal.parent.parent == BASE.parent &&
            binding.transactionId == journal.parent.fileName.toString() &&
            listOf(permitSha256, activationHead).all { it.matches(hash) } &&
            qualificationSnapshotId.matches(Regex("cap-[a-f0-9]{12}")))
        val history = TransactionJournal.verify(journal)
        val claim = history.last()
        require(claim.phase == Phase.ACTIVATION_STARTED && claim.hash == activationHead &&
            claim.prevHash == binding.acceptedJournalHead && claim.deployment == binding.deployment &&
            claim.activationPermitSha256 == permitSha256 && claim.transactionId == binding.transactionId &&
            claim.update == null && history[history.size - 2].qualificationSnapshotId == qualificationSnapshotId) {
            "Fresh site selection needs one actual first-install activation claim"
        }
        val (consumptionSha, trialId) = consumed(binding, permitSha256, activationHead, qualificationSnapshotId)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(root.parent)
            Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        return ReleasePrivateFiles.locked(root) {
            require(!Files.exists(site, NOFOLLOW_LINKS)) { "First-install site has prior or uncertain authority" }
            Files.list(root).use { members ->
                val entries = members.filter { it.fileName.toString() != "control.lock" }.toList()
                require(entries.size <= 128)
                for (other in entries) require(current(other).second.hosts.none(sortedHosts::contains)) {
                    "Competing active or pending site owns a first-install hostname"
                }
            }
            val target = ReleaseGeneration(binding.deployment.generationId, binding.deployment.bundleSha256)
            val bytes = json.encodeToString(ActiveSiteSelection(ordinal = 1, siteId = siteId, hosts = sortedHosts,
                deployment = binding.deployment, previousHeadSha256 = "0".repeat(64), source = target,
                transactionId = binding.transactionId, activationJournalHead = activationHead,
                consumedPermitSha256 = permitSha256, consumptionSha256 = consumptionSha,
                qualificationSnapshotId = qualificationSnapshotId, selectedTrialId = trialId, fresh = true)).toByteArray()
            Files.createDirectory(site, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
            ReleasePrivateFiles.save(site.resolve("rev-1.json"), bytes)
            val digest = ReleaseLocks.sha256(bytes)
            ReleasePrivateFiles.save(site.resolve("head.json"), json.encodeToString(ActiveSiteHead(1, digest)).toByteArray())
            digest
        }
    }
    fun select(binding: ReleaseActivationBinding, permitSha256: String, activationHead: String,
        qualificationSnapshotId: String): String = if (source == null) selectFresh(binding, permitSha256,
            activationHead, qualificationSnapshotId) else locked {
        val journal = journal()
        binding.deployment.validate()
        val original = requireNotNull(source).also { it.validate() }
        require(root == BASE && journal.parent.parent == BASE.parent &&
            binding.transactionId == journal.parent.fileName.toString() &&
            listOf(permitSha256, activationHead).all { it.matches(hash) } &&
            binding.deployment.generationId != original.id &&
            qualificationSnapshotId.matches(Regex("cap-[a-f0-9]{12}")))
        val history = TransactionJournal.verify(journal)
        val claim = history.last()
        require(claim.phase == Phase.ACTIVATION_STARTED && claim.hash == activationHead &&
            claim.prevHash == binding.acceptedJournalHead && claim.deployment == binding.deployment &&
            claim.activationPermitSha256 == permitSha256 && claim.transactionId == binding.transactionId &&
            claim.update?.sourceGeneration == original.id && claim.update?.sourceBundleSha256 == original.bundleSha256 &&
            claim.update?.sitePolicySha256 == binding.deployment.sitePolicySha256 &&
            history[history.size - 2].qualificationSnapshotId == qualificationSnapshotId) {
            "Global site selection requires actual late-bound owned activation claim"
        }
        val (consumptionSha, trialId) = consumed(binding, permitSha256, activationHead, qualificationSnapshotId)
        val priorHead = json.decodeFromString<ActiveSiteHead>(ReleasePrivateFiles.read(
            site.resolve("head.json")).decodeToString())
        val prior = if (priorHead.ordinal == 0) {
            val (head, bootstrap) = bootstrapAt(site)
            require(head == priorHead && bootstrap.siteId == siteId && bootstrap.hosts == sortedHosts &&
                bootstrap.source == original && bootstrap.sitePolicySha256 == binding.deployment.sitePolicySha256) {
                "Owned source is not the independently signed original site"
            }
            head
        } else {
            val (head, previous) = current(site)
            require(previous.siteId == siteId && previous.hosts == sortedHosts &&
                previous.deployment.generationId == original.id && previous.deployment.bundleSha256 == original.bundleSha256 &&
                previous.deployment.sitePolicySha256 == binding.deployment.sitePolicySha256) {
                "Owned update source is not the globally active original site"
            }
            head
        }
        Files.list(root).use { members ->
            val entries = members.filter { it != site && it.fileName.toString() != "control.lock" }.toList()
            require(entries.size <= 128)
            for (other in entries) {
                require(currentHosts(other).none(sortedHosts::contains)) {
                    "Overlapping active or pending site owns approved hostname"
                }
            }
        }
        val ordinal = Math.addExact(prior.ordinal, 1)
        val priorBytes = ReleasePrivateFiles.read(site.resolve("head.json"), 1048576)
        val selected = ActiveSiteSelection(ordinal = ordinal, siteId = siteId, hosts = sortedHosts,
            deployment = binding.deployment, previousHeadSha256 = ReleaseLocks.sha256(priorBytes), source = original,
            transactionId = binding.transactionId, activationJournalHead = activationHead,
            consumedPermitSha256 = permitSha256, consumptionSha256 = consumptionSha,
            qualificationSnapshotId = qualificationSnapshotId, selectedTrialId = trialId)
        val bytes = json.encodeToString(selected).toByteArray()
        val digest = ReleaseLocks.sha256(bytes)
        ReleasePrivateFiles.save(site.resolve("rev-$ordinal.json"), bytes)
        require(ReleasePrivateFiles.read(site.resolve("head.json")).contentEquals(priorBytes))
        val replacement = json.encodeToString(ActiveSiteHead(ordinal, digest)).toByteArray()
        val temporary = site.resolve("head-$ordinal.pending.json")
        ReleasePrivateFiles.save(temporary, replacement)
        Files.move(temporary, site.resolve("head.json"), ATOMIC_MOVE, REPLACE_EXISTING)
        ReleasePrivateFiles.sync(site)
        digest
    }
    fun finalize(binding: ReleaseActivationBinding, committed: JournalRecord, selectionSha256: String) = locked {
        val journal = journal()
        require(root == BASE && selectionSha256.matches(hash))
        val (head, selected) = current(site)
        require(head.revisionSha256 == selectionSha256 && selected.transactionId == binding.transactionId &&
            selected.deployment == binding.deployment &&
            (selected.source == source || source == null && selected.fresh &&
                selected.source == ReleaseGeneration(binding.deployment.generationId, binding.deployment.bundleSha256)))
        val last = TransactionJournal.verify(journal).last()
        require(last == committed && last.phase == Phase.COMMITTED &&
            last.prevHash == selected.activationJournalHead && last.deployment == selected.deployment &&
            last.activationPermitSha256 == selected.consumedPermitSha256)
        val (consumptionSha, trialId) = consumedAfterCommit(binding, selected)
        require(consumptionSha == selected.consumptionSha256 && trialId == selected.selectedTrialId)
        val result = ActiveSiteCompletion(selectionSha256 = selectionSha256, committedJournalHead = last.hash,
            transactionId = binding.transactionId, target = binding.deployment)
        ReleasePrivateFiles.save(site.resolve("$selectionSha256.completed.json"), json.encodeToString(result).toByteArray())
    }
    /** Used by RSS publication and old-site retirement. A selection alone is NEVER live
     * authority; an exact COMMITTED journal and unmodified retained consumed permit must be
     * independently observed under the global overlap lock. Final completion is separate.
     */
    fun requireCommitted(expectedTarget: ReleaseDeploymentBinding, requireCompleted: Boolean = false): ActiveSiteSelection =
        locked { committed(expectedTarget, requireCompleted) }
    private fun committed(expectedTarget: ReleaseDeploymentBinding, requireCompleted: Boolean): ActiveSiteSelection {
        val journal = journal()
        val (head, selected) = current(site)
        require(root == BASE && selected.siteId == siteId && selected.hosts == sortedHosts &&
            head.revisionSha256.matches(hash) && selected.deployment == expectedTarget &&
            (source == null || selected.source == source) &&
            selected.transactionId == journal.parent.fileName.toString())
        val history = TransactionJournal.verify(journal)
        val last = history.last()
        require(last.phase == Phase.COMMITTED && last.deployment == expectedTarget &&
            last.prevHash == selected.activationJournalHead &&
            last.activationPermitSha256 == selected.consumedPermitSha256 &&
            history.any { it.phase == Phase.ACTIVATION_STARTED && it.hash == selected.activationJournalHead } &&
            history.any { it.phase == Phase.ACCEPTED && it.qualificationSnapshotId == selected.qualificationSnapshotId }) {
            "Pending, uncertain or foreign site selection is not committed authority"
        }
        val accepted = history.single { it.phase == Phase.ACCEPTED }
        val binding = ReleaseActivationBinding(selected.transactionId, last.lockDigest, accepted.hash, expectedTarget)
        val (digest, trial) = consumedAfterCommit(binding, selected)
        require(digest == selected.consumptionSha256 && trial == selected.selectedTrialId)
        if (requireCompleted) {
            val result = json.decodeFromString<ActiveSiteCompletion>(ReleasePrivateFiles.read(
                site.resolve("${head.revisionSha256}.completed.json")).decodeToString())
            require(result.schemaVersion == 1 && result.selectionSha256 == head.revisionSha256 &&
                result.committedJournalHead == last.hash && result.transactionId == selected.transactionId &&
                result.target == expectedTarget)
        }
        return selected
    }
    private fun consumedAfterCommit(binding: ReleaseActivationBinding, selected: ActiveSiteSelection): Pair<String, String> {
        val bytes = ReleasePrivateFiles.read(consumption(), 4 * 1024 * 1024)
        val retained = json.parseToJsonElement(bytes.decodeToString()).jsonObject
        val record = retained.getValue("consumption").jsonObject
        val permit = retained.getValue("permit").jsonObject
        require(record.getValue("generation") == JsonPrimitive(binding.deployment.generationId) &&
            record.getValue("permitSha256") == JsonPrimitive(selected.consumedPermitSha256) &&
            record.getValue("activationJournalHead") == JsonPrimitive(selected.activationJournalHead) &&
            record.getValue("claimJournalSha256") == JsonPrimitive(
                ReleaseLocks.sha256(retained.getValue("claimJournal").jsonPrimitive.content.toByteArray())) &&
            ReleaseLocks.sha256(permit.toString().toByteArray()) == selected.consumedPermitSha256 &&
            permit.getValue("snapshotId") == JsonPrimitive(selected.qualificationSnapshotId) &&
            permit.getValue("secondTrialId") == JsonPrimitive(selected.selectedTrialId) &&
            permit.getValue("binding").jsonObject.getValue("deployment") == json.encodeToJsonElement(binding.deployment))
        return ReleaseLocks.sha256(bytes) to retained.getValue("permit").jsonObject.getValue("secondTrialId").jsonPrimitive.content
    }
}
