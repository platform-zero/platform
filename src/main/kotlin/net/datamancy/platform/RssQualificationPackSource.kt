package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.net.URI
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** C1-owned source: its 47 hashes bind immutable, generation-local fixture XML.
 * The real case-scoped loopback GET is rechecked against those bytes before any
 * fixture checkpoint; reviewed upstream URLs are identity metadata only. */
@Serializable internal data class RssQualificationFeedSource(val id: String, val account: String,
    val originalUrl: String, val path: String, val responseSha256: String)
@Serializable internal data class RssQualificationPackManifest(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val invocationId: String,
    val phaseClaimSha256: String, val pack: String, val feeds: List<RssQualificationFeedSource>)
@Serializable internal data class RssQualificationPackBinding(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val invocationId: String,
    val phaseClaimSha256: String, val host: String, val privateAddress: String,
    val caSha256: String, val servedLeafSha256: String, val feeds: List<RssQualificationFeedSource>,
    val originalManifestSha256: String) {
    fun validate(reviewed: List<ReviewedFeed>, generationId: String, bundle: String,
        caseId: String, phaseSha: String, address: String, ca: String, leaf: String) {
        val hash = Regex("[a-f0-9]{64}")
        require(schemaVersion == 1 && generation == generationId && bundleSha256 == bundle &&
            invocationId == caseId && phaseClaimSha256 == phaseSha && host == "social.datamancy.net" &&
            privateAddress == address && caSha256 == ca && servedLeafSha256 == leaf &&
            listOf(bundleSha256, phaseClaimSha256, caSha256, servedLeafSha256, originalManifestSha256).all(hash::matches) &&
            reviewed.size == 47 && reviewed.map { it.pack }.toSet().size == 9 &&
            reviewed.map { it.feed.account }.toSet().size == 47 && feeds.size == 47 &&
            feeds.map { it.id }.toSet() == reviewed.map { it.feed.id }.toSet()) {
            "Private RSS source must cover exactly the claimed original 47 reviewed identities"
        }
        for (feed in reviewed) {
            val entry = feeds.single { it.id == feed.feed.id }
            require(entry.account == feed.feed.account && entry.originalUrl == feed.feed.url &&
                entry.path == "/feed/pack/${feed.feed.id}" && hash.matches(entry.responseSha256)) {
                "Private RSS response does not belong to its reviewed source and account"
            }
        }
    }
}

/** Production-only loopback feed transport. Original Caddy issuer/address proof for
 * real Mastodon remains separately required; this never fetches a public RSS URL,
 * sends credentials/POST, follows a redirect or refetches on RESTORE. */
internal object RssQualificationPackSource {
    private val json = Json { ignoreUnknownKeys = false }
    private data class Case(val generation: Path, val caseId: String, val pack: String)
    private val current = ThreadLocal<Case?>()
    private val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private fun fixtureRoot(generation: String, caseId: String): Path =
        GenerationRuntime.BASE.resolve(generation).resolve("rss/qualification-pack-source/$caseId")

    /** Deterministic private *test content*, never an imported news story. All reviewed
     * identities are in the manifest; no upstream URL is dereferenced. Core alone
     * mounts these exact read-only files into its already owned private fixture service. */
    internal fun xml(feed: ReviewedFeed): ByteArray {
        require(feed in RssPacks.load())
        val id = feed.feed.id
        val account = feed.feed.account
        fun escape(value: String) = buildString {
            value.forEach { char -> append(when (char) {
                '&' -> "&amp;"; '<' -> "&lt;"; '>' -> "&gt;"; '"' -> "&quot;"; '\'' -> "&apos;"
                else -> char.toString()
            }) }
        }
        return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<rss version=\"2.0\"><channel><title>Private RSS qualification fixture</title>" +
            "<description>TEST FIXTURE, not external news; reviewed pack ${escape(feed.pack)}</description>" +
            "<item><guid>qualification-fixture-v1:$id</guid>" +
            "<title>Private qualification fixture: $id (not external news)</title>" +
            "<link>https://fixture.invalid/qualification/$id</link>" +
            "<description>TEST FIXTURE for ${escape(account)}; reviewed upstream identity " +
            "${escape(feed.feed.url)}; no upstream GET or publication</description></item>" +
            "</channel></rss>\n").toByteArray(Charsets.UTF_8)
    }

    /** Owner-held original INSTALL producer. A pending source/partial write is never
     * adopted or retried. The generation-local manifest pins immutable raw XML bytes
     * for all 47 reviewed IDs/accounts, independently of per-case feed-items.json. */
    fun produce(generation: GenerationBundle, bundleSha256: String, invocationId: String,
        phaseClaimSha256: String, pack: String): ActivationInput {
        val root = GenerationRuntime.BASE.resolve(generation.request.id)
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        val reviewed = RssPacks.load()
        require(generation.request.id.matches(Regex("q-[a-f0-9]{12}")) &&
            invocationId.matches(Regex("case-[a-f0-9-]{36}")) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            phaseClaimSha256.matches(Regex("[a-f0-9]{64}")) &&
            ReleaseLocks.sha256(bundleBytes) == bundleSha256 &&
            json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true)) == generation &&
            pack in reviewed.map { it.pack }.toSet() && reviewed.size == 47 &&
            reviewed.map { it.feed.account }.toSet().size == 47)
        val parent = root.resolve("rss/qualification-pack-source")
        val slot = fixtureRoot(generation.request.id, invocationId)
        ReleasePrivateFiles.directory(parent.parent)
        val intent = "private-rss-qualification-fixture-v1\n${generation.request.id}\n$bundleSha256\n$invocationId\n$phaseClaimSha256\n$pack\n"
        // This original-generation pre-effect fence exists BEFORE even the source
        // directory is made. An uncertain/partial attempt is never silently reused.
        ReleasePrivateFiles.save(root.resolve("rss/qualification-pack-source-$invocationId.intent"),
            intent.toByteArray(Charsets.UTF_8))
        if (!Files.exists(parent, NOFOLLOW_LINKS)) { Files.createDirectory(parent, mode); ReleasePrivateFiles.sync(parent.parent) }
        ReleasePrivateFiles.directory(parent)
        Files.createDirectory(slot, mode) // CREATE_NEW: no partial fixture adoption or re-issuance
        ReleasePrivateFiles.sync(parent)
        ReleasePrivateFiles.save(slot.resolve("source.intent"), intent.toByteArray(Charsets.UTF_8))
        val files = slot.resolve("feeds")
        Files.createDirectory(files, mode); ReleasePrivateFiles.sync(slot)
        val entries = reviewed.map { feed ->
            val bytes = xml(feed)
            require(bytes.size in 1..65536 && RssXml.parse(bytes, URI(feed.feed.url)).single().id ==
                "qualification-fixture-v1:${feed.feed.id}")
            ReleasePrivateFiles.save(files.resolve("${feed.feed.id}.xml"), bytes)
            RssQualificationFeedSource(feed.feed.id, feed.feed.account, feed.feed.url,
                "/feed/pack/${feed.feed.id}", ReleaseLocks.sha256(bytes))
        }
        val manifest = RssQualificationPackManifest(generation = generation.request.id,
            bundleSha256 = bundleSha256, invocationId = invocationId,
            phaseClaimSha256 = phaseClaimSha256, pack = pack, feeds = entries)
        val bytes = Json.encodeToString(RssQualificationPackManifest.serializer(), manifest).encodeToByteArray()
        val file = slot.resolve("manifest.json")
        ReleasePrivateFiles.save(file, bytes)
        return ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
    }

    /** C1's typed issuer. The 47 response hashes come only from the above
     * owner-produced original XML manifest, never from a client or context map.
     * The actual native GET still rechecks each SHA before checkpointing. */
    fun prepare(caseDir: Path, generation: GenerationBundle, bundleSha256: String,
        invocationId: String, phaseClaimSha256: String, privateAddress: String,
        caFile: Path, caSha256: String, leafSha256: String, pack: String,
        originalFixtureManifest: ActivationInput): ActivationInput {
        val root = GenerationRuntime.BASE.resolve(generation.request.id)
        require(caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            invocationId.matches(Regex("case-[a-f0-9-]{36}")) &&
            generation.members.size == 1 &&
            ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304).let { bytes ->
                ReleaseLocks.sha256(bytes) == bundleSha256 &&
                    json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true)) == generation
            } &&
            caFile == caseDir.resolve("private-ingress-ca.pem") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(caFile, 65536)) == caSha256)
        val reviewed = RssPacks.load()
        val original = fixtureRoot(generation.request.id, invocationId)
        val manifestFile = original.resolve("manifest.json")
        require(originalFixtureManifest.path == manifestFile.toString() &&
            originalFixtureManifest.sha256.matches(Regex("[a-f0-9]{64}")))
        val originalBytes = ReleasePrivateFiles.read(manifestFile, 65536)
        require(ReleaseLocks.sha256(originalBytes) == originalFixtureManifest.sha256)
        val manifest = json.decodeFromString<RssQualificationPackManifest>(
            originalBytes.decodeToString(throwOnInvalidSequence = true))
        require(manifest.schemaVersion == 1 && manifest.generation == generation.request.id &&
            manifest.bundleSha256 == bundleSha256 && manifest.invocationId == invocationId &&
            manifest.phaseClaimSha256 == phaseClaimSha256 && manifest.pack == pack &&
            manifest.feeds.size == 47 && manifest.feeds.map { it.id }.toSet() == reviewed.map { it.feed.id }.toSet() &&
            ReleasePrivateFiles.read(original.resolve("source.intent"), 1024).let { intent ->
                intent.contentEquals("private-rss-qualification-fixture-v1\n${generation.request.id}\n$bundleSha256\n$invocationId\n$phaseClaimSha256\n$pack\n".toByteArray(Charsets.UTF_8)) &&
                    ReleasePrivateFiles.read(root.resolve("rss/qualification-pack-source-$invocationId.intent"), 1024)
                        .contentEquals(intent)
            })
        for (feed in reviewed) {
            val entry = manifest.feeds.single { it.id == feed.feed.id }
            val bytes = ReleasePrivateFiles.read(original.resolve("feeds/${feed.feed.id}.xml"), 65536)
            require(entry.account == feed.feed.account && entry.originalUrl == feed.feed.url &&
                entry.path == "/feed/pack/${feed.feed.id}" &&
                ReleaseLocks.sha256(bytes) == entry.responseSha256 && bytes.contentEquals(xml(feed)))
        }
        val source = RssQualificationPackBinding(generation = generation.request.id,
            bundleSha256 = bundleSha256, invocationId = invocationId,
            phaseClaimSha256 = phaseClaimSha256, host = "social.datamancy.net",
            privateAddress = privateAddress, caSha256 = caSha256, servedLeafSha256 = leafSha256,
            feeds = manifest.feeds, originalManifestSha256 = originalFixtureManifest.sha256)
        source.validate(reviewed, generation.request.id, bundleSha256, invocationId,
            phaseClaimSha256, privateAddress, caSha256, leafSha256)
        val issuer = CanonicalCaddyServedLeafReadback(root, generation, bundleSha256,
            QualificationPrivateTls.selectedManifest(requireNotNull(generation.members.single().spec.fragmentBinding)))
        val proof = issuer.verify(source.host)
        val leaf = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(Path.of(proof.path), 8192)
            .decodeToString(throwOnInvalidSequence = true))
        require(leaf.servedLeafDerSha256 == leafSha256 && leaf.caSha256 == caSha256 &&
            issuer.verifiedPrivateEndpoint(source.host) == "https://$privateAddress:443")
        val directory = caseDir.resolve("owner-proofs")
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(directory)
        val file = directory.resolve("rss-pack-source.json")
        val bytes = Json.encodeToString(RssQualificationPackBinding.serializer(), source).encodeToByteArray()
        ReleasePrivateFiles.save(file, bytes) // create-new; never adopt a partial/foreign producer
        return ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
    }

    fun <T> withCase(stateRoot: Path, fixture: Path, pack: String, action: () -> T): T {
        val slot = fixture.parent
        require(current.get() == null && fixture.fileName.toString() == "feed-items.json" &&
            stateRoot == slot.resolve("state") && slot.parent.fileName.toString() == "rss-qualification" &&
            slot.fileName.toString().matches(Regex("(?:case-[a-f0-9-]{36}|rssq-[a-f0-9]{12})")) &&
            slot.parent.parent.parent == GenerationRuntime.BASE &&
            pack in RssPacks.load().map { it.pack }.toSet())
        current.set(Case(slot.parent.parent, slot.fileName.toString(), pack))
        try { return action() } finally { current.remove() }
    }
    private fun field(objectJson: kotlinx.serialization.json.JsonObject, key: String): String =
        requireNotNull(objectJson[key]) { "Missing private RSS pack source $key" }.jsonPrimitive.content

    fun fetch(feed: ReviewedFeed): List<FeedItem> {
        val reviewed = RssPacks.load()
        require(feed in reviewed)
        val selected = requireNotNull(current.get()) { "Private pack fetch requires a scoped native case" }
        val caseId = requireNotNull(System.getenv("P0V3_CASE_INVOCATION_ID"))
        val claimSha = requireNotNull(System.getenv("P0V3_RSS_QUALIFICATION_SHA256"))
        val phaseSha = requireNotNull(System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256"))
        require(caseId.matches(Regex("case-[a-f0-9-]{36}")) &&
            listOf(claimSha, phaseSha).all { it.matches(Regex("[a-f0-9]{64}")) })
        val generationId = selected.generation.fileName.toString()
        require(generationId.matches(Regex("q-[a-f0-9]{12}")) && selected.pack == feed.pack &&
            (selected.caseId == caseId || selected.caseId.startsWith("rssq-")))
        val root = selected.generation
        val claim = json.decodeFromString<RssQualificationIntent>(ReleasePrivateFiles.read(
            root.resolve("rss/qualification-intents/$caseId.intent.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(claim.schemaVersion == 1 && claim.phase == "INSTALL" && claim.generation == generationId &&
            claim.invocationId == caseId && claim.phaseClaimSha256 == phaseSha &&
            (claim.serviceId == "rss-pack-${feed.pack}" || feed.pack == "analysis" &&
                claim.serviceId in setOf("mastodon-rss-publisher", "rss-jobs")) &&
            claim.caseDirectory.startsWith("/") && ReleaseLocks.sha256(ReleasePrivateFiles.read(
                root.resolve("rss/qualification-intents/$caseId.intent.json"), 8192)) == claimSha) {
            "Pack GET requires an exact original phase/case claim"
        }
        val caseDir = Path.of(claim.caseDirectory)
        require(caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            caseDir.fileName.toString().startsWith("${claim.serviceId}--") &&
            (java.nio.file.Files.getAttribute(caseDir, "unix:uid") as Number).toLong() == UnixSystem().uid)
        val contextBytes = ReleasePrivateFiles.read(caseDir.resolve("context.json"), 4194304)
        require(ReleaseLocks.sha256(contextBytes) == claim.contextSha256)
        val context = json.parseToJsonElement(contextBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val sourceFile = caseDir.resolve("owner-proofs/rss-pack-source.json")
        require((if (selected.caseId == caseId) context["fixtureId"] == null else
            field(context, "fixtureId") == selected.caseId) &&
            field(context, "rssPackSourceFile") == sourceFile.toString())
        val sourceBytes = ReleasePrivateFiles.read(sourceFile, 65536)
        require(ReleaseLocks.sha256(sourceBytes) == field(context, "rssPackSourceSha256"))
        val source = json.decodeFromString<RssQualificationPackBinding>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        val address = field(context, "mastodonScopedAddress")
        val ca = field(context, "caSha256")
        val leaf = field(context, "sourceLeafSha256")
        source.validate(reviewed, generationId, claim.bundleSha256, caseId, phaseSha, address, ca, leaf)
        val original = fixtureRoot(generationId, caseId)
        val originalBytes = ReleasePrivateFiles.read(original.resolve("manifest.json"), 65536)
        require(ReleaseLocks.sha256(originalBytes) == source.originalManifestSha256)
        val manifest = json.decodeFromString<RssQualificationPackManifest>(originalBytes.decodeToString(throwOnInvalidSequence = true))
        require(manifest.schemaVersion == 1 && manifest.generation == generationId &&
            manifest.bundleSha256 == claim.bundleSha256 && manifest.invocationId == caseId &&
            manifest.phaseClaimSha256 == phaseSha && manifest.pack == feed.pack && manifest.feeds == source.feeds)
        val fixture = ReleasePrivateFiles.read(original.resolve("feeds/${feed.feed.id}.xml"), 65536)
        require(ReleaseLocks.sha256(fixture) == source.feeds.single { it.id == feed.feed.id }.responseSha256 &&
            fixture.contentEquals(xml(feed)))
        require(field(context, "bundleSha256") == claim.bundleSha256 &&
            field(context, "caFile") == caseDir.resolve("private-ingress-ca.pem").toString()) {
            "Private pack CA must be the current owner-copied case trust"
        }
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bundleBytes) == claim.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == generationId && bundle.members.size == 1)
        val issuer = CanonicalCaddyServedLeafReadback(root, bundle, claim.bundleSha256,
            QualificationPrivateTls.selectedManifest(requireNotNull(bundle.members.single().spec.fragmentBinding)))
        val receipt = issuer.verify(source.host)
        val observed = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(Path.of(receipt.path), 8192)
            .decodeToString(throwOnInvalidSequence = true))
        require(observed.servedLeafDerSha256 == leaf && observed.caSha256 == ca &&
            issuer.verifiedPrivateEndpoint(source.host) == "https://$address:443") {
            "Private RSS source changed its selected original Caddy CID/issuer"
        }
        val entry = source.feeds.single { it.id == feed.feed.id }
        val response = privateGet(source, entry, selected.caseId, feed.pack)
        require(ReleaseLocks.sha256(response) == entry.responseSha256) {
            "Private GET returned changed original fixture bytes"
        }
        return RssXml.parse(response, URI(feed.feed.url)).also { require(it.isNotEmpty()) }
    }

    private fun privateGet(source: RssQualificationPackBinding, entry: RssQualificationFeedSource,
        fixtureId: String, pack: String): ByteArray {
        require(entry.path == "/feed/pack/${entry.id}" &&
            entry.id.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")))
        val serverRoot = Path.of("/run/user/${UnixSystem().uid}/rss-fixtures")
            .resolve(source.generation).resolve(fixtureId)
        val planFile = serverRoot.resolve("server-plan.json")
        val planBytes = ReleasePrivateFiles.read(planFile, 65536)
        val raw = json.parseToJsonElement(planBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val plan = Json { ignoreUnknownKeys = true }.decodeFromString<RssNativeFixtureServerPlan>(
            planBytes.decodeToString(throwOnInvalidSequence = true))
        val manifest = fixtureRoot(source.generation, source.invocationId).resolve("manifest.json")
        require(plan.schemaVersion == 1 && plan.generation == source.generation &&
            plan.fixtureId == fixtureId && plan.pack == pack && plan.port in 49152..65535 &&
            plan.serverRoot == serverRoot.toString() &&
            field(raw, "packSourceManifestFile") == manifest.toString() &&
            field(raw, "packSourceManifestSha256") == source.originalManifestSha256 &&
            Path.of(plan.certificateAuthority) == serverRoot.resolve("fixture-ca.pem") &&
            Path.of(plan.keyStore) == serverRoot.resolve("fixture-keystore.p12") &&
            Path.of(plan.keyStorePasswordFile) == serverRoot.resolve("fixture-keystore.pass")) {
            "Private pack GET requires the exact case-owned feed-only TLS server and original manifest"
        }
        val keyBytes = ReleasePrivateFiles.read(Path.of(plan.keyStore), 65536)
        val passwordBytes = ReleasePrivateFiles.read(Path.of(plan.keyStorePasswordFile), 1024)
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(plan.certificateAuthority), 65536)) == plan.caSha256 &&
            ReleaseLocks.sha256(keyBytes) == plan.keyStoreSha256 &&
            ReleaseLocks.sha256(passwordBytes) == plan.keyStorePasswordSha256)
        val password = passwordBytes.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').toCharArray()
        val expectedLeaf = try {
            require(password.size in 24..256)
            val store = java.security.KeyStore.getInstance("PKCS12")
            keyBytes.inputStream().use { store.load(it, password) }
            val aliases = store.aliases()
            require(aliases.hasMoreElements())
            val alias = aliases.nextElement()
            require(!aliases.hasMoreElements())
            val certificate = store.getCertificate(alias) as java.security.cert.X509Certificate
            certificate.checkValidity()
            ReleaseLocks.sha256(certificate.encoded)
        } finally { password.fill('\u0000') }
        val origin = URI("https://127.0.0.1:${plan.port}")
        val reply = PinnedRssFixtureHttp(origin, Path.of(plan.certificateAuthority), plan.caSha256)
            .request("GET", origin.resolve(entry.path), mapOf("Accept" to "application/rss+xml"), "")
        require(reply.status == 200 && reply.peerLeafDerSha256 == expectedLeaf && reply.body.size in 1..65536 &&
            reply.headers["content-encoding"] in listOf(null, "", "identity")) {
            "Exact original private RSS XML fixture GET failed"
        }
        return reply.body
    }
}
