package net.datamancy.platform

import java.net.URI
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Original feature custody, not an imported legacy account or publication permit.
 * The 47 subjects are exactly the identities in the nine sealed reviewed packs. */
@Serializable internal data class QualificationRssFeatureLedger(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val candidateSha256: String,
    val invocationId: String, val phaseClaimSha256: String, val pack: String,
    val originalManifestSha256: String, val packFeedIds: Map<String, List<String>>,
    val accountTokenSha256: Map<String, String>)

internal object QualificationRssCaseInputs {
    private val hash = Regex("[a-f0-9]{64}")
    private val cases = setOf("mastodon-rss-publisher", "rss-jobs", "rss-pack-analysis",
        "rss-pack-aus", "rss-pack-aus-state", "rss-pack-china", "rss-pack-china-state",
        "rss-pack-tas", "rss-pack-us", "rss-pack-us-state", "rss-pack-world")
    private fun field(context: JsonObject, name: String): String =
        requireNotNull(context[name]) { "Missing original RSS fixture custody $name" }.jsonPrimitive.content

    /** Pure checks for the only approved original 47-identity/nine-pack feature shape. */
    internal fun validate(ledger: QualificationRssFeatureLedger, feeds: List<ReviewedFeed>,
        generation: String, bundle: String, candidate: String, invocation: String, phase: String,
        pack: String, manifest: String) {
        val packs = feeds.groupBy { it.pack }.mapValues { (_, entries) -> entries.map { it.feed.id } }
        require(ledger.schemaVersion == 1 && ledger.generation == generation &&
            ledger.bundleSha256 == bundle && ledger.candidateSha256 == candidate &&
            ledger.invocationId == invocation && ledger.phaseClaimSha256 == phase &&
            ledger.pack == pack && ledger.originalManifestSha256 == manifest &&
            listOf(bundle, candidate, phase, manifest).all(hash::matches) &&
            feeds.size == 47 && packs.size == 9 && feeds.map { it.feed.account }.toSet().size == 47 &&
            ledger.packFeedIds == packs && ledger.accountTokenSha256.keys ==
                feeds.map { it.feed.account }.toSet() && ledger.accountTokenSha256.values.all(hash::matches) &&
            ledger.accountTokenSha256.values.toSet().size == 47) {
            "Original RSS feature must have all nine reviewed packs and 47 distinct real token subjects"
        }
    }

    /** C1 passes only sealed native owner inputs, after its selected social Caddy
     * CA/leaf/address proof and the already admitted owner-held RSS phase claim.
     * No server is started here: its real PID/port/serving readback belongs to the
     * later case-owned runner's fsynced child plan, never a prestart guess. */
    fun issue(caseDir: Path, generation: GenerationBundle, bundleSha256: String,
        serviceId: String, surface: String, variant: String, phase: String,
        invocationId: String, phaseClaimSha256: String, originalContext: JsonObject,
        ca: ActivationInput, servedLeafSha256: String, ingressControlAddress: String): Map<String, JsonElement> {
        require(serviceId in cases && surface == "HEADLESS" && variant == "NATIVE" && phase == "INSTALL" &&
            caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            caseDir.fileName.toString() == "$serviceId--workflow--headless--native" &&
            invocationId.matches(Regex("case-[a-f0-9-]{36}")) && hash.matches(phaseClaimSha256) &&
            hash.matches(bundleSha256) && hash.matches(generation.request.candidateSha256) &&
            hash.matches(servedLeafSha256) && hash.matches(ca.sha256) &&
            generation.request.id.matches(Regex("q-[a-f0-9]{12}")) &&
            generation.request.rssPlan != null && generation.request.recoveredRssPlan == null &&
            generation.recoverySourceKopia == null &&
            ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(generation.request.id)
                .resolve("bundle.json"), 4194304).let { bytes ->
                ReleaseLocks.sha256(bytes) == bundleSha256 &&
                    Json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true)) == generation
            } &&
            ca.path == caseDir.resolve("private-ingress-ca.pem").toString() &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(ca.path), 65536)) == ca.sha256 &&
            RssControllerPayloads.authorized(generation, generation.request.id,
                GenerationRuntime.BASE.resolve(generation.request.id))) {
            "Original INSTALL-only RSS producer requires the sealed selected generation and issuer"
        }
        val pack = if (serviceId in setOf("mastodon-rss-publisher", "rss-jobs")) "analysis"
            else serviceId.removePrefix("rss-pack-")
        val feeds = RssPacks.load()
        require(pack in feeds.map { it.pack }.toSet() && feeds.size == 47 &&
            feeds.map { it.feed.account }.toSet().size == 47)
        val fixtureId = if (serviceId.startsWith("rss-pack-")) invocationId else field(originalContext, "fixtureId")
        require(fixtureId.matches(Regex(if (serviceId.startsWith("rss-pack-"))
            "case-[a-f0-9-]{36}" else "rssq-[a-f0-9]{12}")) &&
            (if (serviceId.startsWith("rss-pack-")) originalContext["fixtureId"] == null
             else field(originalContext, "fixtureSyntheticAccount").matches(Regex("rssq_[a-f0-9]{12}"))))
        // Real existing feed-only TLS custody, not a fabricated C1 server plan or
        // a public Mastodon issuer: the eventual case child copies these bytes once.
        val origin = URI(field(originalContext, "fixtureOrigin"))
        require(origin.scheme == "https" && origin.host == "127.0.0.1" && origin.port in 49152..65535 &&
            origin.path in setOf("", "/") && origin.userInfo == null &&
            origin.rawQuery == null && origin.rawFragment == null &&
            field(originalContext, "fixtureBaselineUrl") == origin.resolve("/feed/baseline").toString() &&
            field(originalContext, "fixtureNewItemUrl") == origin.resolve("/feed/new").toString())
        val fixtureCa = ReleasePrivateFiles.read(Path.of(field(originalContext, "fixtureCaFile")), 65536)
        val keystore = ReleasePrivateFiles.read(Path.of(field(originalContext, "fixtureKeyStoreFile")), 65536)
        val passwordBytes = ReleasePrivateFiles.read(Path.of(field(originalContext, "fixtureKeyStorePasswordFile")), 1024)
        require(ReleaseLocks.sha256(fixtureCa) == field(originalContext, "fixtureCaSha256") &&
            ReleaseLocks.sha256(keystore) == field(originalContext, "fixtureKeyStoreSha256") &&
            ReleaseLocks.sha256(passwordBytes) == field(originalContext, "fixtureKeyStorePasswordSha256") &&
            !fixtureCa.contentEquals(ReleasePrivateFiles.read(Path.of(ca.path), 65536))) {
            "Feed-only loopback TLS custody cannot replace the selected real Mastodon issuer"
        }
        val authority = CertificateFactory.getInstance("X.509")
            .generateCertificate(fixtureCa.inputStream()) as X509Certificate
        authority.checkValidity()
        val password = passwordBytes.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').toCharArray()
        try {
            require(password.size in 24..256)
            val store = KeyStore.getInstance("PKCS12")
            keystore.inputStream().use { store.load(it, password) }
            val aliases = store.aliases()
            require(aliases.hasMoreElements())
            val alias = aliases.nextElement()
            require(!aliases.hasMoreElements())
            val certificate = store.getCertificateChain(alias)?.firstOrNull() as? X509Certificate
                ?: error("Original loopback TLS leaf missing")
            certificate.checkValidity(); certificate.verify(authority.publicKey)
            require(certificate.subjectAlternativeNames?.any { it[0] == 7 && it[1] == "127.0.0.1" } == true)
        } finally { password.fill('\u0000') }
        val root = GenerationRuntime.BASE.resolve(generation.request.id)
        val tokens = root.resolve("rss/tokens")
        ReleasePrivateFiles.directory(tokens)
        val tokenHashes = feeds.associate { feed ->
            val path = tokens.resolve("${feed.feed.account}.token")
            MastodonRssSender.privateToken(path) // custody and encoding only, no GET or POST
            feed.feed.account to ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 2048))
        }
        if (!serviceId.startsWith("rss-pack-")) {
            val expected = root.resolve("rss/qualification-custody/$fixtureId/bot.token")
            require(field(originalContext, "fixtureSyntheticTokenFile") == expected.toString() &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(expected, 2048)) ==
                    field(originalContext, "fixtureSyntheticTokenSha256"))
            MastodonRssSender.privateToken(expected)
        }
        val original = RssQualificationPackSource.produce(generation, bundleSha256,
            invocationId, phaseClaimSha256, pack)
        val selected = RssQualificationPackSource.prepare(caseDir, generation, bundleSha256,
            invocationId, phaseClaimSha256, ingressControlAddress, Path.of(ca.path), ca.sha256,
            servedLeafSha256, pack, original)
        val ledger = QualificationRssFeatureLedger(generation = generation.request.id,
            bundleSha256 = bundleSha256, candidateSha256 = generation.request.candidateSha256,
            invocationId = invocationId, phaseClaimSha256 = phaseClaimSha256, pack = pack,
            originalManifestSha256 = original.sha256,
            packFeedIds = feeds.groupBy { it.pack }.mapValues { (_, values) -> values.map { it.feed.id } },
            accountTokenSha256 = tokenHashes)
        validate(ledger, feeds, generation.request.id, bundleSha256, generation.request.candidateSha256,
            invocationId, phaseClaimSha256, pack, original.sha256)
        val file = caseDir.resolve("owner-proofs/rss-feature-ledger.json")
        val bytes = Json.encodeToString(QualificationRssFeatureLedger.serializer(), ledger).encodeToByteArray()
        ReleasePrivateFiles.save(file, bytes) // create-new; partial issue cannot be silently retried
        return mapOf("rssPackSourceFile" to JsonPrimitive(selected.path),
            "rssPackSourceSha256" to JsonPrimitive(selected.sha256),
            "rssPackManifestSha256" to JsonPrimitive(original.sha256),
            "rssFeatureLedgerFile" to JsonPrimitive(file.toString()),
            "rssFeatureLedgerSha256" to JsonPrimitive(ReleaseLocks.sha256(bytes)))
    }
}
