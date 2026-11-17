package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

class QualificationRssCaseInputsTest {
    private val feeds = RssPacks.load()
    private val bundle = "a".repeat(64)
    private val candidate = "b".repeat(64)
    private val phase = "c".repeat(64)
    private val manifest = "d".repeat(64)
    private val invocation = "case-" + "e".repeat(36)
    private val generation = "q-" + "f".repeat(12)
    private fun original() = QualificationRssFeatureLedger(generation = generation,
        bundleSha256 = bundle, candidateSha256 = candidate, invocationId = invocation,
        phaseClaimSha256 = phase, pack = "analysis", originalManifestSha256 = manifest,
        packFeedIds = feeds.groupBy { it.pack }.mapValues { (_, values) -> values.map { it.feed.id } },
        accountTokenSha256 = feeds.mapIndexed { index, feed ->
            feed.feed.account to index.toString(16).padStart(64, '0') }.toMap())
    private fun check(ledger: QualificationRssFeatureLedger) = QualificationRssCaseInputs.validate(
        ledger, feeds, generation, bundle, candidate, invocation, phase, "analysis", manifest)

    @Test fun `selected original feature includes exactly nine packs and 47 distinct account custodians`() {
        check(original())
        assertFailsWith<IllegalArgumentException> { check(original().copy(packFeedIds = mapOf("analysis" to listOf("fake")))) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(accountTokenSha256 = emptyMap())) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(accountTokenSha256 =
            original().accountTokenSha256.mapValues { bundle })) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(accountTokenSha256 =
            original().accountTokenSha256 + ("rss_foreign" to bundle))) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(originalManifestSha256 = candidate)) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(phaseClaimSha256 = candidate)) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(candidateSha256 = manifest)) }
        assertFailsWith<IllegalArgumentException> { check(original().copy(invocationId = "case-foreign")) }
    }
}
