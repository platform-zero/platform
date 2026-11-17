package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class RssControllerPayloadsTest {
    private fun dir(path: Path) = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("rss-controller-unit-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try { block(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun sourceBundle(root: Path): GenerationBundle = GenerationBundle(
        GenerationRequest(id = "q-123456789abc", candidateSha256 = "b".repeat(64),
            members = emptyList(), diskReservationMiB = 1024, store = RuntimeStore.CANONICAL_V2,
            rssPlan = GenerationRssPlan(controllerSha256 = "b".repeat(64),
                artifactClosure = ActivationInput(root.resolve("closure").toString(), "c".repeat(64)),
                mastodonOrigin = "https://social.datamancy.net")), emptyList(), 0)
    @Test fun `non RSS generation may capture but missing planned or unplanned RSS custody refuses`(): Unit = fixture { root ->
        val source = dir(root.resolve("q-123456789abc"))
        val planned = sourceBundle(root)
        val unplanned = planned.copy(request = planned.request.copy(rssPlan = null))
        val bundleFile = source.resolve("bundle.json")
        ReleasePrivateFiles.save(bundleFile, Json.encodeToString(unplanned).toByteArray())
        assertTrue(RssControllerPayloads.capture(source, linkedMapOf()).isEmpty())
        dir(source.resolve("rss"))
        assertFailsWith<IllegalArgumentException> { RssControllerPayloads.capture(source, linkedMapOf()) }
        Files.delete(source.resolve("rss"))
        Files.delete(bundleFile)
        ReleasePrivateFiles.save(bundleFile, Json.encodeToString(planned).toByteArray())
        assertFailsWith<IllegalArgumentException> { RssControllerPayloads.capture(source, linkedMapOf()) }
    }
    @Test fun `cold projection preserves original checkpoint and never restores scheduler authority`(): Unit = fixture { root ->
        val source = dir(root.resolve("q-123456789abc"))
        GenerationRssPlan.prepare(source)
        val bundle = sourceBundle(root)
        ReleasePrivateFiles.save(source.resolve("bundle.json"), Json.encodeToString(bundle).toByteArray())
        val state = source.resolve("rss/state")
        val original = Files.readAllBytes(state.resolve("rss-state.json"))
        val schedule = dir(source.resolve("rss/schedule"))
        ReleasePrivateFiles.save(schedule.resolve("enabled"), "a".repeat(64).toByteArray())
        val tokens = source.resolve("rss/tokens")
        val account = RssPacks.load().first().feed.account
        ReleasePrivateFiles.save(tokens.resolve("$account.token"), "synthetic-private-custody-record-not-live".toByteArray())
        val fixtureId = "case-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val qualification = dir(source.resolve("rss/qualification-custody"))
        val bot = dir(qualification.resolve(fixtureId))
        ReleasePrivateFiles.save(bot.resolve("bot.token"), "actual-canonical-synthetic-bot-token-source".toByteArray())
        val payloads = linkedMapOf<String, Path>()
        val names = RssControllerPayloads.capture(source, payloads)
        assertEquals(3, names.size)
        assertEquals(bot.resolve("bot.token"), payloads.getValue(
            "controller/rss/qualification-custody/$fixtureId/bot.token"))
        assertFalse(names.any { "schedule" in it || it.endsWith(".lock") || "enabled" in it })
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = "q-123456789abc",
            bundleSha256 = "a".repeat(64), members = emptyList(), files = RecoveryCapsule.describe(payloads),
            controllerFiles = names)
        RssControllerPayloads.validate(manifest)
        val extracted = dir(root.resolve("extracted"))
        for ((name, sourcePath) in payloads) {
            var parent = extracted
            for (part in name.split('/').dropLast(1)) {
                parent = parent.resolve(part)
                if (!Files.exists(parent)) dir(parent)
            }
            ReleasePrivateFiles.save(extracted.resolve(name), Files.readAllBytes(sourcePath))
        }
        val recovered = RecoveredGeneration(bundle, manifest, extracted,
            GenerationRecoveryCheck(manifest.generation, manifest.id, manifest.bundleSha256, "", emptyList()))
        val target = dir(root.resolve("target"))
        RssControllerPayloads.restore(recovered, target)
        assertContentEquals(original, Files.readAllBytes(target.resolve("rss/state/rss-state.json")))
        assertEquals(RssStateStore(state).read(), RssStateStore(target.resolve("rss/state")).read())
        assertFalse(Files.exists(target.resolve("rss/schedule")))
        assertContentEquals(Files.readAllBytes(tokens.resolve("$account.token")), Files.readAllBytes(target.resolve("rss/tokens/$account.token")))
        assertContentEquals(Files.readAllBytes(bot.resolve("bot.token")), Files.readAllBytes(
            target.resolve("rss/qualification-custody/$fixtureId/bot.token")))
        assertFails { RssControllerPayloads.restore(recovered, target) }
        val recaptured = dir(root.resolve("q-222222222222"))
        val inertRequest = GenerationRssPlan.coldRecoveryTarget(bundle.request,
            bundle.request.copy(id = recaptured.fileName.toString()))
        assertNull(inertRequest.rssPlan)
        assertEquals(bundle.request.rssPlan, inertRequest.recoveredRssPlan)
        val lineage = KopiaSnapshotReceipt(id = manifest.id, generation = bundle.request.id,
            bundleSha256 = manifest.bundleSha256, snapshotId = "snapshot-original", rootObjectId = "object-original",
            manifestSha256 = "d".repeat(64), files = 2, plaintextBytes = 1024,
            image = root.resolve("image").toString(), imageId = "e".repeat(64))
        val inertBundle = bundle.copy(request = inertRequest, recoverySourceKopia = lineage)
        ReleasePrivateFiles.save(recaptured.resolve("bundle.json"), Json.encodeToString(inertBundle).toByteArray())
        val inertRss = dir(recaptured.resolve("rss"))
        for (name in listOf("state", "tokens")) {
            val folder = dir(inertRss.resolve(name))
            Files.list(target.resolve("rss/$name")).use { stream -> stream.forEach { item ->
                ReleasePrivateFiles.save(folder.resolve(item.fileName.toString()), Files.readAllBytes(item))
            } }
        }
        val inertCustody = dir(inertRss.resolve("qualification-custody"))
        val inertBot = dir(inertCustody.resolve(fixtureId))
        ReleasePrivateFiles.save(inertBot.resolve("bot.token"), Files.readAllBytes(bot.resolve("bot.token")))
        val next = linkedMapOf<String, Path>()
        assertEquals(names, RssControllerPayloads.capture(recaptured, next))
        assertContentEquals(original, Files.readAllBytes(next.getValue("controller/rss/state/rss-state.json")))
    }
    @Test fun `foreign metadata linked files malicious manifest and interruption fail closed`(): Unit = fixture { root ->
        val source = dir(root.resolve("q-123456789abc"))
        GenerationRssPlan.prepare(source)
        ReleasePrivateFiles.save(source.resolve("bundle.json"), Json.encodeToString(sourceBundle(root)).toByteArray())
        val payloads = linkedMapOf<String, Path>()
        val names = RssControllerPayloads.capture(source, payloads)
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = "q-123456789abc",
            bundleSha256 = "a".repeat(64), members = emptyList(), files = RecoveryCapsule.describe(payloads),
            controllerFiles = names)
        for (bad in listOf("controller/rss/schedule/enabled", "controller/rss/state/rss-state.lock",
            "controller/rss/tokens/../token", "controller/rss/tokens/root.token"))
            assertFails { RssControllerPayloads.validate(manifest.copy(controllerFiles = names + bad)) }
        val state = source.resolve("rss/state")
        val originalState = Files.readAllBytes(state.resolve("rss-state.json"))
        Files.writeString(state.resolve("rss-state.json"), "{}")
        assertFails { RssControllerPayloads.capture(source, linkedMapOf()) }
        Files.delete(state.resolve("rss-state.json"))
        Files.createSymbolicLink(state.resolve("rss-state.json"), root.resolve("outside"))
        assertFails { RssControllerPayloads.capture(source, linkedMapOf()) }
        Files.delete(state.resolve("rss-state.json"))
        assertFails { RssStateStore(state).initializeFresh() } // Existing lock prohibits reset after damage.
        ReleasePrivateFiles.save(state.resolve("rss-state.json"), originalState)
        val qualification = dir(source.resolve("rss/qualification-custody"))
        val bot = dir(qualification.resolve("case-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        Files.createSymbolicLink(bot.resolve("bot.token"), root.resolve("outside-synthetic-credential"))
        assertFails { RssControllerPayloads.capture(source, linkedMapOf()) } // Never follow a foreign bot token.
    }
}
