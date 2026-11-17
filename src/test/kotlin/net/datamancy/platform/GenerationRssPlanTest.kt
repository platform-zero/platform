package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationRssPlanTest {
    private class Fixture : AutoCloseable {
        val json = Json { encodeDefaults = true }
        val root = Files.createTempDirectory("generation-rss-unit-").also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
        fun dir(parent: Path, name: String) = Files.createDirectory(parent.resolve(name),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val generations = dir(root, "generations")
        val id = "q-111111111111"
        val generation = dir(generations, id)
        val closure = root.resolve("closure.json").also { ReleasePrivateFiles.save(it, "{}".toByteArray()) }
        val rssPlan = GenerationRssPlan(controllerSha256 = "a".repeat(64),
            artifactClosure = ActivationInput(closure.toString(), ReleaseLocks.sha256(Files.readAllBytes(closure))),
            mastodonOrigin = "https://social.datamancy.net")
        val inventory = Files.readAllBytes(Path.of("release/downloaded-candidate-inventory.json"))
        val request = AssemblyRequest(id = id, candidateSha256 = "b".repeat(64), inventorySha256 = ReleaseLocks.sha256(inventory),
            selections = listOf(AssemblySelection("foundation"), AssemblySelection("mastodon")), diskReservationMiB = 32768,
            store = RuntimeStore.CANONICAL_V2, rssPlan = rssPlan)
        val plan = GenerationAssembly().plan(request, inventory)
        val graph = SiteOwnerships.inspect(plan)
        val owners = graph.processes.associate { it.process to requireNotNull(it.compiledProduct) }
        val contract = SiteOwnership(site = "rss-unit", assemblySha256 = graph.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "cohort") },
            inputs = graph.inputs.map { SiteInputOwner(it.input, requireNotNull(it.compiledProduct), true, it.consumers) },
            routes = listOf(SiteRouteOwner("social.datamancy.net", "mastodon", "$id-mastodon/social", 8080)),
            managed = GenerationManagedComponents.ownership(plan.generation))
        val ownership: BoundSiteOwnership = SiteOwnerships.bind(plan, contract, setOf("social.datamancy.net"))
        val bundle = GenerationBundle(plan.generation, plan.specs.zip(plan.generation.members).map { (spec, member) ->
            val inputs = PrivateDeployment.inputNames(spec).associateWith { "c".repeat(64) }
            GenerationPin(member, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), inputs,
                PrivateDeployment.expectedFingerprint(spec, inputs), spec)
        }, plan.specs.sumOf { spec -> spec.processes.filterNot { it.oneShot }.sumOf { p -> p.memoryMiB.toLong() } +
            (spec.processes.filter { it.oneShot }.maxOfOrNull { p -> p.memoryMiB } ?: 0) } + GenerationRssPlan.MEMORY_MIB,
            assemblySha256 = graph.assemblySha256, ownership = ownership)
        val bundleBytes = json.encodeToString(bundle).toByteArray()
        val bundleHash = ReleaseLocks.sha256(bundleBytes)
        val binding = RssScheduleBinding(deployment = ReleaseDeploymentBinding(id, bundleHash, "d".repeat(64), "e".repeat(64)),
            transactionJournal = root.resolve("transaction.jsonl").toString(), stateDirectory = generation.resolve("rss/state").toString(),
            tokenDirectory = generation.resolve("rss/tokens").toString(), mastodonOrigin = rssPlan.mastodonOrigin,
            controllerSha256 = rssPlan.controllerSha256, artifactClosure = rssPlan.artifactClosure, userId = UnixSystem().uid.toInt())
        val scheduleRoot = generation.resolve("rss/schedule")
        val accounts = (RssPacks.load().map { it.feed.account } + "rss_observer").sorted()
        val identityFixture = RssHttp { method, uri, headers, body ->
            require(method == "GET" && uri.toString() == "https://social.datamancy.net/api/v1/accounts/verify_credentials" &&
                body.isEmpty() && headers["Accept"] == "application/json")
            val bearer = requireNotNull(headers["Authorization"]).removePrefix("Bearer ")
            val name = accounts.single { bearer == "unit-local-$it-pinned-token-0123456789" }
            val id = (accounts.indexOf(name) + 1).toString()
            RssHttpReply(200, (if (name == "rss_observer")
                """{"id":"$id","acct":"$name","following_count":47}"""
            else """{"id":"$id","acct":"$name","bot":true}""").toByteArray())
        }
        val authority = GenerationRssEnrollmentAuthority(generations, identityFixture)
        val schedule = RssSchedule({ _, _ -> error("No activation in enrollment units") }, {},
            RssHttp { _, _, _, _ -> error("No network") }, enrollment = authority)
        init {
            ReleasePrivateFiles.save(generation.resolve("bundle.json"), bundleBytes)
            ReleasePrivateFiles.save(generation.resolve("assembly.intent.json"), json.encodeToString(plan.summary).toByteArray())
            ReleasePrivateFiles.save(generation.resolve("ownership.intent.json"), json.encodeToString(ownership).toByteArray())
            ReleasePrivateFiles.save(generation.resolve("assembly.result.json"),
                json.encodeToString(AssemblyPreparationOutcome(graph.assemblySha256, true, bundleHash)).toByteArray())
            GenerationRssPlan.prepare(generation)
            val tokenRoot = generation.resolve("rss/tokens")
            ReleasePrivateFiles.directory(tokenRoot)
            for (name in RssPacks.load().map { it.feed.account }.toSet() + "rss_observer") {
                ReleasePrivateFiles.save(tokenRoot.resolve("$name.token"),
                    ("unit-local-$name-pinned-token-0123456789\n").toByteArray())
            }
        }
        override fun close() { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `sealed plan has no future digest and one immutable enrollment binds actual generation`(): Unit = Fixture().use { f ->
        assertEquals(f.rssPlan, f.bundle.request.rssPlan)
        SiteOwnerships.checkSealed(f.bundle)
        val before = RssStateStore(Path.of(f.binding.stateDirectory)).read()
        val hash = f.schedule.enroll(f.scheduleRoot, f.binding)
        f.authority.verify(f.scheduleRoot, f.binding, hash)
        assertNull(f.schedule.tick(f.scheduleRoot, hash))
        assertEquals(before, RssStateStore(Path.of(f.binding.stateDirectory)).read())
        assertFails { f.schedule.enroll(f.scheduleRoot, f.binding) }
        assertFails { f.schedule.enroll(f.generation.resolve("rss/alias"), f.binding) }
        assertFalse(Files.exists(f.generation.resolve("rss/alias")))
        assertFails { GenerationRssPlan.prepare(f.generation) }
        val intent = Files.readAllBytes(f.generation.resolve("rss-enrollment.intent.json"))
        assertContentEquals(intent, Files.readAllBytes(f.generation.resolve("rss-enrollment.complete.json")))
        val target = f.plan.generation.copy(id = "q-222222222222")
        val projected = GenerationRssPlan.coldRecoveryTarget(f.plan.generation, target)
        assertNull(projected.rssPlan)
        assertEquals(f.plan.generation.rssPlan, projected.recoveredRssPlan)
        val next = GenerationRssPlan.coldRecoveryTarget(projected,
            projected.copy(id = "q-333333333333"))
        assertNull(next.rssPlan)
        assertEquals(projected.recoveredRssPlan, next.recoveredRssPlan)
        assertEquals(target.id, projected.id)
        assertEquals(RuntimeStore.CANONICAL_V2, projected.store)
        assertFails { GenerationRssPlan.coldRecoveryTarget(f.plan.generation, target.copy(store = RuntimeStore.LEGACY)) }
        assertFails { GenerationRssPlan.coldRecoveryTarget(f.plan.generation, target.copy(id = f.plan.generation.id)) }
    }
    @Test fun `foreign state origin artifact or generation refuses before creating schedule`(): Unit = Fixture().use { f ->
        for (bad in listOf(f.binding.copy(stateDirectory = f.root.resolve("state").toString()),
            f.binding.copy(tokenDirectory = f.root.resolve("tokens").toString()),
            f.binding.copy(mastodonOrigin = "https://foreign.datamancy.net"), f.binding.copy(intervalSeconds = 600),
            f.binding.copy(controllerSha256 = "f".repeat(64)),
            f.binding.copy(deployment = f.binding.deployment.copy(bundleSha256 = "f".repeat(64))))) {
            assertFails { f.schedule.enroll(f.scheduleRoot, bad) }
            assertFalse(Files.exists(f.scheduleRoot))
        }
        Files.writeString(f.closure, "changed")
        assertFails { f.schedule.enroll(f.scheduleRoot, f.binding) }
        assertFalse(Files.exists(f.scheduleRoot))
    }
    @Test fun `partial generation enrollment is retained and cannot be replaced or used`(): Unit = Fixture().use { f ->
        val hash = ReleaseLocks.sha256(f.json.encodeToString(f.binding).toByteArray())
        f.authority.claim(f.scheduleRoot, f.binding, hash)
        assertFails { f.authority.verify(f.scheduleRoot, f.binding, hash) }
        assertFails { f.authority.complete(f.scheduleRoot, f.binding, hash) }
        assertFails { f.schedule.enroll(f.scheduleRoot, f.binding) }
        assertFalse(Files.exists(f.generation.resolve("rss-enrollment.complete.json")))
        assertFails { f.authority.claim(f.scheduleRoot, f.binding, "f".repeat(64)) }
    }
    @Test fun `missing or altered preparation and enrollment never authorize worker`(): Unit = Fixture().use { f ->
        val hash = f.schedule.enroll(f.scheduleRoot, f.binding)
        Files.writeString(f.generation.resolve("rss-enrollment.complete.json"), "foreign")
        assertFails { f.schedule.tick(f.scheduleRoot, hash) }
        Files.writeString(f.generation.resolve("assembly.result.json"), f.json.encodeToString(
            AssemblyPreparationOutcome(f.graph.assemblySha256, false, f.bundleHash)))
        assertFails { f.authority.preflight(f.scheduleRoot, f.binding) }
    }
    @Test fun `plan validation and historical omission preserve preexisting request bytes`(): Unit = Fixture().use { f ->
        for (bad in listOf(f.rssPlan.copy(schemaVersion = 2), f.rssPlan.copy(controllerSha256 = "bad"),
            f.rssPlan.copy(intervalSeconds = 1), f.rssPlan.copy(mastodonOrigin = "https://datamancy.net"),
            f.rssPlan.copy(mastodonOrigin = "https://social.datamancy.net/path"),
            f.rssPlan.copy(artifactClosure = f.rssPlan.artifactClosure.copy(path = "relative")))) assertFails { bad.validate() }
        assertFails { GenerationAssembly().plan(f.request.copy(store = RuntimeStore.LEGACY), f.inventory) }
        assertFails { GenerationRssPlan.validateOwnership(f.plan.generation, null) }
        assertFails { GenerationRssPlan.validateOwnership(f.plan.generation, f.ownership.copy(approvedHosts = emptySet())) }
        assertFails { GenerationRssPlan.validateOwnership(f.plan.generation, f.ownership.copy(contract = f.contract.copy(routes = emptyList()))) }
        assertFalse(f.json.encodeToString(f.request.copy(rssPlan = null)).contains("rssPlan"))
        assertFalse(f.json.encodeToString(f.plan.generation.copy(rssPlan = null)).contains("rssPlan"))
        assertFails { SiteOwnerships.checkSealed(f.bundle.copy(request = f.bundle.request.copy(rssPlan = f.rssPlan.copy(intervalSeconds = 600)))) }
    }
}
