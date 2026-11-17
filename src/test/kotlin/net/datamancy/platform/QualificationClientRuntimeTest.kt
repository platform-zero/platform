package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QualificationClientRuntimeTest {
    private val generation = "q-0123456789ab"
    private val fp = "a".repeat(64)
    private val image = AcquiredImage("qualification-client", "https://example.invalid/source", "qualified-client:v1",
        "registry.example.invalid/qualified-client@sha256:${"b".repeat(64)}", "c".repeat(64),
        listOf("registry.example.invalid/qualified-client@sha256:${"b".repeat(64)}"),
        "sha256:${"b".repeat(64)}", "amd64", "linux")
    private val spec = PrivateDeploymentSpec(name = generation, store = RuntimeStore.CANONICAL_V2,
        volumes = emptyList(), processes = listOf(
            RuntimeProcess("caddy", "caddy:example", "a".repeat(64), 1000, networks = listOf("qualification-web")),
            RuntimeProcess("livekit", "livekit:example", "d".repeat(64), 1000, networks = listOf("qualification-web"))),
        networks = listOf("qualification-web"))
    private val request = QualificationClientRequest("qc-123456789abc", generation, fp, "case-rtc-browser",
        "/mnt/media/p0-v3/evidence/case-rtc-browser", "d".repeat(64),
        "/opt/p0v3/acceptance", "e".repeat(64), "f".repeat(64),
        "matrix-rtc", "WEB", "BROWSER", "INSTALL",
        ActivationInput("/mnt/media/p0-v3/original-source-ca.pem", "b".repeat(64)), "c".repeat(64),
        image.imageId, image.pinnedImage, image.selectedManifestDigest, 4096, 2048, 512)
    private val runtime = QualificationClientRuntime(Path.of("/mnt/media/p0-v3/release-generations/$generation/qualification-client"),
        spec, generation, fp, AcquiredInventory(1, "acquired", listOf(image)),
        setOf("rtc.datamancy.net", "auth.datamancy.net", "matrix.datamancy.net"), RuntimeCommands { throw AssertionError("Unit source must not call Podman") },
        { process -> if (process == "caddy") "10.42.0.2" else "10.42.0.3" },
        { _, _, _ -> throw AssertionError("Unit source must not enter a native namespace") })

    @Test fun `historical QClient and TURN policy bytes omit new claim public revisions and private mode`(): Unit {
        val json = Json { encodeDefaults = true }
        val original = json.encodeToString(request)
        assertFalse("publicCertificateRevisions" in original || "nativeCaseClaimSha256" in original ||
            "clientMode" in original)
        assertEquals(original, json.encodeToString(json.decodeFromString<QualificationClientRequest>(original)))
        val policy = QualificationTurnPolicy("qc-0123456789ab", "case-rtc-browser", generation,
            caddyClientIp = "10.42.0.2", livekitClientIp = "10.42.0.3", containerId = fp,
            containerPid = 42, containerNetnsInode = 321, nftTable = "p0v3_qc_0123456789ab",
            rulesSha256 = fp, nativeRulesReadbackSha256 = fp)
        val policyBytes = json.encodeToString(policy)
        assertFalse("clientMode" in policyBytes)
        assertEquals(policyBytes, json.encodeToString(json.decodeFromString<QualificationTurnPolicy>(policyBytes)))
    }

    @Test fun `guest browser and Android TURN use one exact QClient namespace table and default-drop SFU policy`(): Unit {
        val policy = QualificationClientRuntime.nftRules("p0v3_qc_123456789abc", "10.42.0.2", "10.42.0.3")
            .decodeToString()
        assertContains(policy, "ip daddr 10.42.0.2 udp dport 3478 counter dnat ip to 10.42.0.3:3478")
        assertContains(policy, "ip daddr 10.42.0.2 tcp dport 5349 counter dnat ip to 10.42.0.3:5349")
        assertContains(policy, "ip daddr 10.42.0.3 tcp dport 7880 counter drop")
        assertContains(policy, "ip daddr 10.42.0.3 udp dport 50000-50020 counter drop")
        assertContains(policy, "ip daddr 10.42.0.2 tcp dport 443 counter accept")
        assertEquals(2, "policy drop;".toRegex().findAll(policy).count())
        assertFalse("0.0.0.0" in policy || "flush ruleset" in policy || "table ip filter" in policy)
        assertFailsWith<IllegalArgumentException> {
            QualificationClientRuntime.nftRules("foreign", "10.42.0.2", "10.42.0.3")
        }
        assertFailsWith<IllegalArgumentException> {
            QualificationClientRuntime.nftRules("p0v3_qc_123456789abc", "8.8.8.8", "10.42.0.3")
        }
        assertFailsWith<IllegalArgumentException> {
            QualificationClientRuntime.nftRules("p0v3_qc_123456789abc", "10.42.0.2", "10.42.0.2")
        }
    }

    @Test fun `fixed image runner starts detached with only one internal network no public port or host-trust mutation`(): Unit {
        val args = runtime.arguments(request, "p0v3-qc-$generation-${request.invocationId}",
            Path.of(request.caseDirectory), "10.42.0.2")
        assertContains(args, "--pull=never")
        val native = com.sun.security.auth.module.UnixSystem()
        assertContains(args, "/tmp:rw,nosuid,nodev,size=512m,mode=700,uid=${native.uid},gid=${native.gid}")
        assertEquals(listOf("--user", "${native.uid}:${native.gid}"), args.windowed(2).single { it.first() == "--user" })
        assertTrue(args.none { it.startsWith("--userns") || "keep-id" in it })
        assertContains(args, "--cap-drop=all")
        assertContains(args, "--read-only")
        assertContains(args, "--dns=127.0.0.1")
        assertContains(args, "p0v3-live-$generation-qualification-web")
        assertContains(args, "--entrypoint")
        assertContains(args, "/opt/p0v3/qualified-client-entry.py")
        assertContains(args, "P0V3_CLIENT_MODE=NORMAL")
        val denied = runtime.arguments(request.copy(serviceId = "alloy", surface = "HEADLESS",
            variant = "NATIVE", clientMode = "NATIVE_NETWORK_DENIAL"),
            "p0v3-qc-$generation-${request.invocationId}", Path.of(request.caseDirectory), "10.42.0.2")
        assertContains(denied, "P0V3_CLIENT_MODE=NATIVE_NETWORK_DENIAL")
        assertTrue(args.none { it in setOf("--privileged", "--network=host", "--publish", "--publish-all", "--volume=/", "--dns=8.8.8.8") })
        assertEquals(1, args.count { it == "--network" })
        assertEquals(0, args.count { it == "--device" })
        // New explicit user exception is Android TEST guests only; admission still
        // pins the private QClient net, exact APK mount and a single KVM device.
        for (api in listOf("API34", "API36")) {
            val apk = ActivationInput("/mnt/media/p0-v3/qualified-clients/real.apk", "f".repeat(64))
            val android = runtime.arguments(request.copy(serviceId = "element", surface = "ANDROID",
                variant = api, officialApk = apk), "p0v3-qc-$generation-${request.invocationId}",
                Path.of(request.caseDirectory), "10.42.0.2")
            assertContains(android, "/dev/kvm:/dev/kvm")
            assertEquals(1, android.count { it == "--device" })
            assertContains(android, "${apk.path}:${apk.path}:ro")
            assertFalse(android.any { it in setOf("--network=host", "--privileged", "--publish", "--publish-all") })
            assertFailsWith<IllegalArgumentException> { runtime.arguments(request.copy(
                surface = "ANDROID", variant = api, officialApk = apk),
                "p0v3-qc-$generation-${request.invocationId}", Path.of(request.caseDirectory), "10.42.0.2") }
            assertFailsWith<IllegalArgumentException> { runtime.arguments(request.copy(
                serviceId = "element", surface = "ANDROID", variant = api, officialApk = null),
                "p0v3-qc-$generation-${request.invocationId}", Path.of(request.caseDirectory), "10.42.0.2") }
        }
        val original = Path.of(request.caseDirectory).parent.resolve("grafana-original-native")
        val grafana = runtime.arguments(request.copy(serviceId = "grafana", surface = "WEB",
            variant = "BROWSER", phase = "INSTALL",
            grafanaNativeOracle = ActivationInput(original.resolve("oracle.json").toString(), "a".repeat(64)),
            grafanaNativeObservation = ActivationInput(original.resolve("native-result.json").toString(), "b".repeat(64)),
            predecessorFiles = listOf(ActivationInput(original.resolve("oracle.json").toString(), "a".repeat(64)),
                ActivationInput(original.resolve("native-result.json").toString(), "b".repeat(64)))), 
            "p0v3-qc-$generation-${request.invocationId}", Path.of(request.caseDirectory), "10.42.0.2")
        assertFalse("$original:$original:ro" in grafana)
        for (name in listOf("oracle.json", "native-result.json"))
            assertEquals(1, grafana.count { it == "$original/$name:$original/$name:ro" })
    }

    @Test fun `actual kernel UID and GID mappings reject ambiguity overflow and credential drift`(): Unit {
        val map = "         0       100000      1000\n      1000         1234         1\n      1001       101001     64535\n"
        assertEquals(1234L, QualificationClientUidMapping.hostId(map))
        assertEquals(2500L, QualificationClientUidMapping.hostId("0 0 4294967295\n", 2500L))
        assertFails { QualificationClientUidMapping.hostId(map, 2500L).also { require(it == 2500L) } }
        QualificationClientUidMapping.credentials("Name:\tclient\nUid:\t1234\t1234\t1234\t1234\nGid:\t3456\t3456\t3456\t3456\n",
            1234L, 3456L)
        assertEquals(101000L, QualificationClientUidMapping.hostId("0 100000 65536\n"))
        for (invalid in listOf("0 100000 500\n", "1000 1234 1\n1000 9999 1\n",
            "1000 1234 1\n2000 1234 1\n", "4294967295 1234 2\n", "1000 1234 0\n",
            "1000 x 1\n", "1000 1234 1\n1000 1234 1\n"))
            assertFails { QualificationClientUidMapping.hostId(invalid) }
        assertFails { QualificationClientUidMapping.credentials(
            "Uid:\t1234\t0\t1234\t1234\nGid:\t3456\t3456\t3456\t3456\n", 1234, 3456) }
        assertFails { QualificationClientUidMapping.credentials(
            "Uid:\t1234\t1234\t1234\t1234\nGid:\t3456\t3456\t3456\t3456\nGid:\t3456\t3456\t3456\t3456\n", 1234, 3456) }
    }

    @Test fun `Seafile browser and official Android preserve standard gate while native requires reviewed signer`(): Unit {
        for ((surface, variant) in listOf("WEB" to "BROWSER", "ANDROID" to "API34", "ANDROID" to "API36")) {
            assertTrue(admittedSeafileTools(request.copy(serviceId = "seafile", surface = surface,
                variant = variant), setOf("files.datamancy.net"), null))
        }
        val h = "a".repeat(64)
        val pins = NativeSeafileToolPins(h, h, h, h, h, h, h, h, h)
        val native = request.copy(serviceId = "seafile", surface = "HEADLESS", variant = "NATIVE",
            seafileToolPins = pins)
        assertFalse(admittedSeafileTools(native, setOf("files.datamancy.net"), null))
        assertFalse(admittedSeafileTools(native, setOf("foreign.datamancy.net"), "a".repeat(64)))
        assertTrue(admittedSeafileTools(native, setOf("files.datamancy.net"), "a".repeat(64)))
        assertFalse(admittedSeafileTools(native.copy(surface = "ANDROID", variant = "API34"),
            setOf("files.datamancy.net"), "a".repeat(64)))
    }

    @Test fun `missing protected native claim rejects a denied-only client before Podman effects`(): Unit {
        val base = Files.createTempDirectory("native-client-intent-unit-")
        val mode = PosixFilePermissions.fromString("rwx------")
        Files.setPosixFilePermissions(base, mode)
        try {
            val genDir = Files.createDirectory(base.resolve(generation), PosixFilePermissions.asFileAttribute(mode))
            val case = Files.createDirectory(base.resolve("case"), PosixFilePermissions.asFileAttribute(mode))
            val suite = Files.createDirectory(base.resolve("suite"), PosixFilePermissions.asFileAttribute(mode))
            val scripts = Files.createDirectory(suite.resolve("scripts"), PosixFilePermissions.asFileAttribute(mode))
            val runner = scripts.resolve("qualified-runner.py")
            Files.writeString(runner, "#!/usr/bin/python3\nraise RuntimeError('never execute a unit fixture')\n")
            val sha = ReleaseLocks.sha256(Files.readAllBytes(runner))
            val ca = base.resolve("ca.pem")
            ReleasePrivateFiles.save(ca, "-----BEGIN CERTIFICATE-----\nUNIT\n-----END CERTIFICATE-----\n".encodeToByteArray())
            val context = "{\"fixture\":\"private-unit\"}".encodeToByteArray()
            ReleasePrivateFiles.save(case.resolve("context.json"), context)
            val intent = buildJsonObject {
                put("invocationId", "case-rtc-browser"); put("serviceId", "alloy")
                put("surface", "HEADLESS"); put("variant", "NATIVE"); put("runnerSha256", sha)
                put("contextSha256", ReleaseLocks.sha256(context))
                put("binding", buildJsonObject { put("generationId", generation); put("phase", "INSTALL") })
            }.toString().encodeToByteArray()
            ReleasePrivateFiles.save(case.resolve("intent.json"), intent)
            val pinned = "registry.example.invalid/owned@sha256:${"a".repeat(64)}"
            val spec = PrivateDeploymentSpec(name = "$generation-canonical-release-v2", store = RuntimeStore.CANONICAL_V2,
                volumes = emptyList(), networks = listOf("qualification-web"), processes = listOf(
                    RuntimeProcess("caddy", pinned, "a".repeat(64), 1000, networks = listOf("qualification-web"),
                        readiness = listOf("/usr/bin/caddy", "version")),
                    RuntimeProcess("livekit", pinned, "a".repeat(64), 1000, networks = listOf("qualification-web"),
                        readiness = listOf("/usr/bin/livekit", "--version"))))
            var calls = 0
            val actor = QualificationClientRuntime(genDir.resolve("qualification-client"), spec, generation, fp,
                AcquiredInventory(1, "acquired", listOf(image)), setOf("rtc.datamancy.net"),
                RuntimeCommands { args ->
                    assertEquals("run", args.first()); calls++; throw PrivateCommandTimeout()
                }, { if (it == "caddy") "10.42.0.2" else "10.42.0.3" },
                { _, _, _ -> error("Native namespace must not run before Podman CID adoption") }, base,
                { GenerationCapacity(65536, 65536) })
            val admitted = request.copy(serviceId = "alloy", surface = "HEADLESS", variant = "NATIVE",
                clientMode = "NATIVE_NETWORK_DENIAL",
                caseDirectory = case.toString(), suiteDirectory = suite.toString(), runnerSha256 = sha,
                caseIntentSha256 = ReleaseLocks.sha256(intent), certificate = ActivationInput(ca.toString(),
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(ca))))
            assertFailsWith<IllegalArgumentException> { actor.start(admitted) }
            val journal = genDir.resolve("qualification-client").resolve(admitted.invocationId)
            assertFalse(Files.exists(journal.resolve("intent.json")))
            assertEquals(0, calls)
            assertFailsWith<IllegalArgumentException> { actor.start(admitted) }
            assertEquals(0, calls)
        } finally { Files.walk(base).use { paths ->
            paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        } }
    }

    @Test fun `a serialized policy is not a packet proof or runner success callback`(): Unit {
        val policy = QualificationTurnPolicy(request.operation, request.invocationId, generation,
            caddyClientIp = "10.42.0.2", livekitClientIp = "10.42.0.3", containerId = "d".repeat(64),
            containerPid = 12001, containerNetnsInode = 20122L, nftTable = "p0v3_qc_123456789abc",
            rulesSha256 = "a".repeat(64), nativeRulesReadbackSha256 = "b".repeat(64))
        assertEquals("qualification-web", policy.clientNetwork)
        assertEquals("matrix-rtc.datamancy.net", policy.rtcHost)
        assertEquals(3478, policy.udpPort)
        assertEquals(5349, policy.tlsPort)
        assertEquals(7880, policy.deniedTcpPort)
        assertEquals(50000, policy.deniedUdpStart)
        assertEquals(50020, policy.deniedUdpEnd)
    }
}
