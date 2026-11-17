package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import kotlinx.serialization.json.*
import kotlin.test.*

class QualificationOfficeCaseInputsTest {
    private val key = "a".repeat(64)
    private val passwords = mapOf("owner" to "b".repeat(64), "reader" to "c".repeat(64),
        "outsider" to "d".repeat(64))
    private val source = mapOf(
        "seafile-users.json" to JsonObject(passwords.mapValues { JsonPrimitive(it.value) }).toString() + "\n",
        "seafile-users.py" to "email=role+'@localhost.invalid'\nccnet_api.add_emailuser(email,password,1,1)\n",
        "seafile-seahub-settings.py" to "ONLYOFFICE_JWT_SECRET='$key'\n",
        "onlyoffice-office.json" to """{"services":{"CoAuthoring":{"secret":{"browser":{"string":"$key"},"inbox":{"string":"$key"},"outbox":{"string":"$key"}}}}}""")
    private val image = "example.org/app@sha256:" + "e".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("seafile", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "f".repeat(64),
            emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    private fun pin(bytes: Map<String, String> = source): GenerationPin {
        val spec = SeafileRuntime.canonicalFragment(inventory, "q-012345abcdef-v2", officeEnabled = true).spec
        return GenerationPin(GenerationMember(spec.name), "0".repeat(64), bytes.mapValues {
            ReleaseLocks.sha256(it.value.encodeToByteArray())
        }, "1".repeat(64), spec)
    }
    private val web = buildJsonObject {
        put("owner", "owner@localhost.invalid"); put("editor", "reader@localhost.invalid")
        put("deniedUser", "outsider@localhost.invalid")
        val repo = "0".repeat(8) + "-0000-0000-0000-" + "0".repeat(12)
        val name = "p0v3-" + "1".repeat(32) + ".docx"
        put("seafileRepositoryId", repo); put("documentName", name)
        put("documentId", "$repo:/$name"); put("documentSha256", "2".repeat(64))
        put("ownerMarker", "Native owner edit " + "3".repeat(24))
        put("editorMarker", "Native second editor " + "4".repeat(24))
    }
    private fun read(bytes: Map<String, String>): (Path) -> ByteArray = { path ->
        bytes.getValue(path.fileName.toString()).encodeToByteArray()
    }
    private fun privateCase(action: (Path) -> Unit) {
        val dir = Files.createTempDirectory("office-owner-inputs-")
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"))
        try { action(dir) } finally {
            Files.walk(dir).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }

    @Test fun `original roles and callback key derive from pinned source not proposed paths`() = privateCase { dir ->
        val inputs = QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "HEADLESS", pin(), web,
            buildJsonObject { }, read(source))
        assertEquals(setOf("seafileCredentialsFile", "officeJwtSecretFile"), inputs.context.keys)
        assertEquals(2, inputs.privateFiles.size)
        val accounts = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(
            inputs.context.getValue("seafileCredentialsFile").jsonPrimitive.content)).decodeToString()).jsonObject
        assertEquals("owner@localhost.invalid", accounts.getValue("owner").jsonObject
            .getValue("username").jsonPrimitive.content)
        assertEquals(passwords.getValue("reader"), accounts.getValue("reader").jsonObject
            .getValue("password").jsonPrimitive.content)
        assertEquals(key, ReleasePrivateFiles.read(Path.of(inputs.context.getValue("officeJwtSecretFile")
            .jsonPrimitive.content)).decodeToString().trim())
        assertFails { QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "HEADLESS", pin(), web,
            buildJsonObject { put("officeJwtSecretFile", "/tmp/foreign") }, read(source)) }
    }

    @Test fun `WEB source and Android role projection reject foreign principals and future guest hashes`() = privateCase { dir ->
        val webInputs = QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "WEB", pin(), null,
            buildJsonObject { }, read(source))
        assertEquals(setOf("seafileAccountsFile"), webInputs.context.keys)
        val android = QualificationOfficeCaseInputs.prepare(dir, "RESTORE", "ANDROID", pin(), web,
            buildJsonObject { }, read(source))
        val scoped = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(android.context
            .getValue("scopedAccountFile").jsonPrimitive.content)).decodeToString()).jsonObject
        assertEquals("reader@localhost.invalid", scoped.getValue("editor").jsonObject
            .getValue("username").jsonPrimitive.content)
        assertFails { QualificationOfficeCaseInputs.prepare(dir, "RESTORE", "ANDROID", pin(),
            JsonObject(web + ("editor" to JsonPrimitive("foreign@localhost.invalid"))), buildJsonObject { }, read(source)) }
        assertFails { QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "ANDROID", pin(), web,
            buildJsonObject { put("seafileInstalledClientReceiptSha256", "3".repeat(64)) }, read(source)) }
    }

    @Test fun `source mutation or callback config mismatch refuses before private file projection`() = privateCase { dir ->
        val tampered = source + ("seafile-users.json" to "{}")
        assertFails { QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "WEB", pin(), null,
            buildJsonObject { }, read(tampered)) }
        val wrong = source + ("onlyoffice-office.json" to source.getValue("onlyoffice-office.json")
            .replace(key, "9".repeat(64)))
        assertFails { QualificationOfficeCaseInputs.prepare(dir, "INSTALL", "HEADLESS", pin(wrong), web,
            buildJsonObject { }, read(wrong)) }
        assertFalse(Files.exists(dir.resolve("owner-proofs")))
    }

    @Test fun `Seafile native and Android reuse exact original source accounts without device issuer`() = privateCase { dir ->
        val native = QualificationOfficeCaseInputs.prepareSeafile(dir,"INSTALL","HEADLESS",pin(),
            buildJsonObject {},read(source))
        val nativeAccounts = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(native.context
            .getValue("credentialsFile").jsonPrimitive.content)).decodeToString()).jsonObject
        assertEquals(passwords.getValue("reader"),nativeAccounts.getValue("reader").jsonObject
            .getValue("password").jsonPrimitive.content)
        assertEquals(1,native.privateFiles.size)
        val browser = QualificationOfficeCaseInputs.prepareSeafile(dir,"INSTALL","WEB",pin(),
            buildJsonObject {},read(source))
        assertEquals(setOf("scopedAccountFile"),browser.context.keys)
        val browserAccounts = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(browser.context
            .getValue("scopedAccountFile").jsonPrimitive.content)).decodeToString()).jsonObject
        assertEquals(setOf("owner","reader","outsider"),browserAccounts.keys)
        assertEquals(passwords.getValue("reader"),browserAccounts.getValue("reader").jsonObject
            .getValue("password").jsonPrimitive.content)
        assertFails { QualificationOfficeCaseInputs.prepareSeafile(dir,"INSTALL","WEB",pin(),
            buildJsonObject { put("scopedAccountFile","/tmp/foreign") },read(source)) }
        assertFails { QualificationOfficeCaseInputs.prepareSeafile(dir,"INSTALL","ANDROID",pin(),
            buildJsonObject { put("deviceAccountRevisionProofSha256","a".repeat(64)) },read(source)) }
        assertFalse(Files.exists(dir.resolve("owner-proofs/seafile-nativeCredentialsFile.json")))
    }

    @Test fun `Seafile restored Android scoped users match original native credentials`() = privateCase { dir ->
        val restored = QualificationOfficeCaseInputs.prepareSeafile(dir,"RESTORE","ANDROID",pin(),
            buildJsonObject {},read(source))
        assertEquals(setOf("credentialsFile","nativeCredentialsFile"),restored.context.keys)
        val scoped = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(restored.context
            .getValue("credentialsFile").jsonPrimitive.content)).decodeToString()).jsonObject
        val native = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(restored.context
            .getValue("nativeCredentialsFile").jsonPrimitive.content)).decodeToString()).jsonObject
        assertEquals(setOf("owner","outsider"),scoped.keys)
        assertEquals(native.getValue("owner"),scoped.getValue("owner"))
        assertEquals(native.getValue("outsider"),scoped.getValue("outsider"))
        assertFails { QualificationOfficeCaseInputs.prepareSeafile(dir,"INSTALL","HEADLESS",pin(),
            buildJsonObject {},read(source + ("seafile-users.json" to "{}"))) }
    }

    @Test fun `RESTORE bridges bind exact two selected native SNI leaves issuers and private address`() {
        val hosts = mapOf("office.datamancy.net" to "onlyoffice", "files.datamancy.net" to "seafile")
        val target = pin().let { it.copy(spec = it.spec.copy(fragmentBinding = RuntimeFragmentBinding(
            CanonicalSharedYamlGraph.RECIPE,"RESTORE",emptyMap()))) }
        val bundleSha = "2".repeat(64); val isolation = "3".repeat(64)
        val issuers = hosts.keys.associateWith { host ->
            ("-----BEGIN CERTIFICATE-----\n" + (if (host.startsWith("office")) "A" else "B").repeat(300) +
                "\n-----END CERTIFICATE-----\n").encodeToByteArray()
        }
        val leaves = hosts.keys.associateWith { host ->
            (if (host.startsWith("office")) "4" else "5").repeat(64)
        }
        val bindings = hosts.mapValues { (host, product) -> PrivateIngressTrustBinding(host,product,
            "front",setOf("original"),setOf("original"),PrivateIngressTrustMode.GRAPH_ISSUED_LEAF,
            "$product-web.pem","$product-web-key.pem","$product-ca.pem",
            "/run/secrets/$product-web.pem","/run/secrets/$product-web-key.pem") }
        val observations = hosts.mapValues { (host, product) -> CaddyServedLeafReadback(
            "q-012345abcdef",bundleSha,target.spec.name,target.runtimeFingerprint,"c".repeat(64),
            host,product,setOf("original"),PrivateIngressTrustMode.GRAPH_ISSUED_LEAF,
            ReleaseLocks.sha256(issuers.getValue(host)),leaves.getValue(host),listOf(host),null,
            "ingress-control") }
        val endpoints = hosts.keys.associateWith { "https://10.23.14.7:443" }
        val roots = hosts.keys.sorted().joinToString("\n",postfix="\n") {
            issuers.getValue(it).decodeToString().trimEnd()
        }.encodeToByteArray()
        fun project(pin: GenerationPin = target, ca: Map<String,ByteArray> = issuers,
            receipts: Map<String,CaddyServedLeafReadback> = observations,
            addresses: Map<String,String> = endpoints, rootsPem: ByteArray = roots,
            nativeIssuer: ByteArray? = null) =
            QualificationOfficeCaseInputs.validatedRestoreBridges("q-012345abcdef",bundleSha,
                pin,bindings,receipts,addresses,ca,leaves,rootsPem,
                ReleaseLocks.sha256(rootsPem),isolation,nativeIssuer)
        val bridged = project()
        assertEquals(setOf("bridge","bridges"),bridged.keys)
        assertEquals("office.datamancy.net",bridged.getValue("bridge").jsonObject
            .getValue("originalHost").jsonPrimitive.content)
        assertEquals("files.datamancy.net",bridged.getValue("bridges").jsonObject
            .getValue("files.datamancy.net").jsonObject.getValue("originalHost").jsonPrimitive.content)
        assertFails { project(pin = target.copy(spec = target.spec.copy(name = "q-ffffffffffff-v2"))) }
        assertFails { project(ca = issuers + ("files.datamancy.net" to "foreign".encodeToByteArray())) }
        assertFails { project(rootsPem = issuers.getValue("office.datamancy.net")) }
        val nativeIssuer = ("-----BEGIN CERTIFICATE-----\n" + "C".repeat(300) +
            "\n-----END CERTIFICATE-----\n").encodeToByteArray()
        val triple = (issuers + ("files-native.datamancy.net" to nativeIssuer)).toSortedMap()
            .values.joinToString("\n",postfix="\n") { it.decodeToString().trimEnd() }.encodeToByteArray()
        assertEquals(bridged,project(rootsPem = triple,nativeIssuer = nativeIssuer))
        assertFails { project(rootsPem = triple,nativeIssuer = "foreign".encodeToByteArray()) }
        assertFails { project(receipts = observations + ("files.datamancy.net" to
            observations.getValue("office.datamancy.net"))) }
        assertFails { project(addresses = endpoints + ("files.datamancy.net" to
            "https://10.23.14.8:443")) }
        assertFails { project(addresses = endpoints + ("files.datamancy.net" to
            "https://8.8.8.8:443")) }
    }

    @Test fun `poststart owner receipt binds raw bytes CA bridge guest and installed Seadroid`() = privateCase { dir ->
        val owner = dir.resolve("owner-proofs")
        Files.createDirectory(owner)
        Files.setPosixFilePermissions(owner, PosixFilePermissions.fromString("rwx------"))
        val invocation = "case-00000000-0000-0000-0000-000000000001"
        val generation = "q-012345abcdef"
        val context = buildJsonObject {
            put("seafileInstalledClientReceiptFile", owner.resolve("seafile-installed-client.json").toString())
            put("seafileFixtureApkSha256", "4".repeat(64)); put("caSha256", "5".repeat(64))
            put("android", buildJsonObject { put("api", 34); put("serial", "emulator-5554") })
        }
        val receipt = buildJsonObject {
            put("schemaVersion", 1); put("invocationId", invocation); put("generationId", generation)
            put("api", 34); put("serial", "emulator-5554"); put("packageName", "com.seafile.seadroid2")
            put("apkSha256", "4".repeat(64)); put("signerSha256", "6".repeat(64))
            put("guestCaAdoptionSha256", "7".repeat(64))
        }.toString().encodeToByteArray()
        ReleasePrivateFiles.save(owner.resolve("seafile-installed-client.json"), receipt)
        ReleasePrivateFiles.save(dir.resolve("qualification-guest-gate.json"), buildJsonObject {
            put("invocationId", invocation); put("containerId", "8".repeat(64))
            put("ownerBridgeSha256", "9".repeat(64))
        }.toString().encodeToByteArray())
        val trust = buildJsonObject {
            put("invocationId", invocation); put("generationId", generation)
            put("caSha256", "5".repeat(64)); put("ownerBridgeSha256", "9".repeat(64))
            put("ownerAdoptionSha256", "7".repeat(64))
            put("seafileInstalledClientReceiptSha256", ReleaseLocks.sha256(receipt))
        }
        ReleasePrivateFiles.save(dir.resolve("qualification-guest-trust-gate.json"), trust.toString().encodeToByteArray())
        assertEquals(ReleaseLocks.sha256(receipt), QualificationOfficeCaseInputs.bindPostStart(
            dir, context, invocation, generation))
        assertFails { QualificationOfficeCaseInputs.bindPostStart(dir,
            JsonObject(context + ("caSha256" to JsonPrimitive("0".repeat(64)))), invocation, generation) }
        assertFails { QualificationOfficeCaseInputs.bindPostStart(dir,
            JsonObject(context + ("seafileInstalledClientReceiptSha256" to JsonPrimitive(ReleaseLocks.sha256(receipt)))),
            invocation, generation) }
        Files.write(owner.resolve("seafile-installed-client.json"), receipt + byteArrayOf(10))
        assertFails { QualificationOfficeCaseInputs.bindPostStart(dir, context, invocation, generation) }
    }
}
