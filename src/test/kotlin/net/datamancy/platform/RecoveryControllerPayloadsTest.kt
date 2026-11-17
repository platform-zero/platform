package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

class RecoveryControllerPayloadsTest {
    private fun directory(path: Path) = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun file(path: Path, text: String) {
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.writeString(path, text)
    }
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("controller-payload-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try { block(generation(root)) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun generation(parent: Path): Path {
        val root = directory(parent.resolve("q-123456789abc"))
        val bundle = GenerationBundle(GenerationRequest(id = root.fileName.toString(),
            candidateSha256 = "b".repeat(64), members = emptyList(), diskReservationMiB = 1024), emptyList(), 0)
        file(root.resolve("bundle.json"), Json.encodeToString(bundle))
        return root
    }
    @Test fun `only declared nonauthority fixture subtree is captured and imported without replay`() = fixture { root ->
        val source = generation(root)
        val fixture = directory(directory(source.resolve("rss-qualification")).resolve("invocation-1"))
        val state = directory(fixture.resolve("state"))
        file(state.resolve("rss-state.json"), "{\"original\":true}")
        file(state.resolve("rss-state.lock"), "legacy-local-lock-never-copied\n")
        file(fixture.resolve("feed-items.json"), "{\"fixture\":\"original\"}")
        for (original in listOf("fixture-ca.pem", "mastodon-ca.pem", "native-fixture-binding.json", "native-fixture-state.json",
            "native-accepted.json", "native-receipt.json", "native-remote-evidence.json", "native-pending.json"))
            file(fixture.resolve(original), "original-$original")
        file(source.resolve("activation.permit"), "must never restore")
        val payloads = linkedMapOf<String, Path>()
        val names = RecoveryControllerPayloads.capture(source, payloads)
        assertEquals(10, names.size)
        assertFalse(names.any { it.endsWith(".lock") })
        assertTrue(names.all { it.startsWith("controller/rss-qualification/invocation-1/") })
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = "q-123456789abc", bundleSha256 = "a".repeat(64),
            members = emptyList(), files = RecoveryCapsule.describe(payloads), controllerFiles = names)
        RecoveryControllerPayloads.validate(manifest)
        val recoveredRoot = directory(root.resolve("recovered"))
        for ((name, original) in payloads) {
            var parent = recoveredRoot
            for (part in name.split('/').dropLast(1)) {
                parent = parent.resolve(part)
                if (!Files.exists(parent)) directory(parent)
            }
            file(recoveredRoot.resolve(name), Files.readString(original))
        }
        val bundle = GenerationBundle(GenerationRequest(id = manifest.generation, candidateSha256 = "b".repeat(64), members = emptyList(), diskReservationMiB = 1024), emptyList(), 0)
        val recovered = RecoveredGeneration(bundle, manifest, recoveredRoot,
            GenerationRecoveryCheck(manifest.generation, manifest.id, manifest.bundleSha256, "", emptyList()))
        val target = directory(root.resolve("target"))
        RecoveryControllerPayloads.restore(recovered, target)
        assertEquals("{\"original\":true}", Files.readString(target.resolve("rss-qualification/invocation-1/state/rss-state.json")))
        assertFalse(Files.exists(target.resolve("activation.permit")))
        for (original in listOf("fixture-ca.pem", "mastodon-ca.pem", "native-fixture-binding.json", "native-fixture-state.json",
            "native-accepted.json", "native-receipt.json", "native-remote-evidence.json", "native-pending.json"))
            assertEquals("original-$original", Files.readString(target.resolve("rss-qualification/invocation-1/$original")))
        assertEquals("rss-state-lock-v1\n", Files.readString(target.resolve("rss-qualification/invocation-1/state/rss-state.lock")))
        assertFails { RecoveryControllerPayloads.restore(recovered, target) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles = names + names.first())) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(files = manifest.files +
            CapsuleFile("controller/rss-qualification/invocation-1/activation.permit", 1, "a".repeat(64)))) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles = listOf("controller/schedule/enabled.json"))) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles =
            listOf("controller/qualification-actors/manifest.json"))) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles =
            listOf("controller/qualification-actors/bookstack-owner.json"))) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles = listOf("controller/rss-qualification/invocation-1/activation.permit"))) }
        file(fixture.resolve("activation.permit"), "no public authority")
        assertFails { RecoveryControllerPayloads.capture(source, linkedMapOf()) }
        val fresh = directory(root.resolve("fresh"))
        Files.writeString(recoveredRoot.resolve(names.first()), "changed")
        assertFails { RecoveryControllerPayloads.restore(recovered, fresh) }
    }
    @Test fun `INSTALL first use takes sealed original files before custody while RESTORE requires imported custody`() = fixture { root ->
        val source = generation(root)
        val originalInputs = directory(source.resolve("qualification-original-actors"))
        val context = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        for ((role, field, username) in listOf(
            Triple("owner", "ownerCredentialFile", "owner"),
            Triple("outsider", "outsiderCredentialFile", "outsider"),
            Triple("appNonMember", "appNonMemberCredentialFile", "app-nonmember"),
            Triple("sso-owner", "ownerSsoCredentialFile", "owner"),
            Triple("sso-appNonMember", "appNonMemberSsoCredentialFile", "app-nonmember"),
            Triple("sso-outsider", "gatewayOutsiderSsoCredentialFile", "outsider"))) {
            val actor = originalInputs.resolve("donetick-$role.json")
            file(actor, "{\"username\":\"$username\",\"password\":\"${ReleaseLocks.sha256(role.toByteArray())}\"}")
            context[field] = kotlinx.serialization.json.JsonPrimitive(actor.toString())
        }
        context["appNonMemberSubject"] = kotlinx.serialization.json.JsonPrimitive("app-nonmember")
        context["gatewayOutsiderSubject"] = kotlinx.serialization.json.JsonPrimitive("outsider")
        for ((i, field) in listOf("ownerIssuerSubjectUuid", "appNonMemberIssuerSubjectUuid",
            "gatewayOutsiderIssuerSubjectUuid").withIndex())
            context[field] = kotlinx.serialization.json.JsonPrimitive("00000000-0000-4000-8000-00000000000${i + 1}")
        val original = kotlinx.serialization.json.JsonObject(context)
        assertFalse(Files.exists(source.resolve("qualification-actors/manifest.json")))
        val (prepared, pins) = RecoveryActorCustody.pinInstall(source, "donetick", original)
        assertEquals(original, prepared)
        assertEquals(6, pins.size)
        assertEquals(6, pins.map { it.sha256 }.toSet().size)
        assertFails { RecoveryActorCustody.project(source, directory(root.resolve("q-aaaaaaaaaaaa")),
            ReleaseLocks.sha256(Files.readAllBytes(source.resolve("bundle.json"))), "donetick",
            "a".repeat(64), original) }
        assertFalse(Files.exists(source.resolve("qualification-actors/manifest.json")))
        val foreign = source.resolve("foreign-owner.json")
        file(foreign, Files.readString(originalInputs.resolve("donetick-owner.json")))
        assertFails { RecoveryActorCustody.pinInstall(source, "donetick",
            kotlinx.serialization.json.JsonObject(context +
                ("ownerCredentialFile" to kotlinx.serialization.json.JsonPrimitive(foreign.toString())))) }
        Files.writeString(originalInputs.resolve("donetick-owner.json"), "tampered")
        assertFails { RecoveryActorCustody.pinInstall(source, "donetick", original) }
    }
    @Test fun `original actor custody is sealed and restored without minting target grants`() = fixture { root ->
        val source = generation(root)
        val issuer = directory(source.resolve("issued"))
        val services = listOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick")
        val grants = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        for (service in services) {
            val account = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
            for (role in listOf("owner", "outsider")) {
                val path = issuer.resolve("$service-$role.json")
                val username = if (service == "donetick") role else "$role@$service.test"
                file(path, "{\"username\":\"$username\",\"password\":\"${ReleaseLocks.sha256("$service-$role".toByteArray())}\"}")
                account["${role}CredentialFile"] = kotlinx.serialization.json.JsonPrimitive(path.toString())
            }
            if (service == "donetick") for ((role, field, username) in listOf(
                Triple("appNonMember", "appNonMemberCredentialFile", "app-nonmember"),
                Triple("sso-owner", "ownerSsoCredentialFile", "owner"),
                Triple("sso-appNonMember", "appNonMemberSsoCredentialFile", "app-nonmember"),
                Triple("sso-outsider", "gatewayOutsiderSsoCredentialFile", "outsider"))) {
                val path = issuer.resolve("$service-$role.json")
                file(path, "{\"username\":\"$username\",\"password\":\"${ReleaseLocks.sha256("$service-$role".toByteArray())}\"}")
                account[field] = kotlinx.serialization.json.JsonPrimitive(path.toString())
            }
            if (service == "bookstack") for (role in listOf("owner", "outsider")) {
                val path = issuer.resolve("api-$role.json")
                file(path, "{\"tokenId\":\"p0v3-${ReleaseLocks.sha256("id-$role".toByteArray()).take(32)}\",\"secret\":\"${ReleaseLocks.sha256("secret-$role".toByteArray())}\"}")
                account[if (role == "owner") "bookstackApiGrantFile" else "outsiderBookstackApiGrantFile"] =
                    kotlinx.serialization.json.JsonPrimitive(path.toString())
            }
            if (service == "donetick") {
                account["appNonMemberSubject"] = kotlinx.serialization.json.JsonPrimitive("app-nonmember")
                account["gatewayOutsiderSubject"] = kotlinx.serialization.json.JsonPrimitive("outsider")
                for ((i, field) in listOf("ownerIssuerSubjectUuid", "appNonMemberIssuerSubjectUuid",
                    "gatewayOutsiderIssuerSubjectUuid").withIndex())
                    account[field] = kotlinx.serialization.json.JsonPrimitive("00000000-0000-4000-8000-00000000000${i + 1}")
            }
            grants["$service--native--headless--native"] = kotlinx.serialization.json.JsonObject(account)
        }
        val context = source.resolve("original-contexts.json")
        file(context, Json.encodeToString(kotlinx.serialization.json.JsonObject(grants)))
        val originalBundle = ReleaseLocks.sha256(Files.readAllBytes(source.resolve("bundle.json")))
        val originalContext = ActivationInput(context.toString(), ReleaseLocks.sha256(Files.readAllBytes(context)))
        val native = directory(source.resolve("qualification-issuance-native"))
        val issuerPins = services.associateWith { service ->
            val nativePath = native.resolve("$service.json")
            val original = grants.getValue("$service--native--headless--native") as kotlinx.serialization.json.JsonObject
            val credentialKeys = listOf("ownerCredentialFile", "outsiderCredentialFile") +
                (if (service == "bookstack") listOf("bookstackApiGrantFile", "outsiderBookstackApiGrantFile") else emptyList()) +
                (if (service == "donetick") listOf("appNonMemberCredentialFile", "ownerSsoCredentialFile", "appNonMemberSsoCredentialFile", "gatewayOutsiderSsoCredentialFile") else emptyList())
            val names = listOf("$service.owner", "$service.outsider") +
                (if (service == "bookstack") listOf("bookstack.api-owner", "bookstack.api-outsider") else emptyList()) +
                (if (service == "donetick") listOf("donetick.appNonMember", "donetick.sso-owner", "donetick.sso-appNonMember", "donetick.sso-outsider") else emptyList())
            val hashes = credentialKeys.zip(names).associate { (key, name) ->
                name to ReleaseLocks.sha256(Files.readAllBytes(Path.of(original.getValue(key)
                    .let { (it as kotlinx.serialization.json.JsonPrimitive).content })))
            }
            val issuerKind = mapOf("bookstack" to "native-bookstack-grant-readback",
                "erpnext" to "native-erp-actor-readback", "firefly-iii" to "native-finance-credential-issuance",
                "forgejo" to "native-forgejo-actor-readback", "donetick" to "native-donetick-actor-readback").getValue(service)
            file(nativePath, Json.encodeToString(RecoveryActorNativeIssuanceProof(
                generation = source.fileName.toString(), bundleSha256 = originalBundle,
                originalContextsSha256 = originalContext.sha256, service = service, issuerKind = issuerKind,
                credentialSha256 = hashes, ownerSubject = if (service == "donetick") "owner" else "owner@$service.test",
                outsiderSubject = if (service == "donetick") "outsider" else "outsider@$service.test"))) // source-only injected; not runtime proof
            val nativePin = ActivationInput(nativePath.toString(), ReleaseLocks.sha256(Files.readAllBytes(nativePath)))
            val receipt = RecoveryActorIssuanceReadback(sourceGeneration = source.fileName.toString(),
                sourceBundleSha256 = originalBundle, originalContextsSha256 = originalContext.sha256,
                service = service, issuerKind = issuerKind,
                credentialSha256 = hashes,
                originalOwner = if (service == "donetick") "owner" else "owner@$service.test",
                originalOutsider = if (service == "donetick") "outsider" else "outsider@$service.test",
                nativeEvidence = nativePin)
            val path = issuer.resolve("$service-readback.json")
            file(path, Json.encodeToString(receipt))
            ActivationInput(path.toString(), ReleaseLocks.sha256(Files.readAllBytes(path)))
        }
        val staged = RecoveryActorCustody.stage(source, originalBundle, originalContext, issuerPins)
        assertFails { RecoveryActorCustody.stage(source, originalBundle, originalContext, issuerPins) }
        val payloads = linkedMapOf<String, Path>()
        val names = RecoveryControllerPayloads.capture(source, payloads)
        assertEquals(22, names.size)
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = source.fileName.toString(),
            bundleSha256 = originalBundle, members = emptyList(), files = RecoveryCapsule.describe(payloads), controllerFiles = names)
        RecoveryControllerPayloads.validate(manifest)
        val extracted = directory(root.resolve("extracted"))
        for ((name, original) in payloads) {
            var parent = extracted
            for (part in name.split('/').dropLast(1)) {
                parent = parent.resolve(part)
                if (!Files.exists(parent)) directory(parent)
            }
            file(extracted.resolve(name), Files.readString(original))
        }
        val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(source.resolve("bundle.json")))
        val recovered = RecoveredGeneration(bundle, manifest, extracted,
            GenerationRecoveryCheck(manifest.generation, manifest.id, originalBundle, "", emptyList()))
        val target = directory(root.resolve("q-aaaaaaaaaaaa"))
        RecoveryControllerPayloads.restore(recovered, target)
        val originalCase = grants.getValue("bookstack--native--headless--native").let { it as kotlinx.serialization.json.JsonObject }
        val (projected, pins) = RecoveryActorCustody.project(source, target, originalBundle,
            "bookstack", originalContext.sha256, originalCase)
        assertEquals(4, pins.size)
        assertTrue(pins.all { Path.of(it.path).parent == target.resolve("qualification-actors") })
        assertEquals(staged, RecoveryActorCustody.verify(target, source.fileName.toString(), originalBundle))
        assertNotEquals(originalCase["ownerCredentialFile"], projected["ownerCredentialFile"])
        val donetickCase = grants.getValue("donetick--native--headless--native") as kotlinx.serialization.json.JsonObject
        val (donetickRestored, donetickPins) = RecoveryActorCustody.project(source, target, originalBundle,
            "donetick", originalContext.sha256, donetickCase)
        assertEquals(6, donetickPins.size)
        assertTrue(DonetickTripleActorContext.credentialFields.all { donetickRestored[it] != donetickCase[it] })
        assertFails { RecoveryControllerPayloads.restore(recovered, target) }
        Files.writeString(target.resolve("qualification-actors/bookstack-owner.json"), "tampered")
        assertFails { RecoveryActorCustody.verify(target, source.fileName.toString(), originalBundle) }
    }
    @Test fun `missing subtree is legacy compatible and unsafe trees are rejected`() = fixture { root ->
        val payloads = linkedMapOf<String, Path>()
        assertTrue(RecoveryControllerPayloads.capture(root, payloads).isEmpty())
        val subtree = directory(root.resolve("rss-qualification"))
        val invocation = directory(subtree.resolve("invocation-1"))
        file(root.resolve("outside"), "private original")
        Files.createSymbolicLink(invocation.resolve("feed-items.json"), root.resolve("outside"))
        assertFails { RecoveryControllerPayloads.capture(root, payloads) }
        Files.delete(invocation.resolve("feed-items.json"))
        file(invocation.resolve("feed-items.json"), "original")
        Thread.currentThread().interrupt()
        try { assertFailsWith<InterruptedException> { RecoveryControllerPayloads.capture(root, payloads) } }
        finally { assertTrue(Thread.interrupted()) }
        Files.setPosixFilePermissions(invocation, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFails { RecoveryControllerPayloads.capture(root, payloads) }
    }
}
