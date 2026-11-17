package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Core's native owner readback, NOT a caller-proposed path or a new notebook actuator.
 * Core must bind each path to the selected member's actual hub/alice/bob volumes,
 * original episode ACK chain and private isolated target before invoking prepare.
 * A missing readback means no qualification input is issued.
 */
internal data class HubOwnerReadback(
    val generation: String, val member: String, val runtimeFingerprint: String,
    val aliceHome: Path, val bobHome: Path, val hubDatabase: ActivationInput,
    val aliceEpisode: ActivationInput, val bobEpisode: ActivationInput,
    val volumeCustody: ActivationInput)

internal data class HubCaseInputs(val context: Map<String, JsonElement>,
    val privateFiles: List<ActivationInput>)

internal object QualificationHubCaseInputs {
    private val hex = Regex("[a-f0-9]{64}")
    private val users = setOf("alice", "bob", "outsider")
    private val json = Json { isLenient = false }

    /** Extract only actual selected Hub login passwords. Proxy/server/control tokens
     * must never be copied into a browser or Notebook qualification context. */
    internal fun passwords(bytes: ByteArray, expectedSha256: String, generation: String): Map<String,String> {
        require(bytes.size in 1..65536 && hex.matches(expectedSha256) &&
            ReleaseLocks.sha256(bytes) == expectedSha256)
        val root = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(root.getValue("notebookGeneration").jsonPrimitive.content == generation &&
            root.getValue("servers").jsonObject.keys == setOf("alice", "bob") &&
            root.getValue("passwords").jsonObject.keys == users)
        val result = root.getValue("passwords").jsonObject.mapValues { (_, value) -> value.jsonPrimitive.content }
        require(result.values.all { it.matches(hex) } && result.values.toSet().size == users.size)
        return result
    }

    /** C1 supplies sealed pins from current/held bundles; core supplies the owner-only
     * readback after observing real selected volumes and notebook episodes. There is
     * deliberately no default readback or guessed rootful Podman volume path. */
    fun prepare(caseDir: Path, target: GenerationBundle, selected: GenerationPin,
        phase: String, held: GenerationPin?, owner: HubOwnerReadback,
        settingsRead: (Path) -> ByteArray = { ReleasePrivateFiles.read(it, 65536) }): HubCaseInputs {
        require(phase in setOf("INSTALL", "RESTORE") &&
            target.request.id.matches(Regex("q-[a-f0-9]{12}")) &&
            target.members.singleOrNull() == selected &&
            selected.spec.name == "${target.request.id}-v2" &&
            NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(target.request.id), selected.spec) &&
            selected.spec.fragmentBinding?.phase == phase &&
            caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            caseDir.fileName.toString().matches(Regex("jupyter(?:hub|-notebook)--workflow--(?:web--browser|headless--native)")))
        ReleasePrivateFiles.directory(caseDir)
        val settingsPath = PrivateDeployment.BASE.resolve(selected.spec.name)
            .resolve("jupyterhub-hub-settings.json")
        val selectedSha = selected.inputHashes.getValue("jupyterhub-hub-settings.json")
        val current = passwords(settingsRead(settingsPath), selectedSha, target.request.id)
        if (phase == "RESTORE") {
            val source = requireNotNull(target.recoverySourceKopia)
            val old = requireNotNull(held)
            require(source.generation != target.request.id &&
                old.spec.name == "${source.generation}-v2" &&
                NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve(source.generation),old.spec) &&
                old.spec.fragmentBinding?.phase == "INSTALL")
            val oldBytes = settingsRead(PrivateDeployment.BASE.resolve(old.spec.name)
                .resolve("jupyterhub-hub-settings.json"))
            require(passwords(oldBytes,old.inputHashes.getValue("jupyterhub-hub-settings.json"),
                source.generation) == current) { "Restored Hub users were recreated or changed" }
        } else require(held == null && target.recoverySourceKopia == null)
        require(owner.generation == target.request.id && owner.member == selected.spec.name &&
            owner.runtimeFingerprint == selected.runtimeFingerprint &&
            owner.aliceHome != owner.bobHome &&
            listOf(owner.aliceHome,owner.bobHome).all { path ->
                path.isAbsolute && path.normalize() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
                    path.toRealPath() == path
            }) { "Core owner did not supply distinct current selected Hub homes" }
        // This checks the exact owner-issued bytes only. Core must create and validate
        // the native DB/volume/episode readbacks and authorize exact QClient mounts.
        val proofs = listOf(owner.hubDatabase,owner.aliceEpisode,owner.bobEpisode,owner.volumeCustody)
        require(proofs.map { it.path }.toSet().size == proofs.size &&
            proofs.all { pin -> hex.matches(pin.sha256) &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),1048576)) == pin.sha256 })
        val custody = json.parseToJsonElement(ReleasePrivateFiles.read(
            Path.of(owner.volumeCustody.path),65536).decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(custody.keys == setOf("schemaVersion","generation","member","runtimeFingerprint",
            "volumes","aliceHome","bobHome","hubDatabaseSha256","aliceEpisodeSha256",
            "bobEpisodeSha256") && custody.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            custody.getValue("generation").jsonPrimitive.content == owner.generation &&
            custody.getValue("member").jsonPrimitive.content == owner.member &&
            custody.getValue("runtimeFingerprint").jsonPrimitive.content == owner.runtimeFingerprint &&
            custody.getValue("volumes").jsonArray.map { it.jsonPrimitive.content }.toSet() ==
                setOf("hub","alice","bob") && custody.getValue("volumes").jsonArray.size == 3 &&
            custody.getValue("aliceHome").jsonPrimitive.content == owner.aliceHome.toString() &&
            custody.getValue("bobHome").jsonPrimitive.content == owner.bobHome.toString() &&
            custody.getValue("hubDatabaseSha256").jsonPrimitive.content == owner.hubDatabase.sha256 &&
            custody.getValue("aliceEpisodeSha256").jsonPrimitive.content == owner.aliceEpisode.sha256 &&
            custody.getValue("bobEpisodeSha256").jsonPrimitive.content == owner.bobEpisode.sha256) {
            "Core owner volume/episode custody does not bind selected Hub source"
        }
        val accounts = caseDir.resolve("owner-proofs/hub-accounts.json")
        ReleasePrivateFiles.directory(accounts.parent)
        ReleasePrivateFiles.save(accounts, JsonObject(current.mapValues { JsonPrimitive(it.value) })
            .toString().encodeToByteArray())
        val credential = ActivationInput(accounts.toString(),
            ReleaseLocks.sha256(ReleasePrivateFiles.read(accounts,65536)))
        return HubCaseInputs(mapOf(
            "managedHub" to JsonPrimitive(true),
            "origin" to JsonPrimitive("https://notebooks.datamancy.net/"),
            "endpoint" to JsonPrimitive("https://notebooks.datamancy.net/"), "hubAccountFile" to JsonPrimitive(accounts.toString()),
            "hubAccountSha256" to JsonPrimitive(credential.sha256),
            "aliceHomeReadOnlyPath" to JsonPrimitive(owner.aliceHome.toString()),
            "bobHomeReadOnlyPath" to JsonPrimitive(owner.bobHome.toString()),
            "hubDatabaseReadOnlyFile" to JsonPrimitive(owner.hubDatabase.path),
            "hubDatabaseSha256" to JsonPrimitive(owner.hubDatabase.sha256),
            "hubOwnerVolumeCustodyFile" to JsonPrimitive(owner.volumeCustody.path),
            "hubOwnerVolumeCustodySha256" to JsonPrimitive(owner.volumeCustody.sha256),
            "hubAliceEpisodeFile" to JsonPrimitive(owner.aliceEpisode.path),
            "hubAliceEpisodeSha256" to JsonPrimitive(owner.aliceEpisode.sha256),
            "hubBobEpisodeFile" to JsonPrimitive(owner.bobEpisode.path),
            "hubBobEpisodeSha256" to JsonPrimitive(owner.bobEpisode.sha256)),
            proofs + credential)
    }
}
