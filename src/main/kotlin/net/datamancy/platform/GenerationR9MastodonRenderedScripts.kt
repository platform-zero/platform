package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** V2 binding corrects OCI-export vs selected-registry manifest provenance
 * WITHOUT rewriting the original rendered script source or loading any Redis
 * script. The 13 source-rendered SHA1->SHA256 pairs come from exact pinned SUJ
 * ERB/Lua OCI bytes, not guessed allowlists or a running service observation.
 */
internal object GenerationR9MastodonRenderedScripts {
    fun issue(generation: String): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        val sourceGeneration="q-5962a9fda75b"
        // Source-rendered script bytes and their separately checked OCI export
        // are content-addressed image artifacts, not fresh installation state.
        // Never transfer an identity, a Redis SCRIPT LOAD ACK or a running DB.
        val sourceRoot=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$sourceGeneration")
        val source=ReleasePrivateFiles.read(sourceRoot.resolve("mastodon-rendered-lua-source.json"),131072)
        val original=Json.parseToJsonElement(source.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val inv=Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(root.resolve("inventory.json"),2097152)
            .decodeToString(throwOnInvalidSequence=true))
        val selected=inv.images.single { it.product=="mastodon" }
        val export=Json.parseToJsonElement(ReleasePrivateFiles.read(sourceRoot.resolve(
            "mastodon-script-export-custody.result.json"),8192).decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(original.getValue("generation").jsonPrimitive.content==sourceGeneration &&
            original.getValue("scope").jsonPrimitive.content==
                "source-only-rendered-suj-lua-from-exact-selected-oci-not-native-script-load" &&
            !original.getValue("nativeScriptLoadObserved").jsonPrimitive.boolean &&
            original.getValue("archiveSha256").jsonPrimitive.content==export.getValue("archiveSha256").jsonPrimitive.content &&
            original.getValue("imageManifestSha256").jsonPrimitive.content==
                export.getValue("ociManifestDigest").jsonPrimitive.content.removePrefix("sha256:") &&
            selected.imageId==export.getValue("imageId").jsonPrimitive.content &&
            original.getValue("renderedSha256").jsonObject.size==13 &&
            original.getValue("renderedSha256").jsonObject.all { (key,value) ->
                key.matches(Regex("[a-f0-9]{40}")) &&
                    value.jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) })
        val manifest=buildJsonObject {
            put("schemaVersion",1);put("generation",generation)
            put("versions",original.getValue("versions"))
            put("imageManifestSha256",selected.selectedManifestDigest.removePrefix("sha256:"))
            put("renderedSha256",original.getValue("renderedSha256"))
        }
        val parent=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/mastodon")
        if (!Files.exists(parent,NOFOLLOW_LINKS)) {
            Files.createDirectory(parent,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(parent.parent)
        }
        ReleasePrivateFiles.directory(parent)
        val dir=parent.resolve(generation)
        require(!Files.exists(dir,NOFOLLOW_LINKS)) { "Original rendered-script manifest already attempted" }
        Files.createDirectory(dir,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(parent)
        val file=dir.resolve("rendered-scripts.json")
        val bytes=(manifest.toString()+"\n").toByteArray()
        ReleasePrivateFiles.save(file,bytes)
        val pin=ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
        val binding=root.resolve("mastodon-rendered-script-binding-v2.json")
        require(!Files.exists(binding,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(binding,buildJsonObject {
            put("schemaVersion",2);put("generation",generation)
            put("renderedSourceSha256",ReleaseLocks.sha256(source))
            if(generation!=sourceGeneration) put("sourceGeneration",sourceGeneration)
            put("selectedImageId",selected.imageId)
            put("selectedRegistryManifest",selected.selectedManifestDigest)
            put("ociExportManifest",export.getValue("ociManifestDigest"))
            put("config",buildJsonObject { put("path",pin.path);put("sha256",pin.sha256) })
            put("nativeScriptLoadObserved",false);put("qualificationEvidence",false)
        }.toString().toByteArray())
        return pin
    }
}
