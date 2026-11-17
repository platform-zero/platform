package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Honest, versioned developer source provenance; NOT a frozen release lock,
 * signed candidate, controller tree, native acceptance or qualification pass.
 */
internal object GenerationR9DevelopmentProvenance {
    fun issue(generation: String): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(anchor)
        val sources=linkedMapOf(
            "developmentControllerJar" to Path.of("/home/gerald/p0_v3/platform/build/install/p0-v3-platform/lib/p0-v3-platform.jar"),
            "selectedR9Index" to Path.of("/home/gerald/p0_v3/platform/src/main/resources/fragments/v3/canonical/r9/index.yaml"),
            "selectedR9Manifest" to Path.of("/home/gerald/p0_v3/platform/src/main/resources/fragments/v3/canonical/r9/manifest.yaml"),
            "nativeImageReadback" to anchor.resolve("whole-image-store.readback.json"),
            "graphPortalRoutes" to anchor.resolve("graph-portal-routes.json"),
            "rssSourceClosure" to anchor.resolve("rss-source-artifact-closure.json"),
            "forgejoCiSourcePlan" to anchor.resolve("forgejo-ci-source.json"),
            "freshBaoIssuerSource" to Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/FreshOpenBaoBootstrap.kt"),
            "mastodonRedisBridgeSourceNotRenderedLua" to Path.of("/home/gerald/p0_v3/platform/src/main/resources/runtime/mastodon_redis_bridge.py"),
            "originalDonetickGatewayRunnerSource" to Path.of("/home/gerald/p0_v3/acceptance/runners/donetick-native.py"))
        val pins=sources.mapValues { (_,path) ->
            require(Files.isRegularFile(path,NOFOLLOW_LINKS) && !Files.isSymbolicLink(path))
            ReleaseLocks.sha256(Files.readAllBytes(path))
        }
        val bytes=buildJsonObject {
            put("schemaVersion",1);put("generation",generation)
            put("scope","r9-development-private-source-provenance-not-signed-release-candidate")
            put("releaseCandidateFrozen",false);put("controllerTreeInstalled",false)
            put("nativeApplicationStartup",false);put("qualificationEvidence",false)
            put("sourceHashes",buildJsonObject { pins.forEach { (name,digest) -> put(name,digest) } })
        }.toString().toByteArray()
        val file=anchor.resolve("development-provenance-r1.json")
        require(!Files.exists(file,NOFOLLOW_LINKS)) { "Prior developer source snapshot exists; version rather than rewrite" }
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
