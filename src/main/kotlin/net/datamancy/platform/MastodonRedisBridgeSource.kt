package net.datamancy.platform

import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.*

/** Pure source projection for the pinned Mastodon 4.7.4 / Sidekiq 8.1.6 / SUJ 8.1.0
 * broker. The native rendered-script closure must come from an independently
 * authenticated image/source producer; never synthesize an allowed SHA list.
 * The app's original Redis keys are unprefixed, so a fictional namespace would
 * break Sidekiq. Only the broker joins the shared provider network, selecting DB1;
 * its ACL also restricts exact key families and channels, not ~* or &*.
 */
internal object MastodonRedisBridgeSource {
    private val hash = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    fun acl(backendPassword: String, ownerGeneration: String): String {
        require(hash.matches(backendPassword) && generation.matches(ownerGeneration))
        return "user mastodon-bridge on >$backendPassword " +
            listOf("feed:*", "cache:*", "queue:*", "uniquejobs:*", "subscribed:timeline:*",
                "stat:*", "sidekiq-scheduler:*", "queues", "schedule", "retry", "dead", "processes",
                "schedules", "schedules_changed", "p0v3-mastodon-$ownerGeneration:*")
                .joinToString(" ") { "~$it" } + " " +
            "&timeline:* &uniquejobs:* -@all +@read +@write +@scripting +@transaction +@pubsub " +
            "+@connection -@admin -@dangerous -flushall -flushdb -swapdb " +
            "-config -acl -monitor -migrate -restore -function -module +select +info\n"
    }

    fun inputs(ownerGeneration: String, image: AcquiredImage, providerVersion: String,
        renderedScripts: String, frontendPassword: String, backendPassword: String): Map<String, String> {
        require(generation.matches(ownerGeneration) && image.product == "mastodon" &&
            image.selectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
            providerVersion == "7.2.15" && listOf(frontendPassword, backendPassword).all(hash::matches) &&
            frontendPassword != backendPassword)
        val scripts = Json.parseToJsonElement(renderedScripts).jsonObject
        require(scripts.keys == setOf("schemaVersion", "generation", "versions", "imageManifestSha256", "renderedSha256") &&
            scripts.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            scripts.getValue("generation").jsonPrimitive.content == ownerGeneration &&
            scripts.getValue("versions").jsonArray.map { it.jsonPrimitive.content } ==
                listOf("mastodon-4.7.4", "sidekiq-8.1.6", "sidekiq-unique-jobs-8.1.0", "sidekiq-scheduler-6.0.2") &&
            scripts.getValue("imageManifestSha256").jsonPrimitive.content ==
                image.selectedManifestDigest.removePrefix("sha256:"))
        val sha = scripts.getValue("renderedSha256").jsonObject
        require(sha.size in 1..64 && sha.all { (script, digest) ->
            script.matches(Regex("[a-f0-9]{40}")) && digest.jsonPrimitive.content.matches(hash)
        })
        val scriptBytes = renderedScripts.toByteArray(StandardCharsets.UTF_8)
        require(scriptBytes.size in 1..65536 && '\u0000' !in renderedScripts)
        val scriptHash = ReleaseLocks.sha256(scriptBytes)
        val configuration = buildJsonObject {
            put("schemaVersion", 1); put("generation", ownerGeneration)
            put("versions", buildJsonArray {
                listOf("mastodon-4.7.4", "sidekiq-8.1.6", "sidekiq-unique-jobs-8.1.0",
                    "sidekiq-scheduler-6.0.2").forEach { add(it) }
            })
            put("providerAddress", "valkey"); put("providerPort", 6379)
            put("backendCredentialFile", "/run/secrets/mastodon-bridge-backend.token")
            put("frontendCredentialFile", "/run/secrets/mastodon-bridge-frontend.token")
            put("imageManifestSha256", image.selectedManifestDigest.removePrefix("sha256:"))
            put("providerVersion", providerVersion)
            put("renderedScriptsFile", "/run/secrets/mastodon-bridge-scripts.json")
            put("renderedScriptsFileSha256", scriptHash)
            put("scriptJournalDirectory", "/var/lib/mastodon-redis-bridge")
        }
        val source = requireNotNull(javaClass.getResource("/runtime/mastodon_redis_bridge.py"))
            .readText(StandardCharsets.UTF_8)
        require(source.startsWith("#!/usr/bin/env python3\n") &&
            source.contains("Only the bridge-backend ACL may SELECT DB1"))
        return mapOf("mastodon-redis-bridge.py" to source,
            "mastodon-redis-bridge.json" to configuration.toString() + "\n",
            "mastodon-bridge-scripts.json" to renderedScripts,
            "mastodon-bridge-backend.token" to backendPassword + "\n",
            "mastodon-bridge-frontend.token" to frontendPassword + "\n")
    }
}
