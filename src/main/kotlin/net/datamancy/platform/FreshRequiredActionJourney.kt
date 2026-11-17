package net.datamancy.platform

import kotlinx.serialization.json.*

/** Fresh Keycloak owns the approved folded onboarding journey. No separate
 * registration daemon: only admin-created subjects with temporary credentials
 * may complete UPDATE_PASSWORD + CONFIGURE_TOTP on the first browser login.
 * These source assertions do NOT substitute for post-login native readback.
 */
internal object FreshRequiredActionJourney {
    const val ISSUER = "https://auth.datamancy.net/realms/p0v3"
    const val LANDING = "$ISSUER/account/"
    private val actions = setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP")

    fun requireImportedSource(realmJson: String, fresh: FreshIdentityBootstrap) {
        fresh.validate()
        val realm = Json.parseToJsonElement(realmJson).jsonObject
        require(realm.getValue("realm").jsonPrimitive.content == "p0v3" &&
            realm.getValue("registrationAllowed").jsonPrimitive.boolean == false &&
            realm.getValue("resetPasswordAllowed").jsonPrimitive.boolean == false &&
            realm.getValue("sslRequired").jsonPrimitive.content == "all" &&
            realm.getValue("actionTokenGeneratedByAdminLifespan").jsonPrimitive.int == 1800)
        val enabled = realm.getValue("requiredActions").jsonArray.map { it.jsonObject }.filter {
            it.getValue("enabled").jsonPrimitive.boolean && it.getValue("defaultAction").jsonPrimitive.boolean
        }.map { it.getValue("alias").jsonPrimitive.content }.toSet()
        require(enabled == actions)
        val users = realm.getValue("users").jsonArray.map { it.jsonObject }
        for ((name, uuid) in listOf("owner" to fresh.ownerUuid, "outsider" to fresh.outsiderUuid,
            "app-nonmember" to fresh.appNonMemberUuid)) {
            val user = users.single { it.getValue("username").jsonPrimitive.content == name }
            require(user.getValue("id").jsonPrimitive.content == uuid &&
                user.getValue("groups").jsonArray.map { it.jsonPrimitive.content }.toSet() ==
                    fresh.memberships().getValue(uuid) && user.getValue("enabled").jsonPrimitive.boolean &&
                user.getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet() == actions &&
                user.getValue("credentials").jsonArray.single().jsonObject.let {
                    it.getValue("type").jsonPrimitive.content == "password" &&
                        it.getValue("temporary").jsonPrimitive.boolean &&
                        it.getValue("value").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}"))
                })
        }
        require(users.none { it["username"]?.jsonPrimitive?.content in setOf("guest", "anonymous") })
    }

    /** Verified account readback AFTER Keycloak itself completes the actions;
     * merely landing on the account page never qualifies as enrollment. */
    fun requireCompleted(subject: String, userJson: String, credentialJson: String, fresh: FreshIdentityBootstrap) {
        fresh.validate()
        require(subject in setOf(fresh.ownerUuid, fresh.outsiderUuid, fresh.appNonMemberUuid))
        val user = Json.parseToJsonElement(userJson).jsonObject
        val credentials = Json.parseToJsonElement(credentialJson).jsonArray.map { it.jsonObject }
        require(user.getValue("id").jsonPrimitive.content == subject &&
            user.getValue("enabled").jsonPrimitive.boolean &&
            user.getValue("requiredActions").jsonArray.isEmpty() &&
            credentials.count { it.getValue("type").jsonPrimitive.content == "otp" } == 1 &&
            credentials.any { it.getValue("type").jsonPrimitive.content == "password" &&
                it["temporary"]?.jsonPrimitive?.booleanOrNull != true }) {
            "Required actions and native TOTP/password readback are not complete"
        }
    }
}
