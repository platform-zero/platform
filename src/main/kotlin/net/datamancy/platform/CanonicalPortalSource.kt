package net.datamancy.platform

/** Homepage configuration comes only from owned, exact approved routes. It never
 * manufactures an upstream, publishes a private service or embeds an auth token.
 * Acquired Homepage and an authenticated ingress are separate admission gates.
 */
internal object CanonicalPortalSource {
    fun inputs(routes: List<SiteRouteOwner>, approved: Set<String>, selectedR9: Boolean = false): Map<String, String> {
        val full = selectedR9 || CanonicalSharedYamlGraph.manifest().revision == 9
        require(routes.isNotEmpty() && routes.map { it.host }.distinct().size == routes.size &&
            routes.all { it.host in approved && (it.host.matches(Regex("[a-z0-9-]+\\.datamancy\\.net")) ||
                full && (it.host == "datamancy.net" ||
                    it.host.matches(Regex("[a-z0-9-]+\\.[a-z0-9-]+\\.datamancy\\.net")))) &&
                it.product.matches(Regex("[a-z][a-z0-9-]{0,63}")) })
        val yaml = buildString {
            append("- Platform Zero:\n")
            routes.sortedBy { it.host }.forEach { route ->
                append("    - ").append(route.product).append(":\n")
                append("        href: https://").append(route.host).append("/\n")
                append("        description: Private, owner-controlled route\n")
            }
        }
        return mapOf("portal-settings.yaml" to "title: Platform Zero\nheaderStyle: clean\n" +
            "hideVersion: true\nshowStats: false\n",
            "portal-services.yaml" to yaml, "portal-widgets.yaml" to "[]\n")
    }
}
