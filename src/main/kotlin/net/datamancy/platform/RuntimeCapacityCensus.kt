package net.datamancy.platform

/** One bounded, read-only native container census per store for capacity release.
 * An isolated generation's historical per-resource audit executed thousands of
 * independent Podman network/volume inspections for the same unchanged namespace.
 * Reservation release needs current *process quiescence* and the exact original
 * maintenance fence, not a fresh read of every retained network and volume.
 * All retired member locks are held across the census and fence verification.
 */
internal class RuntimeCapacityCensus(
    private val commands: (RuntimeStore) -> RuntimeCommands = { PrivateRootfulCommands(120, it) }) {
    internal data class Container(val cid: String, val name: String, val state: String,
        val member: String, val fingerprint: String)
    internal data class Member(val spec: PrivateDeploymentSpec, val fingerprint: String)
    fun snapshot(store: RuntimeStore): List<Container> {
        val response = commands(store).run(listOf("ps", "-a", "--no-trunc", "--format",
            "{{.ID}}\t{{.Names}}\t{{.State}}\t{{.Label \"io.p0v3.private-deployment\"}}\t{{.Label \"io.p0v3.runtime-fingerprint\"}}"))
        require(response.exitCode == 0 && response.output.toByteArray().size <= 2_000_000) {
            "Native capacity container census missing or oversized"
        }
        val rows = response.output.lineSequence().filter { it.isNotBlank() }.take(4097).map { line ->
            val fields = line.split('\t')
            require(fields.size == 5 && fields[0].matches(Regex("[a-f0-9]{64}")) &&
                fields[1].length in 1..255 && fields[2] in
                    setOf("configured", "created", "running", "paused", "restarting", "stopping", "exited", "unknown")) {
                "Unrecognized native capacity process state"
            }
            Container(fields[0], fields[1], fields[2], fields[3], fields[4])
        }.toList()
        require(rows.size <= 4096 && rows.map { it.cid }.distinct().size == rows.size) {
            "Unbounded or ambiguous native capacity process census"
        }
        return rows
    }
    /** Full bidirectional owner/name binding, not label-only filtering. A renamed
     * container, missing/foreign label on an expected name, unfamiliar process in
     * an owned namespace, or duplicate expected identity retains the reservation.
     */
    fun quiescent(members: List<Member>, observed: List<Container>): Boolean {
        if (members.map { it.spec.name }.distinct().size != members.size) return false
        val expected = members.flatMap { owner -> owner.spec.processes.map { p ->
            "p0v3-live-${owner.spec.name}-${p.id}" to owner
        } }.toMap()
        if (expected.size != members.sumOf { it.spec.processes.size }) return false
        val owners = members.associateBy { it.spec.name }
        val prefixes = owners.keys.map { "p0v3-live-$it-" }
        val named = observed.filter { it.name in expected }
        if (named.map { it.name }.distinct().size != named.size) return false
        return observed.all { container ->
            val namedOwner = expected[container.name]
            val labelledOwner = owners[container.member]
            val inOwnedNamespace = prefixes.any { container.name.startsWith(it) }
            if (namedOwner == null && labelledOwner == null && !inOwnedNamespace) true
            else namedOwner != null && labelledOwner == namedOwner &&
                container.fingerprint == namedOwner.fingerprint &&
                container.state in setOf("created", "configured", "exited")
        }
    }
}
