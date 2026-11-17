package net.datamancy.platform

/** Parser only, NOT a credential grant or admission result. Forgejo prints the generated
 * password before it creates the account; the eventual initializer exit and native account
 * readback must be authenticated separately under the owner lock before custody/retirement.
 * Forgejo 17's generator can include quotes/backslashes/spaces: parse from the known suffix,
 * not by splitting at a quote or assuming the password is hexadecimal.
 */
internal object ForgejoBootstrapResult {
    private val prefix = "generated random password is '"
    private val suffix = "'\nNew user 'p0v3-bootstrap' has been successfully created!\n"

    internal class Candidate internal constructor(internal val password: String) {
        override fun toString() = "Forgejo bootstrap candidate [redacted; not custody]"
    }

    fun parse(original: ByteArray): Candidate {
        require(original.size in 1..512) { "Invalid Forgejo original bootstrap output" }
        val output = original.decodeToString(throwOnInvalidSequence = true)
        require(output.startsWith(prefix) && output.endsWith(suffix)) { "Invalid Forgejo original bootstrap output" }
        val password = output.substring(prefix.length, output.length - suffix.length)
        require(password.length == 64 && password.all { it.code in 0x20..0x7e } &&
            password.first() != ' ' && password.last() != ' ') { "Invalid Forgejo original bootstrap output" }
        return Candidate(password)
    }
}
