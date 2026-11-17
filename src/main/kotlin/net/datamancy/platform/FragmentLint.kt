package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable

@Serializable internal data class FragmentLintReport(
    val schemaVersion: Int = 1, val sourceSha256: String, val fragment: String, val revision: Int,
    val product: String, val installProcesses: Int, val restoreProcesses: Int,
    val localDeclarationValid: Boolean = true, val runtimeAdmitted: Boolean = false,
    val fullGraphValidated: Boolean = false, val qualificationEvidence: Boolean = false)

/** Unprivileged, read-only arbitrary-file linting. Cannot register, prepare or execute a recipe. */
internal object FragmentLint {
    fun inspect(path: Path): FragmentLintReport {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "Fragment lint requires a regular non-symlink file" }
        val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(FragmentYaml.MAX_BYTES + 1) }
        val fragment = GraphFragment.lint(bytes)
        return FragmentLintReport(sourceSha256 = ReleaseLocks.sha256(bytes), fragment = fragment.id,
            revision = fragment.revision, product = fragment.product,
            installProcesses = fragment.install.processes.size, restoreProcesses = fragment.restore.processes.size)
    }
}
