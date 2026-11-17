package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.Json

/** Original helper names are immutable. Only an already-journaled second or later
 * user episode gets disjoint intent/result names. A partial prior episode never
 * authorizes a new suffix, even if the unit appears stopped in systemd.
 */
internal object NotebookEpisodePaths {
    fun suffix(root: Path, member: String, process: String): String {
        if (process !in setOf("alice","bob") || !member.startsWith("${root.fileName}-")) return ""
        val directory = root.resolve("notebooks/episodes/$process")
        if (Files.exists(directory,NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)
            val bundle = Json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence=true))
            require(bundle.request.id == root.fileName.toString() &&
                NotebookSelectedGraph.selected(root,bundle.members.single { it.spec.name == member }.spec)) {
                "Notebook episode is not selected by the sealed full generation graph"
            }
        }
        if (!Files.exists(directory,NOFOLLOW_LINKS)) return ""
        ReleasePrivateFiles.directory(directory)
        val intents = Files.list(directory).use { stream -> stream.toList().map { it.fileName.toString() }
            .filter { it.matches(Regex("[0-9]{4}\\.intent\\.json")) } }
        if (intents.isEmpty()) return ""
        val number = intents.maxOf { it.substringBefore('.').toInt() }
        require(number in 1..64 && intents.size == number &&
            (1..number).all { "%04d.intent.json".format(it) in intents })
        if (number == 1) return ""
        val intent = Json.decodeFromString<NotebookEpisodeIntent>(ReleasePrivateFiles.read(
            directory.resolve("%04d.intent.json".format(number)),8192).decodeToString(throwOnInvalidSequence=true))
        require(intent.generation == root.fileName.toString() && intent.member == member &&
            intent.user == process && intent.ordinal == number &&
            intent.previousTerminalSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                directory.resolve("%04d.terminal.json".format(number-1)),8192))) {
            "Notebook prior episode has no bound terminal evidence"
        }
        return ".episode-%04d".format(number)
    }
    fun path(root: Path, stem: String, member: String, process: String): Path =
        root.resolve(stem + suffix(root,member,process) + ".json")
}
