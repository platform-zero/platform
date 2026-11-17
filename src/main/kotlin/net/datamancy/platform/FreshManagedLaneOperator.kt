package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

@Serializable internal enum class FreshLaneAction { START, STOP }
@Serializable internal data class FreshLaneActionIntent(val generation: String, val laneId: String,
    val ownerSubject: String, val identityHead: String, val action: FreshLaneAction,
    val requestId: String, val ordinal: Int, val previousResultSha256: String?)
@Serializable internal data class FreshLaneActionResult(val intentSha256: String, val action: FreshLaneAction,
    val worklaneResultSha256: String, val nativePhysicalRunning: Boolean,
    val deliveryTokenSha256: String? = null, val tuiosResultSha256: String? = null,
    val piResultSha256: String? = null)

/** The supervised host broker is OUTSIDE the physical Worklane container it
 * stops. All effects run under the release's controller/generation/ordered-member
 * locks; original Worklane and broker receipts remain immutable. No generic
 * command, unit name, arbitrary lane, or uncertain-effect replay enters this API.
 */
internal class FreshManagedLaneOperator(private val plan: ManagedLanePlan, private val root: Path,
    private val broker: ManagedLaneBroker, private val authority: ManagedLaneAuthority,
    private val identityHead: String) {
    private val journal = root.resolve("managed/control/lane-ops")
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    init { plan.validate(plan.generation); require(root == GenerationRuntime.BASE.resolve(plan.generation) &&
        identityHead.matches(Regex("[a-f0-9]{64}"))) }
    private fun prepare() {
        ReleasePrivateFiles.directory(journal.parent)
        if (!Files.exists(journal, NOFOLLOW_LINKS)) Files.createDirectory(journal,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(journal)
    }
    private fun history(): List<Pair<FreshLaneActionIntent,FreshLaneActionResult>> {
        prepare()
        val files = Files.list(journal).use { it.toList() }
        require(files.size <= 128 && files.all { it.fileName.toString().matches(Regex("[0-9]{4}\\.(intent|result)\\.json")) })
        val count = files.count { it.fileName.toString().endsWith(".intent.json") }
        require(count <= 64 && files.size == count * 2) { "Uncertain typed lane operation; no new native effect" }
        return (1..count).map { number ->
            val key = "%04d".format(number)
            val bytes = ReleasePrivateFiles.read(journal.resolve("$key.intent.json"), 4096)
            val intent = json.decodeFromString<FreshLaneActionIntent>(bytes.decodeToString(throwOnInvalidSequence=true))
            val result = json.decodeFromString<FreshLaneActionResult>(
                ReleasePrivateFiles.read(journal.resolve("$key.result.json"),4096).decodeToString(throwOnInvalidSequence=true))
            require(intent.ordinal == number && intent.generation == plan.generation &&
                intent.laneId == plan.lanes.first().laneId && intent.ownerSubject == plan.ownerSubject &&
                intent.identityHead == identityHead && intent.requestId.matches(Regex("[a-f0-9]{32}")) &&
                intent.previousResultSha256 == (if (number == 1) null else ReleaseLocks.sha256(
                    ReleasePrivateFiles.read(journal.resolve("%04d.result.json".format(number-1)),4096))) &&
                result.intentSha256 == ReleaseLocks.sha256(bytes) && result.action == intent.action &&
                result.nativePhysicalRunning == (intent.action == FreshLaneAction.START)) {
                "Foreign or altered lane lifecycle journal"
            }
            intent to result
        }
    }
    fun status(): Boolean {
        val entries = history()
        val expected = entries.lastOrNull()?.first?.action != FreshLaneAction.STOP
        val observed = ManagedLaneRuntime.real(root,plan).physicalRunning()
        require(expected == observed && authority.generationActive(plan.generation) &&
            authority.revisionHead(plan.generation) == identityHead) { "Native managed lane disagrees with typed parent journal" }
        return observed
    }
    fun requireChatReady() {
        val entries = history()
        require(entries.lastOrNull()?.first?.action != FreshLaneAction.STOP &&
            authority.generationActive(plan.generation) && authority.revisionHead(plan.generation) == identityHead)
    }
    fun operate(action: FreshLaneAction, requestId: String): FreshLaneActionResult =
        GenerationRuntime.real().withManagedLaneControlLocks(
            json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)
                .decodeToString(throwOnInvalidSequence=true))) {
            require(requestId.matches(Regex("[a-f0-9]{32}")) && plan.ownerSubject != null &&
                authority.generationActive(plan.generation) && authority.revisionHead(plan.generation) == identityHead &&
                NativeManagedBrokerSupervisor(plan,root).inspect().active)
            val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)
                .decodeToString(throwOnInvalidSequence=true))
            require(bundle.request.managedLanes == plan && NativeManagedIdentityLedger(root.resolve("managed/identity"))
                .requireBound(plan,ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json")))) == identityHead)
            val entries = history()
            require(entries.size < 64 && (entries.lastOrNull()?.first?.action ?: FreshLaneAction.START) != action &&
                entries.none { it.first.requestId == requestId })
            val runtime = ManagedLaneRuntime.real(root,plan)
            require(runtime.physicalRunning() == (action == FreshLaneAction.STOP))
            val physical = plan.lanes.single { it.kind == ManagedLaneKind.WORKLANE }
            val pi = plan.lanes.single { it.kind == ManagedLaneKind.PI }
            if (entries.isEmpty()) runtime.recorded(physical, ManagedLaneOperation.START, "managed-start")
            val ordinal = entries.size + 1
            val previous = entries.lastOrNull()?.let { ReleaseLocks.sha256(
                ReleasePrivateFiles.read(journal.resolve("%04d.result.json".format(entries.size)),4096)) }
            val intent = FreshLaneActionIntent(plan.generation,physical.laneId,requireNotNull(plan.ownerSubject),
                identityHead,action,requestId,ordinal,previous)
            val encoded = json.encodeToString(intent).toByteArray()
            val name = "%04d".format(ordinal)
            ReleasePrivateFiles.save(journal.resolve("$name.intent.json"),encoded)
            val op = if (action == FreshLaneAction.STOP) "stop-device-$requestId" else "resume-device-$requestId"
            val result = if (action == FreshLaneAction.STOP) {
                broker.suspendLane() // Revocation precedes the native stop.
                val evidence = runtime.operate(physical, ManagedLaneOperation.ISOLATE,op)
                require(evidence.isolated && !runtime.physicalRunning())
                FreshLaneActionResult(ReleaseLocks.sha256(encoded),action,evidence.resultSha256,false)
            } else {
                val worklane = runtime.operate(physical, ManagedLaneOperation.START,op)
                require(!worklane.isolated && runtime.physicalRunning())
                val bearer = broker.reissueForLaneStart(op)
                val delivery = runtime.deliverBroker(pi,bearer,op)
                val tuios = runtime.operate(plan.lanes.single { it.kind == ManagedLaneKind.TUIOS },ManagedLaneOperation.START,op)
                val agent = runtime.operate(pi,ManagedLaneOperation.START,op)
                require(!tuios.isolated && !agent.isolated && runtime.physicalRunning())
                broker.activateLane(op,delivery)
                FreshLaneActionResult(ReleaseLocks.sha256(encoded),action,worklane.resultSha256,true,
                    delivery.tokenHash,tuios.resultSha256,agent.resultSha256)
            }
            ReleasePrivateFiles.save(journal.resolve("$name.result.json"),json.encodeToString(result).toByteArray())
            result
        }
}
