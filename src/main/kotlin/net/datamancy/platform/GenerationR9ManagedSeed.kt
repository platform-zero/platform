package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.UUID
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Fresh source-only Keycloak client credentials and one managed service ID.
 * Neither an imported issuer subject nor a lane, broker or upstream key is
 * claimed by this record. Partial initial issue is retained, never retried.
 */
@Serializable internal data class R9ManagedSeed(val generation: String, val laneId: String,
    val serviceSubjectUuid: String, val readerSubjectUuid: String, val ownerSubjectUuid: String,
    val lanes: List<ManagedLaneSpec>, val agentSecret: ActivationInput,
    val readerSecret: ActivationInput, val selectedWorklane: ActivationInput,
    val sourceOnly: Boolean = true, val nativeIssuerEnrolled: Boolean = false)
internal object GenerationR9ManagedSeed {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes")
    fun issue(generation: String): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        val identityPath=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$generation.json")
        val identity=json.decodeFromString<FreshIdentityBootstrap>(GenerationRuntime.privateInput(identityPath)
            .decodeToString(throwOnInvalidSequence=true)).also { it.validate() }
        val next=generation in setOf(GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation)
        val binary=Path.of(if(next) WorklaneLateBrokerImportProof.binaryPath else
            "/home/gerald/p0_v3/.coord/rapid-completion/fresh-r9-managed-worklane-319/worklane")
        val binaryPin=ActivationInput(binary.toString(),RecoveryCapsule.fileHash(binary))
        if(next) WorklaneLateBrokerImportProof.verifySelected(binaryPin)
        else require(binaryPin.sha256=="9a5d277c7fb7da3f5e2d61739e11aae5445e9b1723e8188d0f8c4e550be31016")
        require(Files.getPosixFilePermissions(binary)==PosixFilePermissions.fromString("r-x------"))
        if (!Files.exists(root,NOFOLLOW_LINKS)) {
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
        return ReleasePrivateFiles.locked(root) {
            val dir=root.resolve(generation)
            require(!Files.exists(dir,NOFOLLOW_LINKS)) { "Managed fresh source already attempted; no regenerated subjects or secrets" }
            Files.createDirectory(dir,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
            val lane=UUID.randomUUID().toString()
            val subject=UUID.randomUUID().toString()
            val reader=UUID.randomUUID().toString()
            require(setOf(lane,subject,reader,identity.ownerUuid,identity.outsiderUuid,identity.appNonMemberUuid).size==6)
            val session="p0v3-managed"
            val specs=ManagedLaneKind.entries.map { kind -> ManagedLaneSpec(kind,lane,subject,session,"home","home/workspace",
                if (kind==ManagedLaneKind.WORKLANE) 4096 else 0,
                if (kind==ManagedLaneKind.WORKLANE) 16384 else 0) }
            fun secret(name: String): ActivationInput {
                val bytes=ByteArray(32).also { SecureRandom().nextBytes(it) }
                val text=bytes.joinToString("") { "%02x".format(it) }+"\n"
                bytes.fill(0)
                val file=dir.resolve(name)
                ReleasePrivateFiles.save(file,text.toByteArray())
                return ActivationInput(file.toString(),ReleaseLocks.sha256(text.toByteArray()))
            }
            val agent=secret("agent-secret")
            val read=secret("reader-secret")
            require(agent.sha256!=read.sha256)
            val record=R9ManagedSeed(generation,lane,subject,reader,identity.ownerUuid,specs,
                agent,read,binaryPin)
            val bytes=json.encodeToString(record).toByteArray()
            val file=dir.resolve("source-seed.json")
            ReleasePrivateFiles.save(file,bytes)
            ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
        }
    }
}
