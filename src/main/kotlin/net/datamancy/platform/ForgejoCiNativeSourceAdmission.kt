package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString

/** Serial, read-only CI acquisition and credential preflight BEFORE any
 * full-private rootful member is started. This is not registration, native
 * image import, user-manager startup or an ACK for any of those operations.
 */
internal object ForgejoCiNativeSourceAdmission {
    fun requirePristineAccountNamespace(plan: ForgejoCiSourcePlan) {
        plan.validate(plan.generation)
        val helper = """import os,sys
base='/home/webservices-lab-ci-runner'
gen=sys.argv[1]
name='p0v3-ci-'+gen
paths=[base+'/.local/share/p0v3-ci/'+gen]
paths += [base+'/.config/containers/systemd/'+name+'-'+kind+ext for kind,ext in
          [('internal','.network'),('egress','.network'),('transport','.container'),('runner','.container')]]
paths += [base+'/.config/systemd/user/'+name+'-guard.service']
if os.geteuid()!=784 or any(os.path.lexists(path) for path in paths): sys.exit(19)
""".trimIndent()
        val child = ProcessBuilder("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount,
            "--", "/usr/bin/python3", "-c", helper, plan.generation)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            require(child.waitFor(15, java.util.concurrent.TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Dedicated account has a prior or uncertain generation source; no whole-cohort start"
            }
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    /** Full pre-seal acquisition check, independent of the not-yet-created
     * generation ci/ directory, pending transport and rendered unit files.
     * A later owned START must still rerun check() against the prepared root. */
    fun checkProspective(plan:ForgejoCiSourcePlan) {
        plan.validate(plan.generation)
        ForgejoCiNativeAccountOwner.preflight()
        requirePristineAccountNamespace(plan)
        require(plan.graphOwnedLateUpstream && plan.freshIssuerBootstrap &&
            !plan.freshRegistrationIssued && plan.upstreamCa==null && plan.privateUpstream==null)
        val workflow=GenerationRuntime.privateInput(Path.of(plan.workflow.path))
        require(ReleaseLocks.sha256(workflow)==plan.workflow.sha256)
        val repository=requireNotNull(plan.trustedRepositoryBundle)
        require(Files.isRegularFile(Path.of(repository.path),NOFOLLOW_LINKS) &&
            Files.size(Path.of(repository.path)) in 1024L..(128L*1024*1024) &&
            RecoveryCapsule.fileHash(Path.of(repository.path))==repository.sha256)
        for (input in listOf(plan.runnerBinary,plan.rootlessPodman)) {
            val path=Path.of(input.path)
            require(Files.isRegularFile(path,NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
                Files.isExecutable(path) && RecoveryCapsule.fileHash(path)==input.sha256) {
                "Pinned native CI source executable missing or changed"
            }
        }
        val images=listOf(plan.jobArchive,requireNotNull(plan.runnerImage),requireNotNull(plan.transportImage))
        val home=Path.of("/home/webservices-lab-ci-runner")
        val store=Files.getFileStore(if(Files.isDirectory(home,NOFOLLOW_LINKS)) home else Path.of("/home"))
        val required=images.fold(0L) { sum,image ->
            Math.addExact(sum,Math.addExact(image.archiveBytes,image.maximumUnpackedBytes)) }
        require(store.usableSpace>Math.addExact(required,10L*1024*1024*1024))
        images.forEach { image ->
            val path=Path.of(image.archive.path)
            require(Files.isRegularFile(path,NOFOLLOW_LINKS) && Files.size(path)==image.archiveBytes)
            ManagedLaneOciArchive.inspect(path,image,System.currentTimeMillis()+600000L,store.blockSize)
        }
        require(ForgejoCiNativeUnits.render(plan)["p0v3-ci-${plan.generation}-runner.container"]!=null)
    }
    fun check(plan: ForgejoCiSourcePlan, root: Path) {
        plan.validate(root.fileName.toString())
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        ForgejoCiNativeAccountOwner.preflight()
        if (plan.graphOwnedLateUpstream) {
            val pending = kotlinx.serialization.json.Json.decodeFromString<ForgejoCiGraphUpstreamPending>(
                ReleasePrivateFiles.read(ci.resolve("transport-upstream.pending.json"), 8192).decodeToString())
            require(pending == ForgejoCiGraphUpstreamPending(plan.generation,
                "forgejo.datamancy.net", "ingress-control") &&
                !Files.exists(ci.resolve("transport-upstream-ca.pem"), NOFOLLOW_LINKS) &&
                !Files.exists(ci.resolve("transport-Caddyfile"), NOFOLLOW_LINKS)) {
                "Pending graph issuer cannot masquerade as a pre-start CA or native transport ACK"
            }
        }
        for (input in listOfNotNull(plan.workflow, plan.upstreamCa) +
            if (plan.freshIssuerBootstrap) emptyList() else listOf(plan.registrationToken)) {
            val data = GenerationRuntime.privateInput(Path.of(input.path))
            require(ReleaseLocks.sha256(data) == input.sha256 && data.isNotEmpty())
            if (input == plan.registrationToken) data.fill(0)
        }
        plan.trustedRepositoryBundle?.let { input ->
            val path = Path.of(input.path)
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                Files.size(path) in 1024..128L * 1024 * 1024 &&
                RecoveryCapsule.fileHash(path) == input.sha256)
        }
        for (input in listOf(plan.runnerBinary, plan.rootlessPodman)) {
            val path = Path.of(input.path)
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.isExecutable(path) &&
                RecoveryCapsule.fileHash(path) == input.sha256)
        }
        val images = listOf(plan.jobArchive, requireNotNull(plan.runnerImage), requireNotNull(plan.transportImage))
        val accountHome = Path.of("/home/webservices-lab-ci-runner")
        val store = Files.getFileStore(if (Files.isDirectory(accountHome, NOFOLLOW_LINKS)) accountHome else Path.of("/home"))
        val need = images.fold(0L) { total, image ->
            Math.addExact(total, Math.addExact(image.archiveBytes, image.maximumUnpackedBytes))
        }
        require(store.usableSpace > Math.addExact(need, 10L * 1024 * 1024 * 1024))
        for (image in images) {
            val path = Path.of(image.archive.path)
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) == image.archiveBytes)
            ManagedLaneOciArchive.inspect(path, image, System.currentTimeMillis() + 600000L, store.blockSize)
        }
        val original = requireNotNull(ForgejoCiNativeUnits.render(plan)["p0v3-ci-${plan.generation}-runner.container"])
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve(
            "unit-p0v3-ci-${plan.generation}-runner.container"), 131072)) ==
            ReleaseLocks.sha256(original.toByteArray()))
    }
}
