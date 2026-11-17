package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.system.exitProcess

private val releaseOutputJson = Json { encodeDefaults = true }

fun main(args: Array<String>) {
    val status = runCommand(args, ::println, System.err::println)
    if (status != 0) exitProcess(status)
}

/** Testable CLI boundary: only main can terminate the process. */
internal fun runCommand(args: Array<String>, out: (String) -> Unit, err: (String) -> Unit): Int {
    return try {
    when (args.toList()) {
        listOf("catalog", "validate") -> {
            val catalog = ServiceCatalog.bundled()
            out("Historical evidence valid: ${catalog.serviceIds.size} IDs in ${catalog.modules.size} old modules; NOT an install schema")
        }
        listOf("catalog", "products") -> ProductSelection.bundled().products.sorted().forEach {
            out("$it\tprovisional-logical-product")
        }
        listOf("catalog", "list") ->
            ServiceCatalog.bundled().modules.forEach { module ->
                module.services.forEach { service -> out("${module.id}\t$service\tinventory-only") }
            }
        else -> when {
            args.size == 3 && args[0] == "managed-broker-serve" -> {
                ManagedBrokerHostSource.serve(args[1], args[2])
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-render" -> {
                val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                    GenerationAssembly.readInventory(Path.of(args[2])))
                out(releaseOutputJson.encodeToString(GenerationRender.export(plan, Path.of(args[4]))))
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-check" -> {
                val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                    GenerationAssembly.readInventory(Path.of(args[2])))
                plan.specs.forEach { spec -> out(releaseOutputJson.encodeToString(
                    RuntimeQuadletDiagnostics.verify(spec, RuntimeQuadlets.render(spec)))) }
            }
            args.size == 3 && args[0] == "release" && args[1] == "fragment-lint" -> {
                try {
                    out(releaseOutputJson.encodeToString(FragmentLint.inspect(Path.of(args[2]))))
                } catch (failure: Exception) {
                    err("Fragment lint rejected (${failure.javaClass.simpleName}); no runtime effects authorized")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] in setOf("install", "update", "backup", "restore-test", "rollback", "reconcile", "qualify", "activate") -> {
                val request = ReleaseDispatch.read(Path.of(args[2]))
                require(ReleaseDispatch.operation(request) == args[1]) { "Typed release request operation differs from CLI" }
                val runtime = GenerationRuntime.real()
                val dispatcher = ReleaseDispatch.real(runtime, restoreWhole = { inventory, generation, capture, target ->
                    runtime.restoreKopiaWholeRelease(inventory, generation.id, generation.bundleSha256, capture, target,
                        targetStore = RuntimeStore.CANONICAL_V2)
                }, restoredJourneys = NativeRestoredJourneys.real(runtime))
                out(dispatcher.execute(request))
            }
            args.size == 3 && args[0] == "office-callback-readonly" -> {
                try {
                    out(releaseOutputJson.encodeToString(qualifiedOfficeCallbackReadback(args[1], args[2], System.getenv())))
                } catch (failure: Exception) {
                    err("Office read-only observation rejected (${failure.javaClass.simpleName}); no callback resend authorized")
                    return 1
                }
            }
            args.size == 3 && args[0] == "qualification" && args[1] == "stage-inputs" -> {
                val request = releaseOutputJson.decodeFromString<QualificationStageInputsRequest>(
                    ReleasePrivateFiles.read(Path.of(args[2]), 65536).decodeToString(throwOnInvalidSequence = true))
                out(QualificationPrerequisites.stage(request).toString())
            }
            args.size == 3 && args[0] == "qualification" && args[1] == "publish-artifacts" -> {
                val request = releaseOutputJson.decodeFromString<QualificationPublishArtifactsRequest>(
                    ReleasePrivateFiles.read(Path.of(args[2]), 65536).decodeToString(throwOnInvalidSequence = true))
                out(releaseOutputJson.encodeToString(QualificationPrerequisites.publish(request)))
            }
            args.size == 3 && args[0] == "qualification" && args[1] == "native-request" -> {
                try {
                // No caller-selected spec, store, executable or namespace. The native actor
                // independently reopens the post-intent protected case claim before effects.
                val requestPath = Path.of(args[2])
                require(requestPath.isAbsolute && requestPath.normalize() == requestPath &&
                    requestPath.startsWith(GenerationRuntime.BASE))
                val relative = GenerationRuntime.BASE.relativize(requestPath)
                require(relative.nameCount == 4 && relative.getName(0).toString().matches(Regex("q-[a-f0-9]{12}")) &&
                    relative.getName(1).toString() == "native-qualification" &&
                    relative.getName(2).toString().matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
                    relative.getName(3).toString().matches(Regex("nq-[a-f0-9]{12}\\.request\\.json")))
                val request = releaseOutputJson.decodeFromString<NativeQualificationRequest>(
                    ReleasePrivateFiles.read(requestPath, 65536).decodeToString(throwOnInvalidSequence = true))
                require(request.generationId.matches(Regex("q-[a-f0-9]{12}")) &&
                    request.invocationId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
                    request.operation.matches(Regex("nq-[a-f0-9]{12}")))
                val root = GenerationRuntime.BASE.resolve(request.generationId)
                require(requestPath == root.resolve("native-qualification/${request.invocationId}/${request.operation}.request.json")) {
                    "Native qualification requires its fixed protected request location"
                }
                val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"))
                val bundle = releaseOutputJson.decodeFromString<GenerationBundle>(
                    bundleBytes.decodeToString(throwOnInvalidSequence = true))
                val staged = releaseOutputJson.decodeFromString<GenerationOutcome>(
                    ReleasePrivateFiles.read(root.resolve("stage.result.json")).decodeToString(throwOnInvalidSequence = true))
                require(staged.passed && staged.failureType == null && staged.action in setOf("stage", "restore-import") &&
                    staged.bundleSha256 == ReleaseLocks.sha256(bundleBytes)) { "Native qualification requires completed bound staging" }
                require(bundle.request.id == request.generationId && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
                    bundle.members.map { it.member } == GenerationRuntime.validateScope(bundle.request))
                SiteOwnerships.checkSealed(bundle)
                val pin = bundle.members.single { it.member.name == request.targetMemberName }
                PrivateDeployment.validate(pin.spec)
                require(pin.spec.name == pin.member.name && pin.spec.store == bundle.request.store &&
                    pin.runtimeFingerprint == request.targetFingerprint &&
                    PrivateDeployment.expectedFingerprint(pin.spec, pin.inputHashes) == pin.runtimeFingerprint &&
                    PrivateDeployment.inputNames(pin.spec).toSet() == pin.inputHashes.keys) {
                    "Native qualification target differs from sealed generation ownership"
                }
                val manifestBytes = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve("${pin.member.name}.json"))
                require(ReleaseLocks.sha256(manifestBytes) == pin.manifestSha256 &&
                    releaseOutputJson.decodeFromString<PrivateDeploymentSpec>(
                        manifestBytes.decodeToString(throwOnInvalidSequence = true)) == pin.spec) {
                    "Native qualification runtime manifest changed"
                }
                val inputs = PrivateDeployment.BASE.resolve(pin.member.name)
                pin.inputHashes.forEach { (name, expected) ->
                    require(ReleaseLocks.sha256(ReleasePrivateFiles.read(inputs.resolve(name))) == expected) {
                        "Native qualification target input changed"
                    }
                }
                out(releaseOutputJson.encodeToString(NativeQualificationClient.real(root, pin.spec,
                    pin.runtimeFingerprint).request(request)))
                } catch (failure: Exception) {
                    err("Native qualification rejected (${failure.javaClass.simpleName}); retain intents and do not replay")
                    return 1
                }
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "ingress-lifecycle" -> {
                val request = CaddyLifecycle.readHttps(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(CaddyLifecycle.real().execute(request)))
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "private-pki-lifecycle" -> {
                val request = CaddyLifecycle.readPrivatePki(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(CaddyLifecycle.privatePki(request)))
            }
            args.contentEquals(arrayOf("release", "runtime-store-v2-policy")) -> {
                val store = RuntimeStore.CANONICAL_V2
                out(Json.encodeToString(mapOf("graph" to store.graph, "run" to store.run, "network" to store.network,
                    "module" to store.module.toString(), "configuration" to store.configuration,
                    "objectLimit" to RuntimeLockBudget.ISOLATED_OBJECT_LIMIT.toString())))
                0
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-development-ownership" -> {
                val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                    GenerationAssembly.readInventory(Path.of(args[2])))
                require(plan.generation.purpose == "private-component-integration" &&
                    plan.specs.all { it.ingress == null && it.nativeIngress == null })
                val draft = CanonicalTopology.ownership(CanonicalTopology.compile(plan, false),
                    "private-component-pilot", emptyList(), emptySet())
                out(releaseOutputJson.encodeToString(draft))
                out("Private development ownership draft only; not original site authority or release evidence")
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-ci-pre-effect-disposition" -> {
                val binding = GenerationRuntime.real().issueCiPreEffectDisposition(args[2])
                out(releaseOutputJson.encodeToString(binding))
                out("Failed original retained; separately journaled pre-effect disposition, no original ACK or CI/member effect")
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-ci-member-pre-effect-disposition" -> {
                val binding=GenerationRuntime.real().issueCiMemberPreEffectDisposition(args[2])
                out(releaseOutputJson.encodeToString(binding))
                out("Second failed preparation retained; exact CI/ingress sources adopted, no member input ACK")
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-preparation-terminal-record-v2-pre-effect" -> {
                try {
                    val record=GenerationRuntime.real().recordFailedPreparationV2PreEffect(args[2],
                        ActivationInput(args[3],args[4]),ActivationInput(args[5],args[6]))
                    val file=GenerationRuntime.BASE.resolve(args[2]).resolve(
                        GenerationPreparationTerminalDisposition.V2_PRE_EFFECT)
                    out("${record.generation} ${ReleaseLocks.sha256(ReleasePrivateFiles.read(file,16384))}")
                    out("V2 pre-effect refusal recorded only; original and v1 failure remain false; no terminal ACK or new generation")
                } catch(failure:Exception) {
                    err("V2 pre-effect refusal observation failed (${failure.javaClass.simpleName}); no terminal ACK")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-preparation-terminal-verify-readonly" -> {
                try {
                    val checked=GenerationRuntime.real().verifyFailedPreparationTerminal(args[2],
                        ActivationInput(args[3],args[4]),ActivationInput(args[5],args[6]))
                    out("${checked.generation} ${checked.member} originalFalse=${checked.failedOutcomes.size} unitOrCidEffectObserved=${checked.unitOrCidEffectObserved} publicActivation=${checked.publicActivation}")
                    out("Independent locked read-only terminal verification only; no INSTALL, identity or new native effect")
                } catch(failure:Exception) {
                    err("Read-only terminal verification refused (${failure.javaClass.simpleName}); preserve all historical receipts")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-preparation-terminal-after-v2-refusal" -> {
                try {
                    val sealed=GenerationRuntime.real().terminalizeAfterV2PreEffect(args[2],
                        ActivationInput(args[3],args[4]),ActivationInput(args[5],args[6]))
                    val file=GenerationRuntime.BASE.resolve(args[2]).resolve(
                        GenerationPreparationTerminalDisposition.V3_NAME)
                    out("${sealed.generation} ${ReleaseLocks.sha256(ReleasePrivateFiles.read(file,1048576))}")
                    out("Versioned terminal only: all original preparation and v1 failure receipts remain false; no member start or new credentials")
                } catch(failure:Exception) {
                    err("Versioned post-refusal terminal journal refused (${failure.javaClass.simpleName}); preserve v3 intent and result if present")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-preparation-terminal-reconcile" -> {
                try {
                    val root=GenerationRuntime.BASE.resolve(args[2])
                    val sealed=GenerationRuntime.real().reconcileFailedPreparationTerminal(args[2],
                        ActivationInput(args[3],args[4]),
                        ActivationInput(root.resolve("preparation-terminal.intent.json").toString(),args[5]),
                        ActivationInput(root.resolve("preparation-terminal.result.json").toString(),args[6]))
                    val file=root.resolve(GenerationPreparationTerminalDisposition.V2_NAME)
                    out("${sealed.generation} ${ReleaseLocks.sha256(ReleasePrivateFiles.read(file,1048576))}")
                    out("Separate terminal disposition only: prior false result retained, native absence independently reobserved, no original preparation ACK")
                } catch(failure:Exception) {
                    err("Separate pre-bundle terminal operation refused (${failure.javaClass.simpleName}); retain both original and terminal intents/results")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-preparation-terminal-observe-pair" -> {
                try {
                    val (first,second)=GenerationRuntime.real().observeFailedPreparationPair(args[2],
                        ActivationInput(args[3],args[4]))
                    val sourceSame=first.copy(nativeNamespaceSha256=emptyMap(),nativeSystemdSha256="",
                        nativeManagedUnitSha256="",nativeCiUserAbsenceSha256="",
                        nativeNamespaceRawReadbackSha256=emptyMap())==second.copy(
                        nativeNamespaceSha256=emptyMap(),nativeSystemdSha256="",nativeManagedUnitSha256="",
                        nativeCiUserAbsenceSha256="",nativeNamespaceRawReadbackSha256=emptyMap())
                    out("sourceSame=$sourceSame")
                    out("namespaceAbsenceSame=${first.nativeNamespaceSha256==second.nativeNamespaceSha256} unrelatedRawReadbackSame=${first.nativeNamespaceRawReadbackSha256.keys.associateWith { first.nativeNamespaceRawReadbackSha256[it]==second.nativeNamespaceRawReadbackSha256[it] }} systemUnitsSame=${first.nativeSystemdSha256==second.nativeSystemdSha256} managedUnitSame=${first.nativeManagedUnitSha256==second.nativeManagedUnitSha256} ciAbsenceSame=${first.nativeCiUserAbsenceSha256==second.nativeCiUserAbsenceSha256}")
                    out("READ-ONLY differential; no separate terminal intent or ACK")
                } catch(failure:Exception) {
                    err("Read-only terminal differential refused (${failure.javaClass.simpleName}); no intent or ACK")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-preparation-terminal-observe" -> {
                try {
                    val observed=GenerationRuntime.real().observeFailedPreparation(args[2],ActivationInput(args[3],args[4]))
                    out("${observed.generation} ${observed.member} ${observed.failedOutcomes.size} ${observed.memberFileSha256.size} ${observed.nativeUnitCount} ${observed.nativeSystemdSha256} ${observed.nativeManagedUnitSha256} ${observed.nativeCiUserAbsenceSha256}")
                    out("READ-ONLY native and source census under locks; no terminal intent or ACK was issued")
                } catch(failure:Exception) {
                    err("Pre-bundle read-only native observation refused (${failure.javaClass.simpleName}); no terminal intent or ACK issued")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-preparation-terminal" -> {
                try {
                    val generation=args[2]
                    val disposition=GenerationRuntime.real().terminalizeFailedPreparation(generation,
                        ActivationInput(args[3],args[4]))
                    val path=GenerationRuntime.BASE.resolve(generation).resolve(GenerationPreparationTerminalDisposition.NAME)
                    out("${disposition.generation} ${ReleaseLocks.sha256(ReleasePrivateFiles.read(path,1048576))}")
                    out("Three historical failed outcomes retained; exact member bytes and independent native unit/CID absence recorded under owner and native locks, no replacement ACK")
                } catch(failure:Exception) {
                    err("Pre-bundle terminal disposition refused (${failure.javaClass.simpleName}); retain all original failed receipts and member bytes")
                    return 1
                }
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-worklane-isolated-full-prepare-probe" -> {
                try {
                    val pin=WorklaneFullPrepareReturnProbe.issue()
                    out("Isolated production backend PREPARE + independent attestation only: ${pin.path} ${pin.sha256}")
                } catch(failure:Exception) {
                    err("Isolated full Worklane PREPARE uncertain (${failure.javaClass.simpleName}); inspect scratch intent and native graph, do not replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-q07-partial-installed-unit-terminal" -> {
                try {
                    val pin=GenerationRuntime.real().terminalizeQ07PartialInstalled(args[2],args[3])
                    out("q07 original installed disabled units observed root-read-only, no install result/stage/START: ${pin.path} ${pin.sha256}")
                } catch(failure:Exception) {
                    err("q07 partial-install terminal refused (${failure.javaClass.simpleName}); preserve root-owned files and original intent")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-q9b-cold-prepared-uninstalled-terminal" -> {
                try {
                    val pin=GenerationRuntime.real().terminalizeQ9bColdPreparedUninstalled(args[2],args[3])
                    out("q9b three original cold PREPARE ACKs, missing stage result, no installed units: ${pin.path} ${pin.sha256}")
                } catch(failure:Exception) {
                    err("q9b locked cold-PREPARE terminal refused (${failure.javaClass.simpleName}); preserve results/image")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-q583-prepared-no-start-terminal" -> {
                try {
                    val proof=GenerationRuntime.real().terminalizeQ583PreparedNoStart(args[2],args[3])
                    out("q583 prepared-no-start; no native serve ever attempted: ${proof.path} ${proof.sha256}")
                } catch (failure:Exception) {
                    err("q583 prepared-no-start terminal refused (${failure.javaClass.simpleName}); preserve frozen bundle/native absence")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-q273-uncertain-import-terminal" -> {
                try {
                    val input=GenerationRuntime.real().terminalizeQ273UncertainImport(args[2],args[3])
                    out("q273 uncertain imported Worklane image + manifest, no original PREPARE ACK: ${input.path} ${input.sha256}")
                } catch(failure:Exception) {
                    err("Uncertain q273 terminal refused (${failure.javaClass.simpleName}); preserve original intents/image/manifest")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-live-retained-native-preseal" -> {
                try {
                    val plan=GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    val owner=SiteOwnerships.decode(ReleaseLocks.privateBytes(Path.of(args[4])))
                    val hosts=ReleaseLocks.approvedHosts(Path.of(args[5]))
                    out(GenerationRuntime.real().prospectiveLiveAdmission(plan,owner,hosts))
                    out("Exact serving capacity and fresh inactive native census PASS before seal; no stage or ACK")
                } catch (failure:Exception) {
                    err("Live retained-generation capacity preseal refused (${failure.javaClass.simpleName}); do not seal or start")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-prospective-r10-native-preflight" -> {
                try {
                    val request=GenerationAssembly.readRequest(Path.of(args[3]))
                    require(request.id in setOf("q-dd36ebcf43ef","q-4d3c1cb287e5",GenerationAfterNativeImportLineage.generation,
                        GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                        GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                        GenerationAfterQ07Lineage.generation) &&
                        request.selections.single().recipe==CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE &&
                        !java.nio.file.Files.exists(GenerationRuntime.BASE.resolve(request.id)))
                    val plan=GenerationAssembly().plan(request,GenerationAssembly.readInventory(Path.of(args[2])))
                    val spec=plan.specs.single()
                    require(spec.processes.size==134 && spec.processes.count { !it.oneShot }==79 &&
                        spec.executionBackend==RuntimeExecutionBackend.QUADLET_V2)
                    val owners=SiteOwnerships.decode(ReleaseLocks.privateBytes(Path.of(args[4])))
                    SiteOwnerships.bind(plan,owners,ReleaseLocks.approvedHosts(Path.of(args[5])))
                    val images=GenerationR9ImageStore.verifySelected(request.id,spec)
                    ForgejoCiNativeSourceAdmission.checkProspective(requireNotNull(plan.generation.forgejoCi))
                    plan.generation.managedLanes?.let { lanes ->
                        lanes.validate(request.id)
                        val native=lanes.native
                        val image=requireNotNull(native.imageArchive)
                        // A NEW host binary is eligible only after a separate real,
                        // isolated CLI import and pre-container missing-socket START
                        // refusal. This observation is not the q273 PREPARE ACK.
                        if (request.id in setOf(GenerationAfterQ273Lineage.generation,
                                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                                GenerationAfterQ07Lineage.generation)) {
                            GenerationAfterQ273Lineage.verify(requireNotNull(request.q273UncertainImportPredecessor),
                                requireNotNull(request.qc3PreparedNoStartPredecessor),
                                requireNotNull(request.uncertainNativeImportPredecessor),
                                requireNotNull(request.isolatedRootlessProbePredecessor))
                            WorklaneLateBrokerImportProof.verifySelected(native.worklane)
                        }
                        if (request.id in setOf(GenerationAfterQ583Lineage.generation,
                                GenerationAfterQ9bLineage.generation,GenerationAfterQ07Lineage.generation)) {
                            GenerationAfterQ583Lineage.verify(requireNotNull(request.q583PreparedNoStartPredecessor),
                                requireNotNull(request.isolatedFullWorklanePreparePredecessor),
                                requireNotNull(request.q273UncertainImportPredecessor),
                                requireNotNull(request.qc3PreparedNoStartPredecessor),
                                requireNotNull(request.uncertainNativeImportPredecessor),
                                requireNotNull(request.isolatedRootlessProbePredecessor))
                            WorklaneFullPrepareReturnProbe.verifyLive(
                                requireNotNull(request.isolatedFullWorklanePreparePredecessor))
                        }
                        if (request.id in setOf(GenerationAfterQ9bLineage.generation,
                                GenerationAfterQ07Lineage.generation)) {
                            GenerationAfterQ9bLineage.verify(requireNotNull(request.q9bColdPreparedUninstalledPredecessor),
                                requireNotNull(request.q583PreparedNoStartPredecessor),
                                requireNotNull(request.isolatedFullWorklanePreparePredecessor),
                                requireNotNull(request.q273UncertainImportPredecessor),
                                requireNotNull(request.qc3PreparedNoStartPredecessor),
                                requireNotNull(request.uncertainNativeImportPredecessor),
                                requireNotNull(request.isolatedRootlessProbePredecessor))
                        }
                        if (request.id==GenerationAfterQ07Lineage.generation) {
                            GenerationAfterQ07Lineage.verify(requireNotNull(request.q07PartialInstalledPredecessor),
                                requireNotNull(request.q9bColdPreparedUninstalledPredecessor),
                                requireNotNull(request.q583PreparedNoStartPredecessor),
                                requireNotNull(request.isolatedFullWorklanePreparePredecessor),
                                requireNotNull(request.q273UncertainImportPredecessor),
                                requireNotNull(request.qc3PreparedNoStartPredecessor),
                                requireNotNull(request.uncertainNativeImportPredecessor),
                                requireNotNull(request.isolatedRootlessProbePredecessor))
                        }
                        val path=Path.of(image.archive.path)
                        require(java.nio.file.Files.isRegularFile(path) &&
                            java.nio.file.Files.size(path)==image.archiveBytes &&
                            RecoveryCapsule.fileHash(path)==image.archive.sha256)
                        ManagedLaneOciArchive.inspect(path,image,System.currentTimeMillis()+600000L,
                            java.nio.file.Files.getFileStore(path).blockSize)
                        require(java.nio.file.Files.isExecutable(Path.of(native.worklane.path)) &&
                            java.nio.file.Files.isExecutable(Path.of(native.podman.path)))
                        val managedSource=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/${request.id}")
                        for ((file,input) in listOf("source-target-lane.toml" to native.manifest,
                            "source-storage.conf" to native.storageConfig,
                            "source-broker.json" to requireNotNull(native.broker).configuration))
                            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(managedSource.resolve(file),1048576))==input.sha256)
                        val futureManaged=GenerationRuntime.BASE.resolve(request.id).resolve("managed")
                        NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
                            Path.of(native.storageConfig.path),Path.of(native.manifest.path),
                            futureManaged.resolve("control/home"),futureManaged.resolve("control/config"),
                            futureManaged.resolve("control/data"),futureManaged.resolve("control/run"),image,
                            emptyMap()).validateTargetManifest(
                                ReleasePrivateFiles.read(managedSource.resolve("source-target-lane.toml"),1048576),
                                lanes.lanes.single { it.kind==ManagedLaneKind.WORKLANE },
                                futureManaged.resolve("worklane"))
                        for (input in listOf(native.worklane,native.podman,native.storageConfig,
                            native.manifest,requireNotNull(native.broker).configuration)) {
                            val sourcePath=Path.of(input.path)
                            if (sourcePath.startsWith(GenerationRuntime.BASE.resolve(request.id))) {
                                require(input.path.endsWith("/inputs/target-lane.toml") ||
                                    input.path.endsWith("/control/storage.conf") ||
                                    input.path.endsWith("/inputs/broker.json"))
                            } else require(java.nio.file.Files.isRegularFile(sourcePath) &&
                                RecoveryCapsule.fileHash(sourcePath)==input.sha256)
                        }
                    }
                    RuntimeQuadletPreflight.verify(spec)
                    out(releaseOutputJson.encodeToString(mapOf("generation" to request.id,
                        "completeProspectiveRequestSha256" to RecoveryCapsule.fileHash(Path.of(args[3])),
                        "selected66ImageStoreSha256" to images.sha256,
                        "member" to spec.name,"nativeProcessCount" to "134",
                        "nativeCIExecutableSourceSha256" to requireNotNull(plan.generation.forgejoCi).runnerBinary.sha256,
                        "ownedQuadletPreflight" to "passed","publicActivation" to "false")))
                    out("Read-only complete prospective source, CI executable+UID784, native 66 images and 134 Quadlets; no INSTALL ACK")
                } catch(failure:Exception) {
                    err("Prospective all-family pre-seal native admission refused (${failure.javaClass.simpleName}); no seal or START")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] in setOf("site-ownership-check", "generation-prepare-owned") -> {
                try {
                    val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    val contract = SiteOwnerships.decode(ReleaseLocks.privateBytes(Path.of(args[4])))
                    val hosts = ReleaseLocks.approvedHosts(Path.of(args[5]))
                    if (args[1] == "site-ownership-check") {
                        out(releaseOutputJson.encodeToString(SiteOwnerships.check(plan, contract, hosts)))
                        out("Structural ownership only; no credentials generated, central wiring verified or routes activated")
                    } else {
                        val digest = GenerationRuntime.real().prepareOwnedAssembly(plan, contract, hosts)
                        out("${plan.generation.id} $digest")
                        out("Prepared ownership-bound private inputs; no services started or public authority inherited")
                    }
                } catch (failure: Exception) {
                    err("Site ownership operation rejected (${failure.javaClass.simpleName}); retain any preparation intents and partial inputs, never regenerate credentials")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in
                setOf("generation-r9-ownership-source", "generation-r10-ownership-source") -> {
                try {
                    val r10 = args[1] == "generation-r10-ownership-source"
                    val request=GenerationAssembly.readRequest(Path.of(args[3]))
                    require(request.selections.single().recipe == (if (r10)
                        CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE else CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE))
                    val compiled=GenerationAssembly().canonicalPlan(request,GenerationAssembly.readInventory(Path.of(args[2])))
                    val manifest=if (r10) PackagedGraphFragment.pendingV3R10().first else
                        PackagedGraphFragment.pendingV3R9().first
                    val hosts=requireNotNull(manifest.integratedReference).modules.flatMap {
                        it.privateRoutes.map(CanonicalIngressRoute::host)
                    }.toSet()
                    out(releaseOutputJson.encodeToString(CanonicalTopology.ownership(compiled,
                        if (r10) "full-private-r10" else "full-private-r9",requireNotNull(request.portalRoutes),hosts)))
                } catch (failure: Exception) {
                    err("Exact full private ownership source refused (${failure.javaClass.simpleName}); no native effect")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-canonical-private-ownership" -> {
                try {
                    val compiled = GenerationAssembly().canonicalPlan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])), requireComplete = false)
                    require(compiled.assembly.specs.size == 1 &&
                        compiled.assembly.specs.single().fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
                        !compiled.topology.complete && !compiled.topology.runtimeValidated)
                    out(releaseOutputJson.encodeToString(CanonicalTopology.ownership(compiled,
                        "private-shared-assembled-core", emptyList(), emptySet())))
                    out("Read-only partial canonical shared ownership; not full stack, admission or qualification")
                } catch (failure: Exception) {
                    err("Private shared canonical ownership rejected (${failure.javaClass.simpleName}); no native effect")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-private-assembled-gaps" -> {
                try {
                    val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    out(releaseOutputJson.encodeToString(PrivateAssembledStackGapReport.inspect(plan)))
                    out("Read-only unfrozen compiled graph gaps; no product preparation, install or Acceptance claim")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..160 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_/-]+")) } ?: "unspecified"
                    err("Private assembled graph preview rejected (${failure.javaClass.simpleName}: $diagnostic); no native effect")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-identity" -> {
                try {
                    val path = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/${args[2]}.json")
                    FreshIdentityBootstrap.createOnce(path)
                    out(releaseOutputJson.encodeToString(ActivationInput(path.toString(),
                        ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 16384)))))
                } catch (failure: Exception) {
                    err("Fresh r9 identity input refused (${failure.javaClass.simpleName}); preserve original subject custody")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-inventory" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9Inventory.issue(args[2])))
                } catch (failure: Exception) {
                    err("Pinned full-r9 source inventory refused (${failure.javaClass.simpleName}); do not replace an uncertain generation input")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] in setOf("managed-pi-subscription-issue", "managed-pi-subscription-verify", "managed-pi-script-revision-issue") -> {
                try {
                    val owner=GenerationRuntime.real()
                    out(when(args[1]) {
                        "managed-pi-subscription-issue" -> owner.issueManagedPiSubscriptionCustody(args[2])
                        "managed-pi-script-revision-issue" -> owner.issueManagedPiScriptRevision(args[2])
                        else -> owner.verifyManagedPiSubscriptionCustody(args[2])
                    })
                    out("Owner-local Pi openai OAuth-only custody; no native model or lane result")
                } catch (failure: Exception) {
                    err("Owner-local Pi subscription refused (${failure.javaClass.simpleName}); never retry an uncertain issue")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-q583-managed-plan-v2" -> {
                try {
                    require(args[2]==GenerationAfterQ273Lineage.generation &&
                        args[3].matches(Regex("[a-f0-9]{64}")))
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().issueManagedPiSubscriptionPlan(args[2],args[3])))
                } catch (failure:Exception) {
                    err("q583 distinct managed-plan-v2 refused (${failure.javaClass.simpleName}); preserve old controller source")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-r9-managed-plan" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().issueManagedPiSubscriptionPlan(args[2],args[3])))
                } catch (failure: Exception) {
                    err("Fresh Pi subscription plan refused (${failure.javaClass.simpleName}); require owner-local Pi OAuth-only custody and frozen controller")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-r9-managed-restore-source" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().issueManagedPiRecoveryAuthority(args[2],args[3])))
                } catch (failure: Exception) {
                    err("Target managed source refused (${failure.javaClass.simpleName}); preserve one-use authority and source")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-recovered-managed-revise" -> {
                try {
                    ManagedRecoveryIdentityRevision.issueInChild(args[2],args[3])
                    out("Target native Keycloak issuer revision sealed; no credentials output")
                } catch (failure: Exception) {
                    err("Target issuer revision refused (${failure.javaClass.simpleName}); preserve original intents, never replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-original-managed-identity" -> {
                try {
                    ManagedOriginalIdentityEnrollment.issueInChild(args[2],args[3])
                    out("Native fresh managed subject/reader proof sealed; no bearer output")
                } catch (failure: Exception) {
                    err("Original managed identity refused (${failure.javaClass.simpleName}); preserve intent, do not replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-restored-bao-unseal" -> {
                try {
                    GenerationBaoColdRestore.unsealInChild(args[2],args[3])
                    out("Isolated Bao Raft original shares verified and unsealed; no secrets output")
                } catch (failure: Exception) {
                    err("Restored Bao unseal refused (${failure.javaClass.simpleName}); preserve intents, do not replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-original-bao-issue" -> {
                try {
                    GenerationFreshBaoStage.issueInChild(args[2],args[3])
                    out("Original native Bao issuer result sealed (no token, root or shares on stdout)")
                } catch (failure: Exception) {
                    err("Original Bao issuer refused (${failure.javaClass.simpleName}); preserve intents, do not replay")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-rendered-scripts" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9MastodonRenderedScripts.issue(args[2])))
                } catch (failure: Exception) {
                    err("Selected rendered Lua source refused (${failure.javaClass.simpleName}); no native SCRIPT LOAD claimed")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-managed-observed-image" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9ManagedObservedImage.issue(args[2])))
                } catch (failure: Exception) {
                    err("Managed observed-image binding refused (${failure.javaClass.simpleName}); original build ACK remains absent")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-managed-seed" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9ManagedSeed.issue(args[2])))
                } catch (failure: Exception) {
                    err("Fresh managed source refused (${failure.javaClass.simpleName}); preserve one-use subject/secret issue")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-development-provenance" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9DevelopmentProvenance.issue(args[2])))
                } catch (failure: Exception) {
                    err("Development source snapshot refused (${failure.javaClass.simpleName}); no trusted release candidate asserted")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-image-verify" -> {
                try {
                    val bytes = ReleasePrivateFiles.read(Path.of(
                        "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/${args[2]}/inventory.json"),2097152)
                    val inventory = releaseOutputJson.decodeFromString<AcquiredInventory>(
                        bytes.decodeToString(throwOnInvalidSequence=true))
                    val spec = CanonicalSharedYamlGraph.pendingR9Spec(inventory,"${args[2]}-v2")
                    out(releaseOutputJson.encodeToString(GenerationR9ImageStore.verifySelected(args[2],spec)))
                } catch (failure: Exception) {
                    err("Exact whole-family canonical image recheck refused (${failure.javaClass.simpleName}); no startup authorized")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-image-import" -> {
                try {
                    out("Exact original OCI loads: ${GenerationR9ImageStore.importAndVerify(args[2])}; all 66 selected canonical image IDs reobserved. No app started or qualification ACK issued.")
                } catch (failure: Exception) {
                    err("Whole-family image import refused (${failure.javaClass.simpleName}); preserve any original image-load intents")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-graph-source" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9GraphSourceBindings.issue(args[2])))
                } catch (failure: Exception) {
                    err("Pinned r9 graph/RSS source projection refused (${failure.javaClass.simpleName}); no RSS enrollment issued")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-graph-source" -> {
                try {
                    val id = args[2]
                    val source = java.nio.file.Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/$id/grant.json")
                    out(releaseOutputJson.encodeToString(GenerationR10GraphSourceBindings.issue(id,
                        ActivationInput(source.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(source, 8192))))))
                } catch (failure: Exception) {
                    err("Pinned r10 graph/Planka/RSS source projection refused (${failure.javaClass.simpleName}); no native enrollment issued")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-planka-grant" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationFreshPlankaGrant.issue(args[2])))
                    out("Fresh original Planka actor source only; no native signup, RESTORE replay or qualification")
                } catch (failure: Exception) {
                    err("Fresh Planka actor source refused (${failure.javaClass.simpleName}); do not regenerate a partial grant")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-original-ci-job" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().produceOriginalCiJob(args[2], args[3])))
                } catch (failure: Exception) {
                    err("Original trusted CI job refused (${failure.javaClass.simpleName}); inspect intent before any continuation, never redispatch")
                    return 1
                }
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-r10-successor-compose-budgeted-v3" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.budgeted(v3=true)))
                    out("Versioned request binds lineage-aware ownership projector and fresh capacity envelope")
                } catch(failure:Exception) {
                    err("Versioned successor v3 capacity request refused (${failure.javaClass.simpleName}); retain evidence")
                    return 1
                }
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-q07-compose-budgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ07Source.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-q07-compose-unbudgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ07Source.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-q9b-compose-budgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ9bSource.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-q9b-compose-unbudgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ9bSource.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-q583-compose-budgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ583Source.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-q583-compose-unbudgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ583Source.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-q273-compose-budgeted-v2" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ273Source.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-q273-compose-unbudgeted-v2" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterQ273Source.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-capacity-refusal-compose-budgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterCapacityRefusalSource.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-capacity-refusal-compose-unbudgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterCapacityRefusalSource.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-native-import-compose-budgeted-v2" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterNativeImportSource.budgeted(revision=true)))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-native-import-compose-unbudgeted-v2" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterNativeImportSource.issue(args[2],revision=true)))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-native-import-compose-budgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterNativeImportSource.budgeted()))
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-native-import-compose-unbudgeted" -> {
                out(releaseOutputJson.encodeToString(GenerationAfterNativeImportSource.issue(args[2])))
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-after-preunit-compose-budgeted" -> {
                try { out(releaseOutputJson.encodeToString(GenerationAfterPreUnitSource.budgeted())) }
                catch(failure:Exception) {
                    err("After-preunit budgeted source refused (${failure.javaClass.simpleName}); preserve source evidence")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-preunit-compose-unbudgeted" -> {
                try { out(releaseOutputJson.encodeToString(GenerationAfterPreUnitSource.issue(args[2]))) }
                catch(failure:Exception) {
                    err("After-preunit source refused (${failure.javaClass.simpleName}); preserve all three histories")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-rootless-xdg-image-probe" -> {
                try {
                    out(releaseOutputJson.encodeToString(RootlessXdgImageProbe.issue(args[2])))
                    out("Separate isolated rootless image import probe only; no generation image or application ACK")
                } catch(failure:Exception) {
                    err("Isolated rootless native probe refused (${failure.javaClass.simpleName}); preserve intent, NEVER rerun an uncertain import")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-preunit-worklane-source" -> {
                try { out(releaseOutputJson.encodeToString(GenerationNormalizedWorklaneImage.issue(args[2]))) }
                catch(failure:Exception) {
                    err("After-preunit normalized Worklane source refused (${failure.javaClass.simpleName}); no OCI import")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-after-preunit-ci-source" -> {
                try { out(releaseOutputJson.encodeToString(GenerationR10CiExecutableSource.issueAfterPreUnit(args[2]))) }
                catch(failure:Exception) {
                    err("After-preunit CI source refused (${failure.javaClass.simpleName}); preserve original binary")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-successor-compose-unbudgeted-v3" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.issueV3(args[2])))
                    out("Versioned request binds lineage-aware site ownership; earlier pre-effect refusal retained")
                } catch(failure:Exception) {
                    err("Versioned successor v3 source refused (${failure.javaClass.simpleName}); preserve request history")
                    return 1
                }
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-r10-successor-compose-budgeted-v2" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.budgeted(v2=true)))
                    out("Versioned capacity request: CI VFS source and new controller, no bundle or native effect")
                } catch(failure:Exception) {
                    err("Versioned successor capacity-binding refused (${failure.javaClass.simpleName}); preserve source evidence")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-successor-compose-unbudgeted-v2" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.issueV2(args[2])))
                    out("Versioned successor request binds CI OCI VFS budget; original source and no-start histories preserved")
                } catch(failure:Exception) {
                    err("Versioned successor request refused (${failure.javaClass.simpleName}); preserve original request")
                    return 1
                }
            }
            args.size == 2 && args[0] == "release" && args[1] == "generation-r10-successor-compose-budgeted" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.budgeted()))
                    out("New full request binds original one-use capacity envelope; no sealed bundle or native effect")
                } catch(failure:Exception) {
                    err("Fresh successor capacity-binding source refused (${failure.javaClass.simpleName}); retain envelope, no replay")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-successor-compose-unbudgeted" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10SuccessorSource.issue(args[2])))
                    out("New request binds both predecessors and newly issued source; no sealed bundle or native effect")
                } catch(failure:Exception) {
                    err("Fresh successor unbudgeted source composition refused (${failure.javaClass.simpleName}); retain inputs, no rewrite")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-ci-vfs-budget-source" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10CiExecutableSource.issueRebudgeted(args[2])))
                    out("Source-only CI OCI VFS graph bound verified; no account, image load, runner or job effect")
                } catch(failure:Exception) {
                    err("Versioned CI VFS source refused (${failure.javaClass.simpleName}); preserve earlier source input")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r10-ci-executable-source" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR10CiExecutableSource.issue(args[2])))
                    out("Original host-built executable source pinned; no account, registration or job effect")
                } catch (failure: Exception) {
                    err("Versioned executable runner source refused (${failure.javaClass.simpleName}); preserve original artifact mode and receipt")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-r9-ci-source" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationR9CiSourceBindings.issue(args[2])))
                } catch (failure: Exception) {
                    err("Pinned fresh CI source refused (${failure.javaClass.simpleName}); no registration or native CI result issued")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] in setOf("bao-local-recipient-issue", "bao-local-recipient-issue-v2", "bao-fresh-local-recipient-issue-v3", "bao-local-recipient-verify") -> {
                try {
                    val runtime = GenerationRuntime.real()
                    val pin = when(args[1]) {
                        "bao-local-recipient-issue" -> runtime.issueLocalBaoRecipient(args[2])
                        "bao-local-recipient-issue-v2" -> runtime.issueLocalBaoRecipientAfterInvalidRedirect(args[2])
                        "bao-fresh-local-recipient-issue-v3" -> runtime.issueFreshLocalBaoRecipient(args[2])
                        else -> runtime.verifyLocalBaoRecipient(args[2])
                    }
                    out(releaseOutputJson.encodeToString(pin))
                    out("Owner-local age custody only; no Bao export, off-host handoff, or offline qualification")
                } catch (failure: Exception) {
                    err("Owner-local Bao recipient refused (${failure.javaClass.simpleName}); never retry an uncertain issue")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("generation-assembly-plan", "generation-canonical-plan", "generation-working-envelope", "generation-prepare", "site-ownership-inventory") -> {
                try {
                    val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    if (args[1] == "generation-canonical-plan") out(releaseOutputJson.encodeToString(CanonicalTopology.compile(plan, false).topology))
                    else if (args[1] == "generation-assembly-plan") out(releaseOutputJson.encodeToString(plan.summary))
                    else if (args[1] == "generation-working-envelope") {
                        out(releaseOutputJson.encodeToString(GenerationWorkingEnvelopeIssuer.issue(plan)))
                        out("Prospective source-only first-start envelope sealed; add the returned budget to the SAME private assembly request before owned preparation. Native stage still rechecks each process.")
                    }
                    else if (args[1] == "site-ownership-inventory") out(releaseOutputJson.encodeToString(SiteOwnerships.inspect(plan)))
                    else {
                        val digest = GenerationRuntime.real().prepareAssembly(plan)
                        out("${plan.generation.id} $digest")
                        out("Prepared typed private assembly; no services started, unseal, publication or full-stack qualification")
                    }
                } catch (failure: Exception) {
                    val detail = if (args[1] in setOf("generation-assembly-plan", "generation-canonical-plan", "site-ownership-inventory"))
                        failure.message?.takeIf { it.length in 1..180 &&
                            it.matches(Regex("[A-Za-z0-9 .,;:()_/-]+")) } else null
                    err("Typed assembly rejected (${failure.javaClass.simpleName}${detail?.let { ": $it" } ?: ""}); retain partial inputs, do not regenerate credentials")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-seal" -> {
                try {
                    val request = GenerationRuntime.request(Path.of(args[2]))
                    val digest = GenerationRuntime.real().seal(request)
                    out("${request.id} $digest")
                    out("Sealed private generation inputs; no services started, no release qualification")
                } catch (failure: Exception) {
                    err("Generation seal rejected (${failure.javaClass.simpleName}); private inputs retained")
                    return 1
                }
            }
            args.firstOrNull() == "release" && ((args.size == 5 && args[1] == "weekly-restore-enroll") ||
                (args.size == 4 && args[1] in setOf("weekly-restore-units", "weekly-restore-tick", "weekly-restore-suspend", "weekly-restore-alert"))) -> {
                try {
                    val scheduler = WeeklyRestoreSchedule.real()
                    when (args[1]) {
                        "weekly-restore-enroll" -> out(releaseOutputJson.encodeToString(scheduler.enroll(
                            GenerationRuntime.privateInput(Path.of(args[2])),
                            Json.decodeFromString<WeeklyRestoreBinding>(GenerationRuntime.privateInput(Path.of(args[3])).decodeToString()),
                            GenerationRuntime.privateInput(Path.of(args[4])))))
                        "weekly-restore-units" -> out(releaseOutputJson.encodeToString(scheduler.units(args[2], args[3])))
                        "weekly-restore-tick" -> out(releaseOutputJson.encodeToString(scheduler.tick(args[2], args[3])))
                        "weekly-restore-suspend" -> { scheduler.suspend(args[2], args[3]); out("Weekly restore suspended; evidence retained") }
                        "weekly-restore-alert" -> { scheduler.signalFailure(args[2], args[3]); err("Weekly restore failure retained; no retry or resume") }
                    }
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Weekly restore interrupted; no automatic retry or resume"); return 1
                } catch (failure: Exception) {
                    err("Weekly restore rejected (${failure.javaClass.simpleName}); retain all source/target fences and intents"); return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-kopia-retain" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationRuntime.privateInput(Path.of(args[2])).decodeToString())
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().retainKopia(inventory, args[3], args[4], args[5])))
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Retention interrupted; unknown deletion retained"); return 1
                } catch (failure: Exception) {
                    err("Retention rejected (${failure.javaClass.simpleName}); references and pending outcomes retained"); return 1
                }
            }
            args.firstOrNull() == "release" && ((args.size == 7 && args[1] == "backup-schedule-enroll") ||
                (args.size == 4 && args[1] in setOf("backup-schedule-units", "backup-schedule-tick", "backup-schedule-suspend", "backup-schedule-alert"))) -> {
                try {
                    val scheduler = GenerationBackupSchedule.real()
                    when (args[1]) {
                        "backup-schedule-enroll" -> out(releaseOutputJson.encodeToString(scheduler.enroll(
                            GenerationAssembly.readInventory(Path.of(args[2])), args[3], args[4], args[5], args[6].toInt())))
                        "backup-schedule-units" -> out(releaseOutputJson.encodeToString(scheduler.units(args[2], args[3])))
                        "backup-schedule-tick" -> out(releaseOutputJson.encodeToString(scheduler.tick(args[2], args[3])))
                        "backup-schedule-suspend" -> { scheduler.suspend(args[2], args[3]); out("Schedule suspended; evidence and source state retained") }
                        "backup-schedule-alert" -> { scheduler.signalFailure(args[2], args[3]); err("Scheduled backup blocked or failed; retained state requires reconciliation") }
                    }
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Scheduled backup interrupted; no automatic replay authorized"); return 1
                } catch (failure: Exception) {
                    err("Schedule operation rejected (${failure.javaClass.simpleName}); retain all bindings and intents; no automatic retry authorized")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-backup-reconcile" -> {
                try {
                    val result = GenerationRuntime.real().reconcileBackup(args[2], args[3], args[4], args[5], args[6])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) return 1
                    out("Stop-only backup reconciliation; original leases, intents, snapshots and outcomes retained")
                } catch (failure: Exception) {
                    err("Backup reconciliation rejected (${failure.javaClass.simpleName}); no resume or snapshot replay authorized")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-kopia-quadlet-preflight" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().auditQuadletCapture(inventory, args[3], args[4])))
                    out("Read-only original Quadlet source, volume roots and Kopia artifact; no capture ACK or restore authority")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet Kopia source preflight rejected (${failure.javaClass.simpleName}: $diagnostic); no capture attempted")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] in setOf("generation-kopia-capture", "generation-kopia-capture-quadlet", "generation-kopia-backup") -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    if (args[1] == "generation-kopia-backup") {
                        val result = GenerationRuntime.real().backupKopia(inventory, args[3], args[4], args[5])
                        out(releaseOutputJson.encodeToString(result))
                        if (!result.passed) return 1
                        out("Routine canonical backup resumed its own source; functional restore and full-stack qualification still required")
                    } else {
                        val result = if (args[1] == "generation-kopia-capture-quadlet")
                            GenerationRuntime.real().captureQuadletKopia(inventory, args[3], args[4], args[5])
                        else GenerationRuntime.real().captureKopia(inventory, args[3], args[4], args[5])
                        out(releaseOutputJson.encodeToString(result))
                        out("Native encrypted Kopia snapshot only; source remains stopped and fenced, functional restoration still required")
                    }
                } catch (failure: Exception) {
                    err("Kopia capture rejected (${failure.javaClass.simpleName}); retain repository, custody and pending intents; never resubmit uncertain snapshots")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-quadlet-import-diagnostic" -> {
                try {
                    out(GenerationRuntime.real().auditFailedQuadletImport(args[2], args[3], args[4]))
                    out("Read-only metadata preflight only; failed import remains non-replayable")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..170 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_/-]+")) } ?: "unspecified"
                    err("Failed original import read-only diagnostic (${failure.javaClass.simpleName}: $diagnostic); no effects attempted")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("images-canonical-private-stage-all", "images-canonical-private-audit-all") -> {
                try {
                    val inventory = GenerationAssembly.readInventory(Path.of(args[2]))
                    val order = Json.decodeFromString<List<String>>(GenerationRuntime.privateInput(Path.of(args[3])).decodeToString())
                    val staging = CanonicalPrivateImageStaging()
                    val results = if (args[1] == "images-canonical-private-audit-all")
                        staging.auditAll(inventory, order) else staging.stageAll(inventory, order)
                    out(releaseOutputJson.encodeToString(mapOf(
                        "candidateImages" to results.size,
                        "originalPullACKs" to results.count { it.originalPullAcknowledged },
                        "alreadyPresentObservations" to results.count { it.alreadyPresent })))
                    out("${if (args[1] == "images-canonical-private-audit-all") "Read-only re-audit of" else "Serialized"} private artifact closure only; no assembled application install or qualification")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Canonical artifact ${if (args[1] == "images-canonical-private-audit-all") "read-only audit" else "closure"} stopped (${failure.javaClass.simpleName}: $diagnostic); retain all original intents without replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("images-canonical-private-audit", "images-canonical-private-stage") -> {
                try {
                    val inventory = GenerationAssembly.readInventory(Path.of(args[2]))
                    val staging = CanonicalPrivateImageStaging()
                    if (args[1] == "images-canonical-private-audit") {
                        out(staging.audit(inventory, args[3])?.let { releaseOutputJson.encodeToString(it) } ?: "absent")
                        out("Read-only pinned artifact and canonical confinement check; no application process or pull ACK")
                    } else {
                        out(releaseOutputJson.encodeToString(staging.stage(inventory, args[3])))
                        out("Private canonical pinned image only; no product install, acceptance or release authority")
                    }
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Canonical private artifact staging rejected (${failure.javaClass.simpleName}: $diagnostic); no uncertain effect replay")
                    return 1
                }
            }
            args.size == 9 && args[0] == "release" && args[1] == "generation-kopia-quadlet-import-preflight" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    out(GenerationRuntime.real().auditQuadletImport(inventory, args[3], args[4], args[5], args[6], args[7], args[8]))
                    out("Read-only stopped-source, authenticated Kopia scratch, pinned controller and fresh compiled target; no import effect")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet cold import preflight rejected (${failure.javaClass.simpleName}: $diagnostic); no import effect")
                    return 1
                }
            }
            args.size == 9 && args[0] == "release" && args[1] == "generation-kopia-quadlet-import" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    val result = GenerationRuntime.real().importQuadletKopia(inventory, args[3], args[4], args[5], args[6], args[7], args[8])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) {
                        out("Isolated Quadlet resource/volume import incomplete; retain original intents and fence; do not replay")
                        return 1
                    }
                    out("Original Quadlet volumes independently read back; target remains fenced and stopped until separate systemd owner start")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet cold import rejected (${failure.javaClass.simpleName}: $diagnostic); retain partial target without replay")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-kopia-quadlet-verify" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().verifyQuadletKopia(
                        inventory, args[3], args[4], args[5], args[6])))
                    out("Original Quadlet Kopia payload authenticated into private scratch only; no runtime import or functional restore")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet Kopia scratch verification rejected (${failure.javaClass.simpleName}: $diagnostic); retain original worker intents")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] in setOf("generation-restore-foundation", "generation-restore-applications", "generation-restore-canonical-core", "generation-kopia-restore-canonical-core", "generation-kopia-restore-canonical-core-v2") -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    val runtime = GenerationRuntime.real()
                    val result = when (args[1]) {
                        "generation-restore-applications" -> runtime.restoreApplications(inventory, args[3], args[4], args[5], args[6])
                        "generation-restore-canonical-core" -> runtime.restoreCanonicalCore(inventory, args[3], args[4], args[5], args[6])
                        "generation-kopia-restore-canonical-core-v2" -> runtime.restoreKopiaCanonicalCore(inventory, args[3], args[4], args[5], args[6], targetStore = RuntimeStore.CANONICAL_V2)
                        "generation-kopia-restore-canonical-core" -> runtime.restoreKopiaCanonicalCore(inventory, args[3], args[4], args[5], args[6])
                        else -> runtime.restoreFoundation(inventory, args[3], args[4], args[5], args[6])
                    }
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) {
                        out("Import failed; inspect retained isolation outcome, never start or replay the failed target")
                        return 1
                    }
                    out("Fresh targets remain stopped and fenced; native functional readback is still required")
                } catch (failure: Exception) {
                    err("Compiled cohort restoration rejected (${failure.javaClass.simpleName}); retain all intents, imports and fences")
                    return 1
                }
            }
            args.size == 8 && args[0] == "release" && args[1] == "generation-recovery-check" -> {
                try {
                    val verified = RecoveryCapsule.verify(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6])
                    out(releaseOutputJson.encodeToString(GenerationRecovery.validate(Path.of(args[7]), verified).check))
                } catch (failure: Exception) {
                    err("Recovery binding rejected (${failure.javaClass.simpleName}); no runtime import authorized")
                    return 1
                }
            }
            args.size == 8 && args[0] == "release" && args[1] == "capsule-extract" -> {
                try {
                    out(releaseOutputJson.encodeToString(RecoveryCapsule.extract(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6], Path.of(args[7]))))
                } catch (failure: Exception) {
                    err("Capsule extraction rejected (${failure.javaClass.simpleName}); retain partial private destination; no runtime import")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "volume-tar-inspect" -> {
                try {
                    out(releaseOutputJson.encodeToString(VolumeTar.inspect(Path.of(args[2]), args[3].toInt())))
                } catch (failure: Exception) {
                    err("Volume archive rejected (${failure.javaClass.simpleName}); no extraction or runtime effects")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "capsule-verify" -> {
                try {
                    out(releaseOutputJson.encodeToString(RecoveryCapsule.verify(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6])))
                } catch (failure: Exception) {
                    err("Capsule verification rejected (${failure.javaClass.simpleName}); no extraction or runtime effects")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] in setOf("generation-capture", "generation-verify-capture") -> {
                try {
                    val runtime = GenerationRuntime.real()
                    if (args[1] == "generation-capture") out(releaseOutputJson.encodeToString(runtime.capture(args[2], args[3], args[4])))
                    else out(releaseOutputJson.encodeToString(runtime.verifyCapture(args[2], args[3], args[4])))
                    out("Authenticated local cold capture only; functional restoration and full-stack qualification remain unproven")
                } catch (failure: Exception) {
                    err("Generation capture rejected (${failure.javaClass.simpleName}); retain capture and custody evidence")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-reconcile-isolation" -> {
                try {
                    val result = GenerationRuntime.real().reconcileIsolation(args[2], args[3], args[4], args[5])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) return 1
                    out("Private isolation reconciliation only; no initialization, writes, restart or publication")
                } catch (failure: Exception) {
                    err("Isolation reconciliation rejected (${failure.javaClass.simpleName}); original evidence retained")
                    return 1
                }
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "unit-run" -> {
                val member = args[2]
                require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")))
                val generation = member.take(14)
                val root = GenerationRuntime.BASE.resolve(generation)
                val result = RuntimeQuadletUnitRun(root, RuntimeQuadletDelegation(root))
                    .run(generation, member, args[3])
                out(releaseOutputJson.encodeToString(result))
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "unit-guard" -> {
                val member = args[2]
                require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")))
                val generation = member.take(14)
                val root = GenerationRuntime.BASE.resolve(generation)
                RuntimeQuadletUnitRun(root, RuntimeQuadletDelegation(root))
                    .guard(generation, member, args[3])
                out("Post-stop owner-loss guard observed; no original effect replayed")
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "unit-stop" -> {
                val member = args[2]
                require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")))
                val generation = member.take(14)
                val root = GenerationRuntime.BASE.resolve(generation)
                val result = RuntimeQuadletStop(root, RuntimeQuadletDelegation(root))
                    .stop(generation, member, args[3])
                out(releaseOutputJson.encodeToString(result))
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "unit-admit" -> {
                val member = args[2]
                require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")))
                val generation = member.take(14)
                val result = RuntimeQuadletDelegation(GenerationRuntime.BASE.resolve(generation))
                    .acknowledge(generation, member, args[3], "start")
                out(releaseOutputJson.encodeToString(result))
            }
            args.size == 6 && args[0] == "runtime" && args[1] == "quadlet-copy" -> {
                RuntimeQuadletRootCopy.copy(Path.of(args[2]), Path.of(args[3]), args[4], args[5])
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-serve" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().serveQuadlet(args[2], args[3])))
                    out("Private systemd serving episode stopped and fenced; no activation or qualification")
                } catch (failure: Exception) {
                    err("Quadlet serving episode uncertain (${failure.javaClass.simpleName}); inspect original unit and CID records, do not replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-serve-restored-preflight" -> {
                try {
                    out(GenerationRuntime.real().auditImportedQuadletServing(args[2], args[3]))
                    out("Read-only imported target, installed units, native resources and restore fence; no systemd start or restored functional claim")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Restored Quadlet serving preflight rejected (${failure.javaClass.simpleName}: $diagnostic); no start attempted")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-serve-restored" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().serveImportedQuadlet(args[2], args[3])))
                    out("Isolated systemd-owned recovery stopped and fenced; functional readback remains separate")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Recovered Quadlet serving uncertain (${failure.javaClass.simpleName}: $diagnostic); retain original unit/CID records")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-capacity-terminal" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().terminalQuadletCapacity(args[2], args[3])))
                    out("Separate terminal capacity observation only; original isolation ACK and restore are not implied")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet terminal capacity observation rejected (${failure.javaClass.simpleName}: $diagnostic); retain original effects")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-separate-terminal-status" -> {
                try {
                    val receipt=GenerationRuntime.real().verifySeparateQuadletTerminal(args[2],args[3])
                    out("Independent physical capacity disposition verified for ${receipt.generation}; " +
                        "${receipt.originalCids.size} exact exited CIDs; original serving/stop ACKs remain incomplete")
                } catch (failure: Exception) {
                    val diagnostic=failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Separate terminal status uncertain (${failure.javaClass.simpleName}: $diagnostic); retain reservation")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-separate-terminal-check" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().checkSeparateQuadletTerminal(args[2],args[3])))
                    out("Readback only: no capacity receipt recorded, original ACKs remain missing")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    val where = failure.stackTrace.firstOrNull { it.className.startsWith("net.datamancy.platform.") }
                        ?.let { it.className.substringAfterLast('.') + "." + it.methodName + ":" + it.lineNumber }
                        ?: "unknown"
                    err("Separate physical disposition check rejected (${failure.javaClass.simpleName}: $diagnostic at $where); no effect replayed")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-separate-terminal" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().separateQuadletTerminal(args[2],args[3])))
                    out("Separate physical capacity disposition only; missing original ACKs remain missing")
                } catch (failure: Exception) {
                    err("Separate physical disposition rejected (${failure.javaClass.simpleName}); no original effect replayed")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-serve-stop" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().requestQuadletServeStop(args[2], args[3])))
                    out("Original stop request recorded; owner must verify and execute one StopUnit per CID")
                } catch (failure: Exception) {
                    err("Original serving stop request rejected (${failure.javaClass.simpleName}); do not reissue")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-stage" -> {
                try {
                    val result = GenerationRuntime.real().stageQuadlet(args[2], args[3])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) return 1
                    out("Private owned Quadlet stage only; no activation or qualification")
                } catch (failure: Exception) {
                    err("Quadlet stage rejected (${failure.javaClass.simpleName}); reconcile original, never replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-quadlet-capacity-preflight" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().auditQuadletCapacity(args[2], args[3])))
                    out("Read-only capacity diagnostic; installer must recheck before any effect")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..150 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Quadlet capacity preflight rejected (${failure.javaClass.simpleName}: $diagnostic); no installation authorized")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-unit-install" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().installQuadlet(args[2], args[3], args[4])))
                    out("Disabled installed Quadlet sources only; no StartUnit or release qualification")
                } catch (failure: Exception) {
                    val gate = failure as? GenerationRuntime.QuadletInstallGateFailure
                    val known = setOf("Insufficient phase capacity; no workload eviction or implicit maintenance fallback",
                        "Insufficient dedicated runtime object locks; preserve retained resources and do not renumber shared locks",
                        "Unknown generation registry entry", "Insufficient protected recovery headroom",
                        "Invalid capacity reservation intent", "Incomplete or foreign assembly preparation",
                        "Invalid runtime object census", "Isolation evidence is stale; reservation cannot be released",
                        "Unordered native member lock cannot join an existing source/target isolation cohort")
                    val cause = gate?.cause
                    val category = cause?.message?.takeIf { gate.stage == "capacity" && it in known }
                        ?: cause?.javaClass?.simpleName ?: failure.javaClass.simpleName
                    err("Quadlet installation rejected (${gate?.stage ?: "boundary"}, $category); retain original intent, do not replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-unit-emergency-contain" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().emergencyContainFailedQuadlet(args[2], args[3])))
                    out("Independent exact-CID owner-death emergency containment only; original missing ACKs, fence and capacity uncertainty remain")
                } catch (failure: Exception) {
                    err("Independent Quadlet emergency containment rejected (${failure.javaClass.simpleName}); retain intent and fence, never retry uncertain effect")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-unit-stage-terminal-audit" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().auditFailedQuadletStageTerminal(args[2], args[3])))
                    out("Read-only fenced failed-stage capacity audit; missing original ACKs remain missing")
                } catch (failure: Exception) {
                    err("Failed-stage terminal audit rejected (${failure.javaClass.simpleName}); no capacity release authorized")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-unit-stage-reconcile" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().reconcileQuadletStage(args[2], args[3])))
                    out("Terminal failed-stage observation only; original fence, exact stopped CIDs and missing stage result retained")
                } catch (failure: Exception) {
                    val known = setOf("Generation input binding changed", "Unbound failed-stage original start or generated launch intent",
                        "Original result without launch intent", "Unacknowledged CID has no exact stopped native identity",
                        "Native stopped process cannot replace a missing original helper ACK",
                        "Changed installed policy or native container after failed StartUnit",
                        "Incomplete original failed-stage ACK cannot be treated as a terminal observation",
                        "Invalid sealed member definition", "Incomplete or foreign assembly preparation")
                    val reason = failure.message?.takeIf { it in known } ?: "unspecified"
                    val origin = failure.stackTrace.firstOrNull { it.className.startsWith("net.datamancy.platform.") }
                        ?.let { "${it.fileName}:${it.lineNumber}" } ?: "unknown"
                    err("Failed Quadlet stage reconciliation rejected (${failure.javaClass.simpleName}: $reason at $origin); retain all original evidence")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] == "generation-unit-reconcile" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().reconcileQuadletInstall(
                        args[2], args[3], args[4])))
                    out("Terminal observation of interrupted install only; original result remains missing, no StartUnit")
                } catch (failure: Exception) {
                    err("Interrupted Quadlet install reconciliation rejected (${failure.javaClass.simpleName}); retain original evidence")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-unit-audit" -> {
                try {
                    out(GenerationRuntime.real().auditInstalledQuadlet(args[2], args[3], args[4], args[5]))
                    out("Read-only installed Quadlet audit; no StartUnit, runtime admission or release qualification")
                } catch (failure: Exception) {
                    val diagnostic = failure.message?.takeIf { it.length in 1..180 &&
                        it.matches(Regex("[A-Za-z0-9 .,;:()_-]+")) } ?: "unspecified"
                    err("Installed Quadlet audit rejected (${failure.javaClass.simpleName}: $diagnostic); no unit start authorized")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-failed-pre-unit-stage-terminal" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().terminalizeFailedPreUnitServe(args[2],args[3])))
                    out("Original stage/managed intents retained; exact native no-unit/no-CID readback only, no START ACK")
                } catch(failure:Exception) {
                    err("Failed pre-unit stage terminal refused (${failure.javaClass.simpleName}); retain original intents, never replay serving")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-qc3-pre-native-capacity-no-start-terminal" -> {
                try {
                    out(releaseOutputJson.encodeToString(
                        GenerationRuntime.real().terminalizeQc3PreparedNoStart(args[2],args[3])))
                    out("qc3 PRE-NATIVE capacity refusal terminal; q4d imported graph unchanged, NO START or qualification")
                } catch(failure:Exception) {
                    err("qc3 prepared-no-start terminal refused (${failure.javaClass.simpleName}); preserve original bundle and native absence")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-uncertain-managed-import-terminal" -> {
                try {
                    out(releaseOutputJson.encodeToString(
                        GenerationRuntime.real().terminalizeUncertainManagedImport(args[2],args[3])))
                    out("Original Worklane import OBSERVED but never ACKNOWLEDGED; graph retained, no START or qualification")
                } catch(failure:Exception) {
                    err("Uncertain managed import terminal refused (${failure.javaClass.simpleName}); retain original intent, graph and owner records; never replay")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "generation-prepared-no-start-terminal-v2" -> {
                try {
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().terminalizePreparedNoStart(args[2],args[3])))
                    out("Previously passed owned PREPARE terminalized as no-START; no unit, CID or credential ACK inferred")
                } catch (failure: Exception) {
                    err("Prepared no-start terminal observation refused (${failure.javaClass.simpleName}); preserve original sealed bundle and native absence")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("generation-audit", "generation-stage", "generation-isolate") -> {
                try {
                    val runtime = GenerationRuntime.real()
                    if (args[1] == "generation-audit") out(releaseOutputJson.encodeToString(runtime.inspect(args[2], args[3])))
                    else {
                        val result = if (args[1] == "generation-stage") runtime.stage(args[2], args[3]) else runtime.isolate(args[2], args[3])
                        out(releaseOutputJson.encodeToString(result))
                        if (!result.passed) return 1
                    }
                    out("Private generation only: no public activation or full-stack qualification")
                } catch (failure: Exception) {
                    err("Generation operation rejected (${failure.javaClass.simpleName}); retain intents and reconcile, do not replay")
                    return 1
                }
            }
            args.size == 5 && args[0] == "runtime" && args[1] == "boot-unit" -> {
                val bytes = ReleaseLocks.privateBytes(RuntimeBootUnits.manifest(args[2]))
                val hash = RuntimeBootUnits.hash(bytes)
                val spec = RuntimeBootUnits.boundSpec(args[2], hash)
                out(RuntimeBootUnits.render(spec, hash, args[3], args[4].toInt()))
            }
            args.size == 4 && args[0] == "runtime" && args[1] in setOf("boot-apply", "boot-stop") -> {
                val spec = RuntimeBootUnits.boundSpec(args[2], args[3])
                val runtime = PrivateDeployment.real()
                val result = if (args[1] == "boot-apply") runtime.apply(spec) else runtime.stop(spec)
                out(releaseOutputJson.encodeToString(result))
            }
            args.size in 3..4 && args[0] == "runtime" && args[1] in setOf("prepare-foundation", "prepare-identity", "prepare-observability", "prepare-forgejo", "prepare-planka", "prepare-sql-cache", "prepare-jellyfin", "prepare-donetick", "prepare-homeassistant", "prepare-notebook", "prepare-qbittorrent", "prepare-synapse", "prepare-matrix", "prepare-opensearch", "prepare-firefly", "prepare-bookstack", "prepare-knowledge-identity", "prepare-livekit", "prepare-openbao", "prepare-mastodon", "prepare-matrix-identity", "prepare-matrix-rtc", "prepare-searxng", "prepare-erpnext", "prepare-crowdsec", "prepare-seafile", "prepare-office", "prepare-keykeeper", "prepare-node-metrics", "prepare-backup", "prepare-huly", "prepare-jupyterhub", "prepare-sogo", "prepare-mail", "prepare-sogo-mail") -> {
                val inventory = ImageStaging.inventory(Path.of(args[2]))
                val path = when (args[1]) {
                    "prepare-foundation" -> FoundationRuntime.prepare(inventory, name = args.getOrNull(3) ?: "foundation")
                    "prepare-identity" -> IdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "identity")
                    "prepare-observability" -> ObservabilityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "observability")
                    "prepare-forgejo" -> ForgejoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "forgejo")
                    "prepare-planka" -> PlankaRuntime.prepare(inventory, name = args.getOrNull(3) ?: "planka")
                    "prepare-sql-cache" -> SqlCacheRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sql-cache")
                    "prepare-jellyfin" -> JellyfinRuntime.prepare(inventory, name = args.getOrNull(3) ?: "jellyfin")
                    "prepare-erpnext" -> ErpNextRuntime.prepare(inventory, name = args.getOrNull(3) ?: "erpnext")
                    "prepare-crowdsec" -> CrowdsecRuntime.prepare(inventory, name = args.getOrNull(3) ?: "crowdsec")
                    "prepare-seafile" -> SeafileRuntime.prepare(inventory, name = args.getOrNull(3) ?: "seafile")
                    "prepare-office" -> OfficeRuntime.prepare(inventory, name = args.getOrNull(3) ?: "files-office")
                    "prepare-keykeeper" -> KeykeeperRuntime.prepare(inventory, name = args.getOrNull(3) ?: "keykeeper-identity")
                    "prepare-node-metrics" -> NodeMetricsRuntime.prepare(inventory, name = args.getOrNull(3) ?: "node-metrics")
                    "prepare-backup" -> KopiaRuntime.prepare(inventory, name = args.getOrNull(3) ?: "backup")
                    "prepare-huly" -> HulyRuntime.prepare(inventory, name = args.getOrNull(3) ?: "huly")
                    "prepare-jupyterhub" -> JupyterHubRuntime.prepare(inventory, name = args.getOrNull(3) ?: "jupyterhub")
                    "prepare-sogo" -> SogoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sogo")
                    "prepare-sogo-mail" -> SogoMailRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sogo-mail")
                    "prepare-mail" -> MailRuntime.prepare(name = args.getOrNull(3) ?: "mail")
                    "prepare-searxng" -> SearxngRuntime.prepare(inventory, name = args.getOrNull(3) ?: "searxng")
                    "prepare-donetick" -> DonetickRuntime.prepare(inventory, name = args.getOrNull(3) ?: "donetick")
                    "prepare-homeassistant" -> HomeAssistantRuntime.prepare(inventory, name = args.getOrNull(3) ?: "homeassistant")
                    "prepare-notebook" -> NotebookRuntime.prepare(inventory, name = args.getOrNull(3) ?: "notebook")
                    "prepare-qbittorrent" -> QbittorrentRuntime.prepare(inventory, name = args.getOrNull(3) ?: "qbittorrent")
                    "prepare-synapse" -> SynapseRuntime.prepare(inventory, name = args.getOrNull(3) ?: "synapse")
                    "prepare-matrix" -> MatrixRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix")
                    "prepare-opensearch" -> OpenSearchRuntime.prepare(inventory, name = args.getOrNull(3) ?: "opensearch")
                    "prepare-firefly" -> FireflyRuntime.prepare(inventory, name = args.getOrNull(3) ?: "firefly")
                    "prepare-bookstack" -> BookStackRuntime.prepare(inventory, name = args.getOrNull(3) ?: "bookstack")
                    "prepare-knowledge-identity" -> KnowledgeIdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "knowledge-identity")
                    "prepare-matrix-rtc" -> MatrixRtcRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix-rtc")
                    "prepare-livekit" -> LiveKitRuntime.prepare(inventory, name = args.getOrNull(3) ?: "livekit")
                    "prepare-openbao" -> OpenBaoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "openbao")
                    "prepare-mastodon" -> MastodonRuntime.prepare(inventory, name = args.getOrNull(3) ?: "mastodon")
                    else -> MatrixIdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix-identity")
                }
                out("Prepared persistent private runtime at $path; credentials retained privately, no services started")
            }
            args.size == 5 && args[0] == "runtime" && args[1] in setOf("prepare-forgejo-restore", "prepare-single-user-restore", "prepare-firefly-restore", "prepare-livekit-restore", "prepare-mastodon-restore", "prepare-searxng-restore", "prepare-seafile-restore", "prepare-node-metrics-restore", "prepare-sogo-mail-restore", "prepare-erpnext-restore") -> {
                val inventory = ImageStaging.inventory(Path.of(args[2]))
                val path = when (args[1]) {
                    "prepare-forgejo-restore" -> ForgejoRuntime.prepareRestore(inventory, Path.of(args[3]), name = args[4])
                    "prepare-searxng-restore" -> SearxngRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-seafile-restore" -> SeafileRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-node-metrics-restore" -> NodeMetricsRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-erpnext-restore" -> ErpNextRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-sogo-mail-restore" -> SogoMailRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-livekit-restore" -> LiveKitRuntime.prepareRestore(inventory, Path.of(args[3]), name = args[4])
                    "prepare-firefly-restore" -> FireflyRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-mastodon-restore" -> MastodonRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    else -> SingleUserRestore.prepare(inventory, Path.of(args[3]), name = args[4])
                }
                out("Prepared isolated restore manifest at $path; recovered data must be verified before apply")
            }
            args.size in 4..5 && args[0] == "runtime" && args[1] == "maintenance-enter" -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().enterMaintenance(spec, args[3], args.getOrNull(4))))
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "maintenance-status" -> {
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().maintenanceStatus(PrivateDeployment.read(Path.of(args[2])))))
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "maintenance-leave" -> {
                PrivateDeployment.real().leaveMaintenance(PrivateDeployment.read(Path.of(args[2])), args[3])
                out("Maintenance released; applications remain stopped")
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "stage-private" -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().stage(spec, args[3])))
                out("Dependency-only staging; a maintenance-enter fence is required to block ordinary startup; not full-stack activation")
            }
            args.size == 3 && args[0] == "runtime" && args[1] in setOf("provision-private", "apply-private", "stop-private", "status-private") -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                val runtime = PrivateDeployment.real()
                val result = when (args[1]) {
                    "provision-private" -> runtime.provision(spec)
                    "apply-private" -> runtime.apply(spec)
                    "stop-private" -> runtime.stop(spec)
                    else -> runtime.status(spec)
                }
                out(releaseOutputJson.encodeToString(result))
                out("Private runtime only: no published ports, no full-stack or public release acceptance")
            }
            RssScheduleCommands.run(args, out) -> Unit
            args.size == 3 && args[0] == "rss" && args[1] == "initialize" -> {
                val root = Path.of(args[2])
                require(root.isAbsolute) { "Absolute RSS state path required" }
                rssStateMutation(root) {
                    if (!java.nio.file.Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS))
                        java.nio.file.Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                    val state = RssStateStore(root)
                    state.withWriteAdmission { state.initializeFresh() }
                }
                out("Initialized fresh RSS state; existing state is never reset on reinstall")
            }
            args.size == 4 && args[0] == "rss" && args[1] == "verify-accounts" -> {
                val sender = MastodonRssSender(java.net.URI(args[2]), { account ->
                    MastodonRssSender.privateToken(Path.of(args[3]).resolve("$account.token"))
                }, JdkRssHttp())
                val accounts = RssPacks.load().map { sender.verifyAccount(it.feed.account) }
                require(accounts.distinct().size == accounts.size) { "RSS account identities are not distinct" }
                out("Verified ${accounts.size} distinct RSS bot accounts; read-only, no publication enabled")
            }
            args.size in setOf(4, 6) && args[0] == "rss" && args[1] == "poll" -> {
                val gate = PollGate.valueOf(args[2].uppercase())
                require((gate == PollGate.ACTIVE && args.size == 6) || (gate != PollGate.ACTIVE && args.size == 4))
                require(gate != PollGate.ACTIVE) { "Active RSS requires an enrolled release-bound schedule; use rss schedule-tick" }
                val root = Path.of(args[3])
                val result = rssStateMutation(root) {
                    val state = RssStateStore(root)
                    state.withWriteAdmission {
                        RssWorker(state, RssFetcher(JdkRssHttp())::fetch,
                            { error("Outbound publishing disabled; use an enrolled release-bound schedule") }).poll(gate)
                    }
                }
                out("RSS ${gate.name.lowercase()}: ${result.feeds} feeds, ${result.observed} observed, ${result.confirmed} confirmed, ${result.failedFeeds.size} failed")
                require(result.failedFeeds.isEmpty()) { "RSS feeds failed without checkpoint advancement: ${result.failureTypes.entries.joinToString(",") { "${it.key}:${it.value}" }}" }
            }
            args.size == 3 && args[0] == "release" && args[1] == "fresh-identity-new" -> {
                out(releaseOutputJson.encodeToString(FreshIdentityBootstrap.createOnce(Path.of(args[2]))))
            }
            args.size == 3 && args[0] == "release" && args[1] == "original-groups-seal" -> {
                val request = releaseOutputJson.decodeFromString<OriginalIdentityGroupSealRequest>(
                    GenerationRuntime.privateInput(Path.of(args[2])).decodeToString(throwOnInvalidSequence = true))
                out(releaseOutputJson.encodeToString(OriginalIdentityGroupQueryOwner.seal(request)))
            }
            args.size == 3 && args[0] == "release" && args[1] == "original-groups-capture" -> {
                val request = releaseOutputJson.decodeFromString<OriginalIdentityGroupQueryRequest>(
                    GenerationRuntime.privateInput(Path.of(args[2])).decodeToString(throwOnInvalidSequence = true))
                val output = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/${request.generation}")
                out(releaseOutputJson.encodeToString(OriginalIdentityGroupQueryOwner.capture(request, output)))
            }
            args.size == 3 && args[0] == "images" && args[1] == "stage" -> {
                val staged = ImageStaging.real().stage(ImageStaging.inventory(Path.of(args[2])))
                out("Verified ${staged.size} content-addressed images in the private v3 store; no services started or compatibility accepted")
            }
            args.size == 7 && args[0] == "release" && args[1] in setOf("validate", "plan") -> {
                val (lock, hash) = ReleaseLocks.validate(Path.of(args[2]), Path.of(args[3]), Path.of(args[4]),
                    Path.of(args[5]), Path.of(args[6]))
                if (args[1] == "plan") out(releaseOutputJson.encodeToString(ReleasePlanning.offline(lock, hash)))
                else out("Validated ${lock.products.size} logical products; lock sha256:$hash; offline only, no images or releases verified upstream")
            }
            args.size == 8 && args[0] == "release" && args[1] == "generator-dryrun" -> {
                val (lock, hash) = ReleaseLocks.validate(Path.of(args[2]), Path.of(args[3]), Path.of(args[4]),
                    Path.of(args[5]), Path.of(args[6]))
                val approved = ReleaseLocks.approvedHosts(Path.of(args[6]))
                val bundle = PrivateQuadlets.render(lock, approved, Path.of(args[7]))
                val count = QuadletDryRun.verify(bundle)
                out("$count temporary Quadlet files passed generator private-store audit for sha256:$hash; no install or Podman execution")
            }
            args.size == 3 && args[0] == "release" && args[1] == "status" -> {
                val records = TransactionJournal.verify(Path.of(args[2]))
                val last = records.last()
                out(Json.encodeToString(last))
            }
            args.firstOrNull() == "release" && args.getOrNull(1) in setOf("install", "update", "status", "backup", "restore-test", "rollback") -> {
                throw IllegalStateException("Release executor not implemented; no v3 production resources changed")
            }
            args.size == 4 && args[0] == "site" && args[1] == "validate" -> {
                val sites = Sites.from(Path.of(args[2]))
                sites.select(args[3])
                out("Explicit site ${args[3]} valid; no installation or acceptance claimed")
            }
            args.size == 4 && args[0] == "plan" && args[1] == "render" -> {
                val site = Sites.from(Path.of(args[2])).select(args[3])
                out(Json.encodeToString(RenderPlan.forSite(site)))
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "identity" -> {
                val sandbox = IdentitySandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "backup" -> { require(args.size == 4); sandbox.backup(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown identity sandbox action")
                }
                out("Fake identity sandbox ${args[2]} completed; no production SSO acceptance")
            }
            args.size == 3 && args[0] == "module" && args[1] == "sandbox-backup" &&
                args[2] in setOf("due", "two") -> {
                val count = if (args[2] == "due") {
                    if (SandboxBackupSchedule.real().runDue()) 1 else 0
                } else SandboxBackupSchedule.real(periodSeconds = 3).runBounded(maxRuns = 2)
                out("Bounded two-module sandbox backup completed $count slot(s); no full-stack acceptance")
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "postgres" -> {
                val sandbox = PostgresSandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "write" -> { require(args.size == 3); sandbox.writeFixture() }
                    "query" -> { require(args.size == 3); out(sandbox.query()) }
                    "backup" -> { require(args.size == 4); sandbox.backup(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restored-write" -> { require(args.size == 4); sandbox.writeRestored(args[3]) }
                    "restored-query" -> { require(args.size == 4); out(sandbox.query(args[3])) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown postgres sandbox action")
                }
                out("Isolated postgres sandbox ${args[2]} completed; no other inventory module accepted")
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "ntfy" -> {
                val sandbox = NtfySandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "snapshot" -> { require(args.size == 4); sandbox.snapshot(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown ntfy sandbox action")
                }
                out("Isolated ntfy sandbox ${args[2]} completed; no other inventory module accepted")
            }
            args.size in 4..5 && args[0] == "probe" && args[1] in setOf("prepare", "install", "stop", "remove", "snapshot", "restore") -> {
                val selection = ProbeSelection(args[2], args[3])
                val lifecycle = ProbeLifecycle.real()
                when (args[1]) {
                    "prepare" -> { require(args.size == 4); lifecycle.prepare(selection) }
                    "install" -> { require(args.size == 4); lifecycle.install(selection) }
                    "stop" -> { require(args.size == 4); lifecycle.stop(selection) }
                    "remove" -> { require(args.size == 4); lifecycle.remove(selection) }
                    "snapshot" -> { require(args.size == 5); lifecycle.snapshot(selection, args[4]) }
                    "restore" -> { require(args.size == 5); lifecycle.restoreIsolated(selection, args[4]) }
                }
                out("Restricted probe ${args[1]} completed; no catalog module or production service accepted")
            }
            args.size == 6 && args[0] == "contract" && args[1] == "plan" -> {
                val site = DeploymentSite.hostLocal(Path.of(args[2]))
                val boundary = DeploymentBoundary(Path.of(args[4]), Path.of(args[5]), DeploymentSite.approvedHosts(Path.of(args[3])))
                out(Json.encodeToString(DeploymentContracts.plan(site, boundary)))
            }
            args.size == 5 && args[0] == "lane" && args[1] == "plan" -> {
                val request = LaneAccountRequest.from(Path.of(args[2]))
                val occupied = LaneAccounts.occupiedFrom(Path.of(args[4]))
                out(Json.encodeToString(LaneAccounts.plan(request, args[3], occupied)))
            }
            args.size == 5 && args[0] == "stage" && args[1] == "offline" -> {
                IsolatedStage.stage(Sites.from(Path.of(args[2])), args[3], Path.of(args[4]))
                out("Offline staged ${args[3]}; Podman/systemd not invoked")
            }
            args.size == 4 && args[0] == "stage" && args[1] == "restore" -> {
                IsolatedStage.restore(Path.of(args[2]), args[3])
                out("Offline workspace restored; no live services changed")
            }
            else -> {
                err("Usage: platform release fragment-lint <fragment.yaml> (offline only) | release generation-render <inventory> <assembly-request> <new-private-directory> | release generation-quadlet-check <inventory> <assembly-request> (generator only) | release install|update|backup|restore-test|rollback|reconcile|qualify|activate <private-request.json> | runtime ingress-lifecycle|private-pki-lifecycle <private-request.json> | release site-ownership-inventory <inventory.json> <private-assembly-request.json> | release site-ownership-check|generation-prepare-owned <inventory.json> <private-assembly-request.json> <private-ownership.json> <private-approved-hosts.json> | release capsule-extract <archive> <key-file> <cap-id> <q-id> <bundle-sha256> <fresh-private-directory> | release volume-tar-inspect <private-tar> <expected-uid-and-gid> | release capsule-verify <archive> <key-file> <cap-id> <q-id> <bundle-sha256> | release generation-capture|generation-verify-capture <q-generation-id> <bundle-sha256> <cap-capture-id> | release generation-assembly-plan|generation-canonical-plan|generation-working-envelope|generation-prepare <inventory.json> <private-assembly-request.json> | release generation-seal <private-generation-request.json> | release generation-audit|generation-stage|generation-isolate <q-generation-id> <bundle-sha256> | release generation-quadlet-stage <q-generation-id> <bundle-sha256> (owned single member) | release generation-unit-install <q-generation-id> <bundle-sha256> <member> (disabled sources only) | release generation-unit-audit <q-generation-id> <bundle-sha256> <member> <process> | release generation-reconcile-isolation <q-generation-id> <bundle-sha256> <r-reconciliation-id> <original-isolation-intent-sha256> | runtime unit-admit|unit-run|unit-stop <member> <process> (systemd helper only; owned lease required) | runtime maintenance-enter <manifest> backup|restore|update [stage-target] | runtime maintenance-status <manifest> | runtime maintenance-leave <manifest> <fence-id> | runtime stage-private <private-runtime-manifest.json> <process-id> | runtime boot-unit <deployment-name> <controller-tree-sha256> <non-root-uid> | runtime boot-apply|boot-stop <deployment-name> <manifest-sha256> | runtime prepare-foundation|prepare-identity|prepare-observability|prepare-forgejo|prepare-planka|prepare-sql-cache|prepare-jellyfin|prepare-donetick|prepare-homeassistant|prepare-notebook|prepare-qbittorrent|prepare-synapse|prepare-matrix|prepare-opensearch|prepare-firefly|prepare-bookstack|prepare-knowledge-identity|prepare-livekit|prepare-openbao|prepare-mastodon|prepare-matrix-identity|prepare-matrix-rtc|prepare-searxng|prepare-erpnext|prepare-crowdsec|prepare-seafile|prepare-office|prepare-keykeeper|prepare-node-metrics|prepare-backup|prepare-huly|prepare-jupyterhub|prepare-sogo|prepare-mail|prepare-sogo-mail <candidate-inventory.json> [deployment-name] | runtime prepare-forgejo-restore|prepare-single-user-restore|prepare-firefly-restore|prepare-livekit-restore|prepare-mastodon-restore|prepare-searxng-restore|prepare-seafile-restore|prepare-node-metrics-restore|prepare-sogo-mail-restore|prepare-erpnext-restore <inventory.json> <recovered-private-input-directory> <new-name> | runtime provision-private|apply-private|stop-private|status-private <private-runtime-manifest.json> | rss verify-accounts <https-origin> <private-token-directory> | rss initialize <private-state-dir> | rss poll staging|restoring <private-state-dir> | rss schedule-enroll <private-schedule-root> <private-binding.json> | rss schedule-units|schedule-tick|schedule-pause <private-schedule-root> <binding-sha256> | rss reconcile <private-schedule-root> <binding-sha256> <state-sha256> <account> <item-key> <status-id> | images stage <downloaded-candidate-inventory.json> | release validate|plan <private-lock.json> <private-sha256-file> <private-signature-base64> <trusted-ed25519-public-key-base64> <private-approved-hosts.json> | release generator-dryrun <same-five-lock-inputs> <explicit-v3-owned-root> | release status <private-journal-file> (verification only; no live resource inventory) (typed operations remain subject to complete lineage, coverage and activation admission) | module identity prepare|install|stop|remove|backup|restore|restore-remove [backup-id] | module sandbox-backup due|two | module postgres prepare|install|stop|remove|write|query|backup|restore|restored-write|restored-query|restore-remove [backup-id] | module ntfy prepare|install|stop|remove|snapshot|restore|restore-remove [snapshot-id] | probe prepare|install|stop|remove <site> <local-sha256-image-id> | probe snapshot|restore <site> <local-sha256-image-id> <snapshot-id> | catalog validate|list|products | site validate <sites.json> <site> | plan render <sites.json> <site> | contract plan <site.json> <approved-hosts.json> <data-root> <backup-root> | lane plan <request.json> <trusted-issuer> <occupied-usernames.json> | stage offline <sites.json> <site> <temp-workspace> | stage restore <temp-workspace> <site>")
                return 2
            }
        }
    }
    0
} catch (e: Exception) {
    err("Rejected: ${e.message}")
    1
    }
}

/** A fixed read-only native observer. The parent release actor retains ordered lifecycle locks;
 * this subprocess must not reacquire them and deadlock its parent. Protected post-intent claim
 * and native pre/post CID checks bind this observation; it cannot submit or retry a callback.
 */
internal fun qualifiedOfficeCallbackReadback(generation: String, operationKey: String,
    environment: Map<String, String>): OfficeCallbackNativeReadback {
    val hash = Regex("[a-f0-9]{64}")
    require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
        operationKey.matches(Regex("office-callback-v2:[a-f0-9]{64}")))
    val claimSha = requireNotNull(environment["P0V3_NATIVE_CASE_CLAIM_SHA256"])
    require(hash.matches(claimSha))
    val caseRoot = Path.of(requireNotNull(environment["P0V3_CASE_ARTIFACT_DIR"]))
    ReleasePrivateFiles.directory(caseRoot)
    val intentBytes = ReleasePrivateFiles.read(caseRoot.resolve("intent.json"), 65536)
    val contextBytes = ReleasePrivateFiles.read(caseRoot.resolve("context.json"))
    val intent = releaseOutputJson.parseToJsonElement(intentBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    val context = releaseOutputJson.parseToJsonElement(contextBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    val invocation = intent.getValue("invocationId").jsonPrimitive.content
    require(invocation.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
        intent.getValue("serviceId").jsonPrimitive.content == "onlyoffice" &&
        intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
        intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
        intent.getValue("contextSha256").jsonPrimitive.content == ReleaseLocks.sha256(contextBytes))
    val binding = intent.getValue("binding").jsonObject
    require(binding.getValue("generationId").jsonPrimitive.content == generation &&
        binding.getValue("phase").jsonPrimitive.content in setOf("INSTALL", "RESTORE") &&
        context.getValue("targetGeneration").jsonPrimitive.content == generation && "caseClaimSha256" !in context)
    val root = GenerationRuntime.BASE.resolve(generation)
    val claimPath = root.resolve("native-qualification-claims/$invocation.json")
    val claimBytes = ReleasePrivateFiles.read(claimPath, 8192)
    require(ReleaseLocks.sha256(claimBytes) == claimSha)
    val claim = releaseOutputJson.parseToJsonElement(claimBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    require(claim.getValue("invocationId") == intent.getValue("invocationId") &&
        claim.getValue("generationId") == binding.getValue("generationId") &&
        claim.getValue("serviceId") == intent.getValue("serviceId") &&
        claim.getValue("phase") == binding.getValue("phase") &&
        claim.getValue("trialId") == binding.getValue("trialId") &&
        claim.getValue("candidate") == binding.getValue("candidate") &&
        claim.getValue("manifestSha256") == intent.getValue("manifestSha256") &&
        claim.getValue("caseIntentSha256").jsonPrimitive.content == ReleaseLocks.sha256(intentBytes) &&
        claim.getValue("contextSha256").jsonPrimitive.content == ReleaseLocks.sha256(contextBytes) &&
        claim.getValue("targetMemberName") == context.getValue("callbackDeploymentName") &&
        claim.getValue("targetFingerprint") == context.getValue("callbackRuntimeFingerprint")) {
        "Office observer requires independently bound protected case authority"
    }
    val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"))
    val bundle = releaseOutputJson.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
    val stage = releaseOutputJson.decodeFromString<GenerationOutcome>(
        ReleasePrivateFiles.read(root.resolve("stage.result.json")).decodeToString(throwOnInvalidSequence = true))
    require(bundle.request.id == generation && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
        stage.passed && stage.failureType == null && stage.action in setOf("stage", "restore-import") &&
        stage.bundleSha256 == ReleaseLocks.sha256(bundleBytes) &&
        bundle.members.map { it.member } == GenerationRuntime.validateScope(bundle.request))
    SiteOwnerships.checkSealed(bundle)
    val pin = bundle.members.single { it.member.name == context.getValue("callbackDeploymentName").jsonPrimitive.content }
    PrivateDeployment.validate(pin.spec)
    require(pin.spec.name == pin.member.name && pin.spec.store == bundle.request.store &&
        pin.runtimeFingerprint == context.getValue("callbackRuntimeFingerprint").jsonPrimitive.content &&
        PrivateDeployment.expectedFingerprint(pin.spec, pin.inputHashes) == pin.runtimeFingerprint &&
        pin.spec.processes.single { it.id == "seafile-backend" }.imageId == context.getValue("backendImageId").jsonPrimitive.content)
    val manifest = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve("${pin.member.name}.json"))
    require(ReleaseLocks.sha256(manifest) == pin.manifestSha256 &&
        releaseOutputJson.decodeFromString<PrivateDeploymentSpec>(manifest.decodeToString(throwOnInvalidSequence = true)) == pin.spec)
    pin.inputHashes.forEach { (file, expected) ->
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(pin.member.name).resolve(file))) == expected)
    }
    val observed = OfficeCallbackNativeCollector.collect(pin.spec, generation, pin.runtimeFingerprint, operationKey)
    require(ReleasePrivateFiles.read(claimPath, 8192).contentEquals(claimBytes) &&
        ReleasePrivateFiles.read(caseRoot.resolve("intent.json"), 65536).contentEquals(intentBytes) &&
        ReleasePrivateFiles.read(caseRoot.resolve("context.json")).contentEquals(contextBytes) &&
        ReleasePrivateFiles.read(root.resolve("bundle.json")).contentEquals(bundleBytes))
    val record = buildJsonObject {
        put("invocationId", invocation); put("generationId", generation); put("caseClaimSha256", claimSha)
        put("caseIntentSha256", ReleaseLocks.sha256(intentBytes)); put("contextSha256", ReleaseLocks.sha256(contextBytes))
        put("phase", binding.getValue("phase")); put("observation", releaseOutputJson.encodeToJsonElement(observed))
    }
    val bytes = releaseOutputJson.encodeToString(record).toByteArray()
    var directory = root
    for (name in listOf("office-callback-readbacks", invocation)) {
        val child = directory.resolve(name)
        if (!Files.exists(child, NOFOLLOW_LINKS)) {
            Files.createDirectory(child, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(directory)
        }
        ReleasePrivateFiles.directory(child); directory = child
    }
    val path = directory.resolve("${ReleaseLocks.sha256(bytes)}.json")
    if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).contentEquals(bytes))
    else ReleasePrivateFiles.save(path, bytes)
    return observed
}

/** Acquire the controller exclusion before directory creation, fetches, generation or state locks. */
private fun <T> rssStateMutation(root: Path, action: () -> T): T {
    require(root.isAbsolute && root.normalize() == root) { "Canonical absolute RSS state path required" }
    val operations = GenerationRssOperations()
    return operations.withExclusion {
        if (root.startsWith(GenerationRuntime.BASE)) {
            val generation = requireNotNull(root.parent?.parent)
            require(generation.parent == GenerationRuntime.BASE && root == generation.resolve("rss/state")) {
                "Unknown managed RSS state location"
            }
            operations.requireWritableGeneration(generation)
            val bundle = Json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(generation.resolve("bundle.json"))
                .decodeToString(throwOnInvalidSequence = true))
            require(bundle.request.id == generation.fileName.toString() && bundle.request.rssPlan != null &&
                bundle.recoverySourceArchiveSha256 == null && bundle.recoverySourceKopia == null && bundle.ownedUpdate == null) {
                "Recovered RSS state is inert; no fetch or checkpoint write authorized"
            }
            SiteOwnerships.checkSealed(bundle)
        }
        action()
    }
}
