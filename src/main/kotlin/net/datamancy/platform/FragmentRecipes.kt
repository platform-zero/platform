package net.datamancy.platform

import java.nio.file.Path

/** Fixed packaged selection. YAML owns topology; Kotlin owns this reviewed input producer and admission. */
internal object FragmentRecipes {
    const val FORGEJO_POSTGRES = "forgejo-pg-v2"
    fun fragments(forgejoRevision: Int = 4): List<PackagedGraphFragment> {
        require(forgejoRevision in setOf(4, 5))
        return listOf(PackagedGraphFragment.load("postgres-timescale", 1),
            if (forgejoRevision == 5) PackagedGraphFragment.loadFullForgejo()
            else PackagedGraphFragment.load("forgejo-postgres", 4))
    }
    val recipeIds = setOf(FORGEJO_POSTGRES)

    fun exportedProviderInput(spec: PrivateDeploymentSpec, file: String, owner: String): Boolean {
        val binding = spec.fragmentBinding ?: return false
        if (binding.recipe !in recipeIds || spec.executionBackend != RuntimeExecutionBackend.QUADLET_V2) return false
        val fragments = (4..5).map(::fragments).singleOrNull { source ->
            binding.resources == source.flatMap { it.resourceHashes.entries }
                .associate { "fragments/v2/${it.key}" to it.value }
        } ?: return false
        val provider = fragments.singleOrNull { it.definition.product == owner } ?: return false
        if (file !in provider.definition.exportedInputs) return false
        val owners = fragments.flatMap { f -> f.definition.processes.map { it.id to f.definition.product } }.toMap()
        if (spec.processes.none { !it.oneShot && owners[it.id] == owner }) return false
        val actual = spec.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }.map { it.id }.toSet()
        val declared = fragments.flatMap { it.definition.inputs }.filter { it.name == file && it.owner == owner }
            .flatMap { it.consumers }.toSet()
        return actual.isNotEmpty() && declared.containsAll(actual)
    }

    fun processOwners(recipe: String): Map<String, String> {
        require(recipe == FORGEJO_POSTGRES)
        return fragments().flatMap { f -> f.definition.processes.map { it.id to f.definition.product } }.toMap()
    }
    fun inputOwners(recipe: String): Map<String, String> {
        require(recipe == FORGEJO_POSTGRES)
        val inputs = fragments().flatMap { it.definition.inputs }
        require(inputs.groupBy { it.name }.values.all { group -> group.map { it.owner }.distinct().size == 1 })
        return inputs.associate { it.name to it.owner }
    }

    fun spec(inventory: AcquiredInventory, name: String, phase: FragmentPhase = FragmentPhase.INSTALL,
        controllerSha256: String? = null, controllerUid: Int? = null, controllerGid: Int? = null,
        forgejoRevision: Int = 4): PrivateDeploymentSpec {
        val fragments = fragments(forgejoRevision)
        val byProduct = fragments.associateBy { it.definition.product }
        require(byProduct.size == fragments.size)
        val projected = fragments.map { it.project(inventory, name, phase) }
        val processOwners = processOwners(FORGEJO_POSTGRES)
        val definitions = fragments.map { it.definition }
        definitions.forEach { f ->
            require(f.providers.all { it in byProduct }) { "Missing fragment provider" }
            f.inputs.filter { it.owner != f.product }.forEach { input ->
                require(input.owner in f.providers && input.name in byProduct.getValue(input.owner).definition.exportedInputs) {
                    "Provider did not export the requested input"
                }
            }
        }
        val processes = projected.flatMap { it.spec.processes }
        require(processes.map { it.id }.distinct().size == processes.size) { "Duplicate fragment process" }
        val attached = processes.map { p ->
            val networks = projected.flatMap { it.providerNetworks[p.id].orEmpty() }
            if (networks.isEmpty()) p else {
                require(processOwners[p.id] in byProduct && !p.oneShot) { "Provider attachment is not a daemon" }
                p.copy(networks = (p.networks + networks).distinct())
            }
        }
        val allInputs = fragments.flatMap { it.requiredInputs(phase) }
        require(allInputs.groupBy { it.name }.values.all { group ->
            group.map { it.owner to it.purpose }.distinct().size == 1
        }) { "Conflicting fragment input ownership or privilege" }
        val resources = linkedMapOf<String, String>()
        fragments.forEach { f -> f.resourceHashes.forEach { (path, hash) ->
            val previous = resources.putIfAbsent("fragments/v2/$path", hash)
            require(previous == null || previous == hash) { "Conflicting packaged resource hashes" }
        } }
        val spec = PrivateDeploymentSpec(name = name, volumes = projected.flatMap { it.spec.volumes },
            processes = attached, networks = projected.flatMap { it.spec.networks }.distinct(),
            databaseAccess = projected.flatMap { it.spec.databaseAccess }, store = RuntimeStore.CANONICAL_V2,
            unmountedRecoveryVolumes = projected.flatMap { it.spec.unmountedRecoveryVolumes }.toSet(),
            executionBackend = RuntimeExecutionBackend.QUADLET_V2,
            fragmentBinding = RuntimeFragmentBinding(FORGEJO_POSTGRES, phase.name, resources.toSortedMap(), controllerSha256, controllerUid, controllerGid))
        PrivateDeployment.validate(spec)
        require(PrivateDeployment.inputNames(spec).toSet() == allInputs.map { it.name }.toSet()) {
            "Combined fragment input closure mismatch"
        }
        allInputs.forEach { input ->
            val consumers = attached.filter { it.environmentFile == input.name || it.files.any { f -> f.file == input.name } }
            val declared = allInputs.filter { it.name == input.name }.flatMap { it.consumers }.filter { id -> attached.any { it.id == id } }.toSet()
            require(consumers.map { it.id }.toSet() == declared)
            require(input.purpose != FragmentInputPurpose.BOOTSTRAP || consumers.all { it.oneShot })
        }
        return spec
    }

    /** Validate all source/template/input contracts before entropy or openssl. No stateful work here. */
    fun inputs(spec: PrivateDeploymentSpec, inventory: AcquiredInventory,
        password: () -> String = RuntimePreparation::password,
        pki: () -> Map<String, String> = { PrivateWebPki.generate("postgres") }): Map<String, String> {
        val forgejoRevision = if (spec.fragmentBinding?.resources?.containsKey(
            "fragments/v2/canonical/r5/index.yaml") == true) 5 else 4
        require(spec == spec(inventory, spec.name, controllerSha256 = spec.fragmentBinding?.controllerSha256,
            controllerUid = spec.fragmentBinding?.controllerUid, controllerGid = spec.fragmentBinding?.controllerGid,
            forgejoRevision = forgejoRevision)) { "Fragment preparation definition changed" }
        val expected = setOf("postgres-bootstrap.env", "postgres.pem", "postgres-key.pem", "postgres-hba.conf",
            "postgres-ca.pem", "forgejo-db-admin.env", "forgejo-migration.env", "forgejo-migration.ini",
            "forgejo-runtime.env", "forgejo-runtime.ini")
        require(PrivateDeployment.inputNames(spec).toSet() == expected) { "Unimplemented fragment input producer" }
        val secrets = List(6) { password() }
        require(secrets.all { it.matches(Regex("[a-f0-9]{64}")) } && secrets.distinct().size == secrets.size)
        val (admin, migration, runtime) = secrets
        val tls = pki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem") && tls.values.all { it.isNotBlank() })
        val fragment = fragments(forgejoRevision).single { it.definition.product == "forgejo" }
        // Forgejo 17 uses base64.RawURLEncoding without padding and requires 32 bytes.
        // Hex64 and padded standard Base64 both tried to rewrite immutable app.ini in native pilots.
        val jwtSecret = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.util.HexFormat.of().parseHex(secrets[5]))
        val shared = mapOf("SECRET_KEY" to secrets[3], "INTERNAL_TOKEN" to secrets[4], "JWT_SECRET" to jwtSecret)
        fun databaseEnv(user: String, password: String) =
            "PGHOST=postgres\nPGPORT=5432\nPGDATABASE=forgejo\nPGUSER=$user\nPGPASSWORD=$password\n" +
                "PGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\n"
        return mapOf(
            "postgres-bootstrap.env" to "POSTGRES_PASSWORD=$admin\n",
            "postgres.pem" to tls.getValue("web.pem"), "postgres-key.pem" to tls.getValue("web-key.pem"),
            "postgres-ca.pem" to tls.getValue("ca.pem"),
            "postgres-hba.conf" to "local all postgres trust\nlocal all all reject\n" +
                "hostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\n" +
                "hostssl all postgres 0.0.0.0/0 scram-sha-256\nhostssl all postgres ::/0 scram-sha-256\n" +
                "hostssl forgejo forgejo,forgejo_migrate 0.0.0.0/0 scram-sha-256\n" +
                "hostssl forgejo forgejo,forgejo_migrate ::/0 scram-sha-256\n",
            "forgejo-db-admin.env" to databaseEnv("postgres", admin).replace("PGDATABASE=forgejo\n", "PGDATABASE=postgres\n") +
                "FORGEJO_MIGRATION_PASSWORD=$migration\nFORGEJO_RUNTIME_PASSWORD=$runtime\n",
            "forgejo-migration.env" to "HOME=/data\nUSER=git\n" + databaseEnv("forgejo_migrate", migration),
            "forgejo-runtime.env" to "HOME=/data\nUSER=git\n" + databaseEnv("forgejo", runtime),
            "forgejo-migration.ini" to FragmentTemplates.render(fragment, "forgejo-migration.ini", shared + ("DATABASE_PASSWORD" to migration)),
            "forgejo-runtime.ini" to FragmentTemplates.render(fragment, "forgejo-runtime.ini", shared + ("DATABASE_PASSWORD" to runtime))
        ).also { require(it.keys == expected) }
    }

    fun bindController(spec: PrivateDeploymentSpec, request: AssemblyRequest): PrivateDeploymentSpec {
        require(request.store == RuntimeStore.CANONICAL_V2)
        val controller = requireNotNull(request.quadletControllerSha256) { "Pinned Quadlet controller required" }
        require(controller.matches(Regex("[a-f0-9]{64}")))
        val identity = com.sun.security.auth.module.UnixSystem()
        require(identity.uid in 1..65534 && identity.gid in 1..65534) { "Non-root preparation identity required" }
        return spec.copy(fragmentBinding = requireNotNull(spec.fragmentBinding).copy(controllerSha256 = controller,
            controllerUid = identity.uid.toInt(), controllerGid = identity.gid.toInt()))
    }

    fun prepareBound(inventory: AcquiredInventory, base: Path, spec: PrivateDeploymentSpec): Path {
        require(spec.store == RuntimeStore.CANONICAL_V2 && spec.fragmentBinding?.controllerSha256 != null)
        require(spec == spec(inventory, spec.name, controllerSha256 = spec.fragmentBinding.controllerSha256,
            controllerUid = spec.fragmentBinding.controllerUid, controllerGid = spec.fragmentBinding.controllerGid)) {
            "Prepared fragment differs from compiled packaged definition"
        }
        return RuntimePreparation.prepare(spec, base) { inputs(spec, inventory) }
    }

    /** Original verified capture supplies the bytes. No entropy, initializer or implicit credential replacement. */
    fun coldInputs(inventory: AcquiredInventory, name: String, original: Map<String, String>): Map<String, String> {
        val fresh = spec(inventory, name)
        val cold = spec(inventory, name, FragmentPhase.RESTORE)
        require(original.keys in setOf(PrivateDeployment.inputNames(fresh).toSet(), PrivateDeployment.inputNames(cold).toSet()) &&
            original.values.all { it.toByteArray().size in 1..1048576 })
        return PrivateDeployment.inputNames(cold).associateWith { original.getValue(it) }
    }
}
