package net.datamancy.platform

import java.nio.file.Path
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlinx.serialization.json.*

internal data class FreshPlankaActorGrant(val generation: String, val ownerPassword: String,
    val outsiderPassword: String) {
    init {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            ownerPassword.matches(Regex("[a-f0-9]{64}")) && outsiderPassword.matches(Regex("[a-f0-9]{64}")) &&
            ownerPassword != outsiderPassword)
    }
}

/** Private Planka with its own database/role, durable one-time migrations, and local upload storage. */
internal object PlankaRuntime {
    const val FIXTURE_TERMS = "# Private automated test instance\n\nSynthetic test accounts and fixture data only. No public service or human end-user agreement is offered here. This notice does not replace upstream software licenses.\n"

    /** v2.2.1 supports POST /api/access-tokens, admin-only POST /api/users and
     * authenticated GET /api/users/:id. Core binds these exact original credentials
     * once to the r2 INSTALL-only process and retains the sealed pair on RESTORE.
     * Bootstrap is minted by db/init.js FIRST and cannot be guessed or aliased.
     */
    fun freshActorEnrollmentInputs(grant: FreshPlankaActorGrant, bootstrapPassword: String): Map<String, String> {
        require(bootstrapPassword.matches(Regex("[a-f0-9]{64}")) &&
            bootstrapPassword !in setOf(grant.ownerPassword, grant.outsiderPassword))
        val termsSha = java.security.MessageDigest.getInstance("SHA-256")
            .digest(FIXTURE_TERMS.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val env = "PLANKA_ENROLL_GENERATION=${grant.generation}\n" +
            "PLANKA_TERMS_SHA256=$termsSha\n" +
            "PLANKA_BOOTSTRAP_PASSWORD=$bootstrapPassword\n" +
            "PLANKA_OWNER_PASSWORD=${grant.ownerPassword}\n" +
            "PLANKA_OUTSIDER_PASSWORD=${grant.outsiderPassword}\n"
        return mapOf("planka-enrollment.env" to env, "planka-enroll.js" to enrollmentSource())
    }

    /** Only the r2 INSTALL one-shot runs this, in the isolated planka-web network.
     * The original upload volume stores the attempted marker and final source receipt;
     * a lost ACK or partial two-user registration permanently fences this generation.
     * No credentials, tokens or passwords are serialized to stdout, journal or artifacts.
     */
    fun enrollmentSource(): String = """
        'use strict';
        const fs = require('node:fs');
        const path = require('node:path');
        const http = require('node:http');
        const crypto = require('node:crypto');
        const fail = () => { throw new Error('Original Planka enrollment uncertain; never replay'); };
        const hash = value => crypto.createHash('sha256').update(value).digest('hex');
        const generation = process.env.PLANKA_ENROLL_GENERATION;
        const bootstrap = process.env.PLANKA_BOOTSTRAP_PASSWORD;
        const termsSha = process.env.PLANKA_TERMS_SHA256;
        const owner = process.env.PLANKA_OWNER_PASSWORD;
        const outsider = process.env.PLANKA_OUTSIDER_PASSWORD;
        if (!/^q-[a-f0-9]{12}${'$'}/.test(generation) || !/^[a-f0-9]{64}${'$'}/.test(termsSha) ||
            ![bootstrap, owner, outsider].every(value => /^[a-f0-9]{64}${'$'}/.test(value)) ||
            new Set([bootstrap, owner, outsider]).size !== 3) fail();
        const directory = '/app/data/actor-enrollment';
        // mkdir is exclusive: even a completed previous attempt cannot be reissued.
        fs.mkdirSync(directory, { mode: 0o700 });
        const volume = fs.openSync('/app/data', 'r');
        try { fs.fsyncSync(volume); } finally { fs.closeSync(volume); }
        // The effect fence is durable BEFORE bootstrap login or either user POST.
        const record = (file, value) => {
          const fd = fs.openSync(path.join(directory, file), 'wx', 0o600);
          try { fs.writeSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); }
          finally { fs.closeSync(fd); }
          const dir = fs.openSync(directory, 'r');
          try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
        };
        record('attempted.json', { generation, bootstrapSha256: hash(bootstrap),
          ownerSha256: hash(owner), outsiderSha256: hash(outsider),
          owner: 'p0v3_owner', outsider: 'p0v3_outsider', schemaVersion: 1 });
        const request = (method, endpoint, token, body) => new Promise((resolve, reject) => {
          if (!['GET', 'POST'].includes(method) || !['/api/access-tokens',
              '/api/access-tokens/accept-terms', '/api/terms', '/api/users',
              '/api/users/me'].includes(endpoint) && !/^\/api\/users\/[0-9]+${'$'}/.test(endpoint)) fail();
          const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
          const req = http.request({ hostname: 'planka', port: 1337, method, path: endpoint,
            timeout: 10000, headers: { Host: 'planka', Accept: 'application/json',
              'User-Agent': 'p0v3-original-planka-enrollment',
              ...(token ? { Authorization: 'Bearer ' + token } : {}),
              ...(bytes ? { 'Content-Type': 'application/json', 'Content-Length': bytes.length } : {}) } }, res => {
            const chunks = []; let size = 0;
            res.on('data', part => { size += part.length; if (size > 65536) req.destroy(); else chunks.push(part); });
            res.on('end', () => {
              if (size > 65536) { reject(new Error('Unbounded Planka response')); return; }
              try { resolve({ status: res.statusCode, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
              catch (_) { reject(new Error('Invalid Planka response')); }
            });
          });
          req.on('timeout', () => req.destroy()); req.on('error', reject);
          req.end(bytes || undefined);
        });
        const requireStatus = (result, code) => { if (result.status !== code) fail(); return result.value; };
        const login = async (username, password, role, signature) => {
          const attempt = await request('POST', '/api/access-tokens', null,
            { emailOrUsername: username, password });
          // v2.2.1 first login requires the real issuer's pending token and terms
          // signature. Neither a guessed token nor silent acceptance is allowed.
          if (attempt.status !== 403 || attempt.value.code !== 'E_FORBIDDEN' ||
              attempt.value.step !== 'accept-terms' ||
              typeof attempt.value.pendingToken !== 'string' ||
              !/^[A-Za-z0-9._~-]{40,1024}${'$'}/.test(attempt.value.pendingToken)) fail();
          record(role + '-terms.intent.json', { generation, signature,
            pendingTokenSha256: hash(attempt.value.pendingToken) });
          const reply = requireStatus(await request('POST', '/api/access-tokens/accept-terms', null,
            { pendingToken: attempt.value.pendingToken, signature, initialLanguage: 'en-US' }), 200);
          if (typeof reply.item !== 'string' || !/^[A-Za-z0-9._~-]{40,8192}${'$'}/.test(reply.item)) fail();
          record(role + '-terms.result.json', { generation, signature, accepted: true });
          return reply.item;
        }; 
        const identity = (value, username, role) => {
          if (!value || typeof value.id !== 'string' || !/^[0-9]+${'$'}/.test(value.id) ||
              value.username !== username || value.role !== role) fail();
          return value.id;
        };
        (async () => {
          const terms = requireStatus(await request('GET', '/api/terms', null, null), 200).item;
          if (!terms || terms.language !== 'en-US' || typeof terms.content !== 'string' ||
              hash(terms.content) !== termsSha || terms.signature !== termsSha) fail();
          const admin = await login('p0v3_bootstrap', bootstrap, 'bootstrap', terms.signature);
          const boot = requireStatus(await request('GET', '/api/users/me', admin, null), 200);
          const bootstrapId = identity(boot.item, 'p0v3_bootstrap', 'admin');
          const ownerCreated = requireStatus(await request('POST', '/api/users', admin, {
            username: 'p0v3_owner', email: 'p0v3-owner@p0v3.example.org',
            password: owner, role: 'admin', name: 'Original Planka Owner' }), 200);
          const ownerId = identity(ownerCreated.item, 'p0v3_owner', 'admin');
          record('owner-created.json', { ownerId, ownerSha256: hash(owner), generation });
          const outsiderCreated = requireStatus(await request('POST', '/api/users', admin, {
            username: 'p0v3_outsider', email: 'p0v3-outsider@p0v3.example.org',
            password: outsider, role: 'boardUser', name: 'Original Planka Outsider' }), 200);
          const outsiderId = identity(outsiderCreated.item, 'p0v3_outsider', 'boardUser');
          record('outsider-created.json', { outsiderId, outsiderSha256: hash(outsider), generation });
          if (new Set([bootstrapId, ownerId, outsiderId]).size !== 3) fail();
          const ownerToken = await login('p0v3_owner', owner, 'owner', terms.signature);
          const outsiderToken = await login('p0v3_outsider', outsider, 'outsider', terms.signature);
          identity(requireStatus(await request('GET', '/api/users/me', ownerToken, null), 200).item,
            'p0v3_owner', 'admin');
          identity(requireStatus(await request('GET', '/api/users/me', outsiderToken, null), 200).item,
            'p0v3_outsider', 'boardUser');
          identity(requireStatus(await request('GET', '/api/users/' + ownerId, admin, null), 200).item,
            'p0v3_owner', 'admin');
          identity(requireStatus(await request('GET', '/api/users/' + outsiderId, admin, null), 200).item,
            'p0v3_outsider', 'boardUser');
          if ((await request('GET', '/api/users', outsiderToken, null)).status !== 403) fail();
          record('completed.json', { schemaVersion: 1, generation, bootstrapId, ownerId, outsiderId,
            bootstrapSha256: hash(bootstrap), ownerSha256: hash(owner), outsiderSha256: hash(outsider),
            ownerRole: 'admin', outsiderRole: 'boardUser', outsiderUsersStatus: 403 });
        })().catch(() => { console.error('Original Planka enrollment uncertain; no retry'); process.exitCode = 1; });
    """.trimIndent() + "\n"

    /** Separate post-one-shot HTTPS issuer readback for core's live source/capture and
     * isolated RESTORE. Caller supplies current selected CA/leaf-pinned clients, retained
     * original two passwords/IDs and never the initializer's bootstrap credential.
     */
    fun nativeActorReadback(ownerClient: HttpClient, outsiderClient: HttpClient, selectedOrigin: URI,
        ownerPassword: String, outsiderPassword: String, originalOwnerId: String,
        originalOutsiderId: String): Map<String, String> {
        require(selectedOrigin.toASCIIString() == "https://planka.datamancy.net" &&
            ownerClient !== outsiderClient &&
            listOf(ownerClient, outsiderClient).all { it.followRedirects() == HttpClient.Redirect.NEVER } &&
            listOf(ownerPassword, outsiderPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            ownerPassword != outsiderPassword &&
            listOf(originalOwnerId, originalOutsiderId).all { it.matches(Regex("[0-9]{1,20}")) } &&
            originalOwnerId != originalOutsiderId)
        fun send(client: HttpClient, method: String, path: String, body: String?, bearer: String?): HttpResponse<String> {
            val req = HttpRequest.newBuilder(URI.create(selectedOrigin.toASCIIString() + path))
                .timeout(Duration.ofSeconds(12)).header("Accept", "application/json")
            if (bearer != null) req.header("Authorization", "Bearer $bearer")
            if (body != null) req.header("Content-Type", "application/json")
            val response = client.send(req.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
                else HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
            require(response.body().length <= 65536 && response.statusCode() !in 300..399)
            return response
        }
        fun login(client: HttpClient, username: String, password: String): String {
            val body = buildJsonObject { put("emailOrUsername", username); put("password", password) }.toString()
            val response = send(client, "POST", "/api/access-tokens", body, null)
            require(response.statusCode() == 200)
            val value = Json.parseToJsonElement(response.body()).jsonObject.getValue("item").jsonPrimitive.content
            require(value.matches(Regex("[A-Za-z0-9._~-]{40,8192}")))
            return value
        }
        val owner = login(ownerClient, "p0v3_owner", ownerPassword)
        val outsider = login(outsiderClient, "p0v3_outsider", outsiderPassword)
        require(owner != outsider)
        fun account(client: HttpClient, bearer: String, path: String, username: String, role: String, id: String) {
            val response = send(client, "GET", path, null, bearer)
            require(response.statusCode() == 200)
            val item = Json.parseToJsonElement(response.body()).jsonObject.getValue("item").jsonObject
            require(item.getValue("id").jsonPrimitive.content == id &&
                item.getValue("username").jsonPrimitive.content == username &&
                item.getValue("role").jsonPrimitive.content == role)
        }
        account(ownerClient, owner, "/api/users/me", "p0v3_owner", "admin", originalOwnerId)
        account(outsiderClient, outsider, "/api/users/me", "p0v3_outsider", "boardUser", originalOutsiderId)
        account(ownerClient, owner, "/api/users/$originalOutsiderId", "p0v3_outsider", "boardUser", originalOutsiderId)
        require(send(outsiderClient, "GET", "/api/users", null, outsider).statusCode() == 403 &&
            send(outsiderClient, "GET", "/api/users/$originalOwnerId", null, outsider).statusCode() == 404)
        return mapOf("ownerId" to originalOwnerId, "outsiderId" to originalOutsiderId,
            "ownerRole" to "admin", "outsiderRole" to "boardUser")
    }
    fun spec(inventory: AcquiredInventory, name: String = "planka"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        val image = inventory.images.single { it.product == "planka" }
        require(image.os == "linux" && image.architecture == "amd64")
        val app = RuntimeProcess("planka", image.pinnedImage, image.imageId, 1000, entrypoint = "/usr/local/bin/node",
            environmentFile = "planka.env", volumes = listOf(RuntimeMount("uploads", "/app/data")),
            files = listOf(RuntimeFile("fixture-terms.md", "/app/terms/custom/en-US.md")),
            tmpfs = listOf("/tmp", "/app/.tmp"), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1",
            readinessHttpPort = 1337)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("postgres", 999), RuntimeVolume("uploads", 1000)),
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("planka-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true, apparmorProfile = "p0v3-private-v1",
                    command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE planka LOGIN PASSWORD '${'$'}PLANKA_PASSWORD';
                        CREATE DATABASE planka OWNER planka;
                        SQL
                    """.trimIndent())),
                app.copy(id = "planka-init", dependencies = listOf("planka-db-init"), command = listOf("db/init.js"),
                    oneShot = true, readinessHttpPort = null),
                app.copy(dependencies = listOf("planka-init"), command = listOf("app.js", "--prod"))
            )).also { PrivateDeployment.validate(it) }
    }
    /** Cold restoration never runs database creation, Knex migrations or administrator seeding. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        PrivateDeployment.validate(compiled)
        val initializers = setOf("postgres-init", "planka-db-init", "planka-init")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == initializers &&
            compiled.processes.map { it.id }.toSet() == initializers + setOf("postgres", "planka")) {
            "Exact standalone Planka recipe required; canonical provider restoration has its own projection"
        }
        val application = compiled.processes.single { it.id == "planka" }
        require(application.entrypoint == "/usr/local/bin/node" && application.command == listOf("app.js", "--prod") &&
            application.environmentFile == "planka.env") { "Application entrypoint may not bootstrap or migrate on restore" }
        return compiled.copy(processes = compiled.processes.filterNot { it.oneShot }.map {
            // The application still depends on the provider even though the init chain is retired.
            // DEFAULT_ADMIN_* in historical planka.env are inactive under app.js --prod; only
            // db/init.js runs seeding, and that process is absent from the restored definition.
            it.copy(dependencies = if (it.id == "planka") listOf("postgres") else it.dependencies.filterNot(initializers::contains))
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in initializers || it.provider in initializers })
            .also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "planka", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            val postgres = RuntimePreparation.password()
            val database = RuntimePreparation.password()
            mapOf("fixture-terms.md" to FIXTURE_TERMS, "postgres.env" to "POSTGRES_PASSWORD=$postgres\n",
                "database-init.env" to "POSTGRES_PASSWORD=$postgres\nPLANKA_PASSWORD=$database\n",
                "planka.env" to "NODE_ENV=production\nLOG_FILE=/tmp/planka.log\nBASE_URL=http://planka:1337\nDATABASE_URL=postgresql://planka:$database@postgres:5432/planka\nSECRET_KEY=${RuntimePreparation.password()}\nDEFAULT_ADMIN_EMAIL=bootstrap@localhost.invalid\nDEFAULT_ADMIN_USERNAME=p0v3_bootstrap\nDEFAULT_ADMIN_NAME=Private bootstrap\nDEFAULT_ADMIN_PASSWORD=${RuntimePreparation.password()}\nOUTGOING_PROXY=http://127.0.0.1:9\n")
        }
}
