package net.datamancy.platform

import java.nio.file.Path

/** Native offline full-text search fixture. No public engines, autocomplete or existing user documents. */
internal object SearxngRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "searxng"): PrivateDeploymentSpec {
        fun image(id: String) = inventory.images.single { it.product == id }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val app = image("searxng"); val web = image("element")
        val seed = RuntimeProcess("corpus-init", app.pinnedImage, app.imageId, 977,
            entrypoint = "/bin/sh", command = listOf("-ec", "exec /usr/local/searxng/.venv/bin/python /run/secrets/seed.py"),
            files = listOf(RuntimeFile("seed.py", "/run/secrets/seed.py")),
            volumes = listOf(RuntimeMount("corpus", "/corpus")), oneShot = true, apparmorProfile = "p0v3-private-v1")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("corpus", 977)), processes = listOf(
            seed,
            RuntimeProcess("searxng", app.pinnedImage, app.imageId, 977, dependencies = listOf("corpus-init"),
                entrypoint = "/bin/sh", command = listOf("-ec", "exec /usr/local/searxng/.venv/bin/granian searx.webapp:app"),
                environmentFile = "searxng.env", files = listOf(RuntimeFile("settings.yml", "/run/secrets/settings.yml")),
                volumes = seed.volumes, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz"),
            RuntimeProcess("search", web.pinnedImage, web.imageId, 101, dependencies = listOf("searxng"),
                entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "web.pem", "web-key.pem", "ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    /** Exact private corpus fixture, original settings secret and native TLS frontend. */
    fun canonicalFragment(inventory: AcquiredInventory, name: String): CanonicalProviderFragment {
        val original = spec(inventory, name)
        val fragment = original.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("search-data", "search-web"), processes = original.processes.map { process ->
                process.copy(id = if (process.oneShot) "searxng-corpus-init" else if (process.id == "search")
                        "searxng-web" else process.id,
                    dependencies = process.dependencies.map {
                        when (it) { "corpus-init" -> "searxng-corpus-init"; "search" -> "searxng-web"; else -> it }
                    }, environmentFile = process.environmentFile?.let { "searxng-$it" },
                    files = process.files.map { it.copy(file = "searxng-${it.file}") },
                    networks = if (process.id == "search") listOf("search-data", "search-web") else listOf("search-data"))
            })
        PrivateDeployment.validate(fragment)
        return CanonicalProviderFragment("searxng", fragment, webNetworks = setOf("search-web"))
    }
    fun canonicalInputs(pki: () -> Map<String, String> = {
        PrivateWebPki.generate("search", dnsNames = listOf("search", "search.datamancy.net"))
    }): Map<String, String> = inputs(pki).mapKeys { (key, _) -> "searxng-$key" }
        .mapValues { (key, value) -> when (key) {
            "searxng-settings.yml" -> {
                require("base_url: https://search:8443/" in value)
                value.replace("base_url: https://search:8443/", "base_url: https://search.datamancy.net/")
            }
            "searxng-nginx.conf" -> {
                require("server_name search;" in value)
                value.replace("server_name search;", "server_name search search.datamancy.net;")
            }
            else -> value
        } }
    fun coldRestoreFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "searxng" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.map { it.id }.toSet() == setOf("searxng-corpus-init", "searxng", "searxng-web") &&
            fresh.spec.volumes.map { it.id } == listOf("corpus"))
        val server = fresh.spec.processes.single { it.id == "searxng" }
        val web = fresh.spec.processes.single { it.id == "searxng-web" }
        require(server.dependencies == listOf("searxng-corpus-init") && web.dependencies == listOf("searxng") &&
            server.volumes == listOf(RuntimeMount("corpus", "/corpus")))
        val projected = fresh.spec.copy(processes = listOf(server.copy(dependencies = emptyList()), web))
        PrivateDeployment.validate(projected)
        return fresh.copy(spec = projected)
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "searxng", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("search") }): Map<String, String> = pki() + mapOf(
        "searxng.env" to "SEARXNG_SETTINGS_PATH=/run/secrets/settings.yml\n__SEARXNG_SETTINGS_PATH=/run/secrets/settings.yml\nSEARXNG_DATA_PATH=/tmp\nGRANIAN_INTERFACE=wsgi\nGRANIAN_HOST=0.0.0.0\nGRANIAN_PORT=8080\nGRANIAN_WORKERS=1\nPYTHONDONTWRITEBYTECODE=1\n",
        "settings.yml" to """
            use_default_settings:
              engines:
                keep_only: []
            general:
              debug: false
              instance_name: Platform Zero private search fixture
            search:
              autocomplete: ''
              formats: [html, json]
              default_lang: en
            server:
              secret_key: '${RuntimePreparation.password()}'
              base_url: https://search:8443/
              method: POST
              limiter: false
              image_proxy: false
              public_instance: false
            ui:
              static_use_hash: true
            outgoing:
              request_timeout: 3.0
            engines:
              - name: private corpus
                engine: sqlite
                shortcut: corpus
                categories: [general]
                database: /corpus/documents.db
                result_type: MainResult
                query_str: 'SELECT title, url, content FROM documents WHERE documents MATCH :query ORDER BY rank'
        """.trimIndent() + "\n",
        "seed.py" to """
            import os, sqlite3
            from pathlib import Path
            if not __debug__:
                raise SystemExit('Optimized Python refused')
            root = Path('/corpus')
            target = root / 'documents.db'
            pending = root / 'documents.pending'
            if target.exists() or pending.exists():
                raise SystemExit('Existing corpus or interrupted initialization retained')
            os.umask(0o077)
            db = sqlite3.connect(pending)
            db.execute('CREATE VIRTUAL TABLE documents USING fts5(title, url UNINDEXED, content)')
            rows = [
                ('Otter habitat', 'https://example.invalid/fixture/otter', 'Synthetic river otter conservation and wetland habitat'),
                ('Otter astronomy', 'https://example.invalid/fixture/stars', 'Synthetic otter constellation observation'),
                ('Alpine botany', 'https://example.invalid/fixture/alpine', 'Synthetic alpine flower survey'),
            ] + [('Quasar note %02d' % i, 'https://example.invalid/fixture/quasar-%02d' % i, 'Synthetic quasar spectrum number %d' % i) for i in range(12)]
            db.executemany('INSERT INTO documents(title,url,content) VALUES(?,?,?)', rows)
            db.commit()
            if db.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise SystemExit('Corpus integrity check failed')
            db.close()
            with pending.open('rb') as stream:
                os.fsync(stream.fileno())
            os.rename(pending, target)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        """.trimIndent() + "\n",
        "nginx.conf" to """
            worker_processes 1;
            pid /tmp/nginx.pid;
            error_log /tmp/nginx-error.log warn;
            events { worker_connections 512; }
            http {
                access_log off;
                client_body_temp_path /tmp/body;
                proxy_temp_path /tmp/proxy;
                fastcgi_temp_path /tmp/fastcgi;
                uwsgi_temp_path /tmp/uwsgi;
                scgi_temp_path /tmp/scgi;
                server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                server {
                    listen 8443 ssl;
                    server_name search;
                    ssl_certificate /run/secrets/web.pem;
                    ssl_certificate_key /run/secrets/web-key.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    client_max_body_size 64k;
                    location / {
                        proxy_pass http://searxng:8080;
                        proxy_set_header Host ${'$'}http_host;
                        proxy_set_header X-Forwarded-Proto https;
                        proxy_set_header X-Forwarded-For ${'$'}remote_addr;
                    }
                }
            }
        """.trimIndent() + "\n"
    )
}
