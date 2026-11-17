package net.datamancy.platform

import java.nio.file.Path

/** Native SQL-authenticated groupware; mail stays disabled unless a separate composite explicitly enables it. */
internal object SogoRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "sogo", mailEnabled: Boolean = false): PrivateDeploymentSpec {
        fun image(id: String) = inventory.images.single { it.product == id }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val pg = image("postgres"); val app = image("sogo"); val cache = image("memcached")
        fun files(vararg names: String) = names.map { RuntimeFile(it, "/run/secrets/$it") }
        val data = RuntimeMount("database", "/var/lib/postgresql/data")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("database", 999), RuntimeVolume("home", 994)), processes = listOf(
            RuntimeProcess("database-init", pg.pinnedImage, pg.imageId, 999, entrypoint = "/bin/sh", environmentFile = "bootstrap.env", oneShot = true,
                volumes = listOf(data), command = listOf("-ec", """
                    umask 077
                    printf '%s' "${'$'}PGPASSWORD" > /tmp/password
                    /usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/data --username=initializer --pwfile=/tmp/password --auth-host=scram-sha-256 --auth-local=trust
                    printf 'hostssl all all 0.0.0.0/0 scram-sha-256\nhostnossl all all 0.0.0.0/0 reject\n' >> /var/lib/postgresql/data/pg_hba.conf
                """.trimIndent()), apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("database", pg.pinnedImage, pg.imageId, 999, dependencies = listOf("database-init"), entrypoint = "/usr/lib/postgresql/17/bin/postgres",
                command = listOf("-D", "/var/lib/postgresql/data", "-c", "listen_addresses=*", "-c", "ssl=on", "-c", "ssl_cert_file=/run/secrets/db.pem", "-c", "ssl_key_file=/run/secrets/db-key.pem", "-c", "ssl_min_protocol_version=TLSv1.2"),
                volumes = listOf(data), files = files("db.pem", "db-key.pem"), tmpfs = listOf("/tmp", "/var/run/postgresql"),
                readiness = listOf("/usr/lib/postgresql/17/bin/pg_isready", "-U", "sogo", "-d", "sogo"), apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("accounts-init", pg.pinnedImage, pg.imageId, 999, dependencies = listOf("database"), entrypoint = "/usr/lib/postgresql/17/bin/psql",
                command = listOf("-X", "-v", "ON_ERROR_STOP=1", "-f", "/run/secrets/setup.sql"), environmentFile = "bootstrap.env",
                files = files("db-ca.pem", "setup.sql"), oneShot = true, apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("cache", cache.pinnedImage, cache.imageId, 11211, entrypoint = "/usr/local/bin/memcached",
                command = listOf("-m", "64", "-p", "11211", "-U", "0", "-c", "128"), memoryMiB = 128,
                readiness = listOf("/bin/sh", "-ec", "test -r /proc/1/status"), apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("sogod", app.pinnedImage, app.imageId, 994, dependencies = listOf("accounts-init", "cache"), entrypoint = "/bin/bash",
                command = listOf("-ec", ". /usr/share/GNUstep/Makefiles/GNUstep.sh; exec /usr/local/sbin/sogod -WONoDetach YES -WOLogFile - -WOPidFile /tmp/sogod.pid"),
                environmentFile = "sogo.env", volumes = listOf(RuntimeMount("home", "/home/sogo")),
                files = listOf(RuntimeFile("sogo.conf", "/etc/sogo/sogo.conf")) + files("db-ca.pem") +
                    if (mailEnabled) listOf(RuntimeFile("mail-ca.pem", "/etc/ssl/certs/ca-certificates.crt")) else emptyList(), memoryMiB = 1536,
                readiness = listOf("/usr/bin/curl", "--fail", "--silent", "--max-time", "3", "http://127.0.0.1:20000/SOGo/"), apparmorProfile = "p0v3-private-v1"),
            RuntimeProcess("groupware", app.pinnedImage, app.imageId, 994, dependencies = listOf("sogod"), entrypoint = "/usr/sbin/apache2",
                command = listOf("-f", "/run/secrets/apache.conf", "-DFOREGROUND"), environmentFile = "web.env", files = files("apache.conf", "web.pem", "web-key.pem", "ca.pem"),
                memoryMiB = 384, readiness = listOf("/usr/bin/curl", "--fail", "--silent", "--max-time", "3", "--cacert", "/run/secrets/ca.pem", "https://groupware:8443/SOGo/"), apparmorProfile = "p0v3-private-v1")
        )).also { PrivateDeployment.validate(it) }
    }
    /** One shared Postgres, Memcached and original mail provider; the V1 local SQL/cache
     * recipe above stays unchanged for historical source fingerprints. */
    fun canonicalFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec): CanonicalProviderFragment {
        require(base.store == RuntimeStore.CANONICAL_V2 &&
            base.processes.any { it.id == "postgres" && !it.oneShot } &&
            base.processes.any { it.id == "memcached" && !it.oneShot })
        val old = spec(inventory, base.name, mailEnabled = true)
        val pg = base.processes.single { it.id == "postgres" }
        val sql = RuntimeProcess("sogo-db-init", pg.image, pg.imageId, pg.userId,
            dependencies = listOf("postgres"), entrypoint = "/usr/lib/postgresql/17/bin/psql",
            command = listOf("-X", "-v", "ON_ERROR_STOP=1", "-f", "/run/secrets/sogo-setup.sql"),
            environmentFile = "sogo-db-admin.env", oneShot = true, networks = listOf("db-admin"),
            files = listOf(RuntimeFile("sogo-setup.sql", "/run/secrets/sogo-setup.sql"),
                RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            apparmorProfile = "p0v3-private-v1")
        val original = old.processes.associateBy { it.id }
        val daemon = original.getValue("sogod").copy(dependencies = listOf("sogo-db-init", "memcached", "mail"),
            networks = listOf("sogo-data", "sogo-cache", "sogo-web", "mail-data"),
            files = listOf(RuntimeFile("sogo.conf", "/etc/sogo/sogo.conf"),
                RuntimeFile("postgres-ca.pem", "/run/secrets/db-ca.pem"),
                RuntimeFile("mail-ca.pem", "/etc/ssl/certs/ca-certificates.crt")))
        val web = original.getValue("groupware").copy(networks = listOf("sogo-web"),
            environmentFile = "sogo-web.env",
            files = original.getValue("groupware").files.map { file -> when (file.file) {
                "ca.pem", "web.pem", "web-key.pem" -> file.copy(file = "sogo-${file.file}")
                "apache.conf" -> file.copy(file = "sogo-apache.conf")
                else -> file
            } })
        return CanonicalProviderFragment("sogo", PrivateDeploymentSpec(name = base.name, store = base.store,
            volumes = listOf(RuntimeVolume("home", 994)), processes = listOf(sql, daemon, web),
            networks = listOf("sogo-data", "sogo-cache", "sogo-web", "mail-data"),
            databaseAccess = listOf(RuntimeDatabaseAccess("sogod", "postgres", "postgres", "sogo",
                "sogo", "sogo.env", "sogo-data"))),
            webNetworks = setOf("sogo-web"), providerNetworks = mapOf(
                "postgres" to setOf("sogo-data"), "memcached" to setOf("sogo-cache")))
    }

    fun canonicalColdFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: CanonicalProviderFragment): CanonicalProviderFragment {
        val fresh = canonicalFragment(inventory, base)
        require(original == fresh) { "Foreign SOGo original calendar/mail/database source" }
        val cold = fresh.spec.copy(processes = fresh.spec.processes.filterNot { it.id == "sogo-db-init" }
            .map { if (it.id == "sogod") it.copy(dependencies = listOf("postgres", "memcached", "mail")) else it })
        require(cold.processes.none { it.oneShot } && cold.volumes == fresh.spec.volumes)
        return fresh.copy(spec = cold)
    }

    fun canonicalInputs(users: Map<String, String>, postgresAdmin: String,
        postgresTls: Map<String, String>,
        pki: (String) -> Map<String, String> = { host ->
            require(host == "groupware.datamancy.net")
            PrivateWebPki.generate("groupware", dnsNames = listOf("groupware", host)) }): Map<String, String> {
        require(postgresTls.keys == setOf("postgres-ca.pem", "postgres.pem", "postgres-key.pem") &&
            postgresTls.values.all { it.isNotBlank() } &&
            postgresAdmin.matches(Regex("[a-f0-9]{64}")) && users.keys == setOf("alice", "bob", "outsider") &&
            users.values.all { it.matches(Regex("[a-f0-9]{64}")) } && users.values.toSet().size == 3)
        // Backend Apache private SNI is a sealed prerequisite, not Caddy's public
        // ACME_PUBLIC original-host identity, which is adopted after target startup.
        val old = inputs(users, mailEnabled = true, pki = { host ->
            if (host == "database") mapOf("ca.pem" to postgresTls.getValue("postgres-ca.pem"),
                "web.pem" to postgresTls.getValue("postgres.pem"),
                "web-key.pem" to postgresTls.getValue("postgres-key.pem"))
            else pki("groupware.datamancy.net")
        })
        val admin = old.getValue("bootstrap.env")
        val password = Regex("(?m)^SOGO_PASSWORD=([a-f0-9]{64})$").find(admin)?.groupValues?.get(1)
        require(password != null)
        val config = old.getValue("sogo.conf")
            .replace("@database:5432", "@postgres:5432")
            .replace("SOGoMemcachedHost = \"cache:11211\"", "SOGoMemcachedHost = \"memcached:11211\"")
            .replace("\"127.0.0.1\", \"groupware\"", "\"127.0.0.1\", \"groupware.datamancy.net\"")
        val apache = old.getValue("apache.conf").replace("groupware:8443", "groupware.datamancy.net")
        require("@postgres:5432" in config && "cache:11211" !in config &&
            "groupware.datamancy.net" in config && "groupware.datamancy.net" in apache)
        return old.filterKeys { it in setOf("ca.pem", "web.pem", "web-key.pem", "web.env") }
            .mapKeys { (file, _) -> if (file in setOf("ca.pem", "web.pem", "web-key.pem", "web.env")) "sogo-$file" else file } + mapOf(
            "sogo.env" to old.getValue("sogo.env") + "SOGO_DB_PASSWORD=$password\n",
            "sogo.conf" to config, "sogo-apache.conf" to apache,
            "sogo-setup.sql" to old.getValue("setup.sql"),
            "sogo-db-admin.env" to "PGHOST=postgres\nPGDATABASE=postgres\nPGUSER=postgres\nPGPASSWORD=$postgresAdmin\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nSOGO_PASSWORD=$password\n" +
                users.entries.joinToString("") { "${it.key.uppercase()}_PASSWORD=${it.value}\n" })
    }

    fun inputs(users: Map<String, String> = listOf("alice", "bob", "outsider").associateWith { RuntimePreparation.password() },
        mailEnabled: Boolean = false,
        pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        require(users.keys == setOf("alice", "bob", "outsider") && users.values.toSet().size == 3 && users.values.all { it.matches(Regex("[a-f0-9]{64}")) })
        val web = pki("groupware"); val db = pki("database")
        val password = RuntimePreparation.password(); val initializer = RuntimePreparation.password()
        val domain = if (mailEnabled) "p0v3.example.org" else "localhost.invalid"
        return web + mapOf(
            "db.pem" to db.getValue("web.pem"), "db-key.pem" to db.getValue("web-key.pem"), "db-ca.pem" to db.getValue("ca.pem"),
            "bootstrap.env" to "PGHOST=database\nPGDATABASE=postgres\nPGUSER=initializer\nPGPASSWORD=$initializer\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/db-ca.pem\nSOGO_PASSWORD=$password\n" + users.entries.joinToString("") { "${it.key.uppercase()}_PASSWORD=${it.value}\n" },
            "sogo.env" to "HOME=/home/sogo\nUSER=sogo\nLOGNAME=sogo\nTZ=UTC\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/db-ca.pem\nLD_LIBRARY_PATH=/usr/local/lib/sogo:/usr/local/lib:/usr/lib\nLD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so.3\n",
            "web.env" to "HOME=/tmp\nTZ=UTC\n",
            "setup.sql" to """
                \getenv app_password SOGO_PASSWORD
                \getenv alice ALICE_PASSWORD
                \getenv bob BOB_PASSWORD
                \getenv outsider OUTSIDER_PASSWORD
                CREATE ROLE sogo LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_password';
                CREATE DATABASE sogo;
                REVOKE CONNECT ON DATABASE sogo FROM PUBLIC;
                GRANT CONNECT ON DATABASE sogo TO sogo;
                \connect sogo
                CREATE EXTENSION pgcrypto;
                GRANT USAGE, CREATE ON SCHEMA public TO sogo;
                CREATE TABLE users (c_uid varchar(64) PRIMARY KEY, c_name varchar(64) UNIQUE NOT NULL, c_password text NOT NULL, c_cn varchar(128) NOT NULL, mail varchar(128) NOT NULL);
                INSERT INTO users VALUES
                  ('alice','alice',crypt(:'alice',gen_salt('bf',12)),'Synthetic Alice','alice@$domain'),
                  ('bob','bob',crypt(:'bob',gen_salt('bf',12)),'Synthetic Bob','bob@$domain'),
                  ('outsider','outsider',crypt(:'outsider',gen_salt('bf',12)),'Synthetic Outsider','outsider@$domain');
                GRANT SELECT ON users TO sogo;
                ALTER ROLE initializer PASSWORD NULL NOLOGIN;
            """.trimIndent() + "\n",
            "sogo.conf" to """
                {
                  SOGoTimeZone = "UTC";
                  SOGoLanguage = "English";
                  SOGoMailDomain = "$domain";
                  SOGoMailSpoolPath = "/home/sogo/spool";
                  SOGoLoginModule = "Calendar";
                  SOGoSuperUsernames = ();
                  SOGoPasswordChangeEnabled = NO;
                  SOGoTrustProxyAuthentication = NO;
                  SOGoXSRFValidationEnabled = YES;
                  SOGoAppointmentSendEMailNotifications = NO;
                  SOGoFoldersSendEMailNotifications = NO;
                  SOGoACLsSendEMailNotifications = NO;
                  SOGoGravatarEnabled = NO;
                  SOGoMailingMechanism = "smtp";
                  SOGoSMTPServer = "${if (mailEnabled) "smtps://mail:2465/?tlsVerifyMode=default" else "smtp://127.0.0.1:9"}";
                  SOGoIMAPServer = "${if (mailEnabled) "imaps://mail:2993/?tlsVerifyMode=default" else "imap://127.0.0.1:9"}";
                  SOGoSMTPAuthenticationType = PLAIN;
                  SOGoForceExternalLoginWithEmail = YES;
                  SOGoMailAuxiliaryUserAccountsEnabled = NO;
                  SOGoSieveScriptsEnabled = NO;
                  SOGoVacationEnabled = NO;
                  SOGoForwardEnabled = NO;
                  SOGoMemcachedHost = "cache:11211";
                  SOGoProfileURL = "postgresql://sogo:$password@database:5432/sogo/sogo_user_profile";
                  OCSFolderInfoURL = "postgresql://sogo:$password@database:5432/sogo/sogo_folder_info";
                  OCSSessionsFolderURL = "postgresql://sogo:$password@database:5432/sogo/sogo_sessions_folder";
                  OCSAdminURL = "postgresql://sogo:$password@database:5432/sogo/sogo_admin";
                  SOGoUserSources = ({ type = sql; id = directory; displayName = "Synthetic directory"; viewURL = "postgresql://sogo:$password@database:5432/sogo/users"; canAuthenticate = YES; isAddressBook = YES; userPasswordAlgorithm = crypt; });
                  WOPort = "0.0.0.0:20000";
                  WOHttpAllowHost = ("127.0.0.1", "groupware");
                  WOWorkersCount = 1;
                  WOSessionTimeOut = 15;
                  SOGoMaximumPingInterval = 30;
                  SOGoMaximumSyncInterval = 30;
                  SOGoMaximumSyncResponseSize = 1024;
                }
            """.trimIndent() + "\n",
            "apache.conf" to """
                ServerRoot /etc/apache2
                DefaultRuntimeDir /tmp
                PidFile /tmp/apache.pid
                Listen 8443
                ServerName groupware:8443
                LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
                LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
                LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
                LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
                LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
                LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so
                LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so
                LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so
                LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
                LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so
                LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so
                LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so
                User sogo
                Group sogo
                ErrorLog /dev/stderr
                LogLevel warn
                TypesConfig /etc/mime.types
                TraceEnable Off
                ServerTokens Prod
                ServerSignature Off
                LimitRequestBody 1048576
                SSLSessionCache shmcb:/tmp/ssl-cache(512000)
                <VirtualHost *:8443>
                  SSLEngine On
                  SSLProtocol -all +TLSv1.2 +TLSv1.3
                  SSLCertificateFile /run/secrets/web.pem
                  SSLCertificateKeyFile /run/secrets/web-key.pem
                  SSLStrictSNIVHostCheck On
                  RewriteEngine On
                  RewriteCond %{HTTP_HOST} !^groupware:8443${'$'} [NC]
                  RewriteRule ^ - [R=421,L]
                  RewriteCond %{HTTP:Origin} !^${'$'}
                  RewriteCond %{HTTP:Origin} !^https://groupware:8443${'$'} [NC]
                  RewriteRule ^ - [F,L]
                  ${if (mailEnabled) "# Private authenticated mail is enabled in this separate composite only" else "RewriteRule ^/SOGo/so/[^/]+/Mail(?:/|${'$'}) - [R=503,L]"}
                  RedirectMatch ^/${'$'} /SOGo/
                  Header always set Referrer-Policy same-origin
                  Header always set X-Content-Type-Options nosniff
                  Header always edit Set-Cookie ^(.*)${'$'} "${'$'}1; Secure; SameSite=Lax"
                  ProxyRequests Off
                  ProxyPreserveHost On
                  ProxyPass /SOGo.woa/WebServerResources/ !
                  ProxyPass /SOGo/WebServerResources/ !
                  Alias /SOGo.woa/WebServerResources/ /usr/lib/GNUstep/SOGo/WebServerResources/
                  Alias /SOGo/WebServerResources/ /usr/lib/GNUstep/SOGo/WebServerResources/
                  <Directory /usr/lib/GNUstep/SOGo/WebServerResources>
                    Options None
                    AllowOverride None
                    Require all granted
                  </Directory>
                  RequestHeader unset x-webobjects-remote-user
                  RequestHeader set x-webobjects-server-port 8443
                  RequestHeader set x-webobjects-server-name groupware
                  RequestHeader set x-webobjects-server-url https://groupware:8443
                  RequestHeader set x-webobjects-server-protocol HTTP/1.0
                  ProxyPass /SOGo http://sogod:20000/SOGo retry=0 connectiontimeout=5 timeout=60
                  ProxyPassReverse /SOGo http://sogod:20000/SOGo
                </VirtualHost>
            """.trimIndent() + "\n"
        )
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "sogo", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
