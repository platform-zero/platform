package net.datamancy.platform

internal data class FreshBookstackOutsiderGrant(val subjectUuid: String, val tokenId: String, val tokenSecret: String) {
    init {
        require(runCatching { java.util.UUID.fromString(subjectUuid).toString() == subjectUuid }.getOrDefault(false) &&
            tokenId.matches(Regex("p0v3-[a-f0-9]{32}")) && tokenSecret.matches(Regex("[a-f0-9]{64}")))
    }
}

/** Fresh-only BookStack API enrollment in the selected migration one-shot.
 * This is an attempted native effect: an intent survives any lost ACK and must
 * never be retried as a second token issuance. OLD token/account state is not read.
 */
internal object FreshBookstackApiSource {
    /** Read-only native Laravel probe, to be run by core only after the original INSTALL
     * journey. Its environment must come from the original sealed owner/outsider and API
     * grants, not from a regenerated fragment. No grant, password or token hash is output.
     * A receipt or a successful HTTP health check is not a substitute for this query.
     */
    fun nativeIssuanceReadbackSource(): String {
        val d = '$'
        return """
            <?php
            declare(strict_types=1);
            error_reporting(0); ini_set('display_errors', '0'); umask(0077); ob_start();
            try {
                require '/app/www/vendor/autoload.php';
                ${d}app = require '/app/www/bootstrap/app.php';
                ${d}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${d}db = Illuminate\Support\Facades\DB::class;
                ${d}hash = Illuminate\Support\Facades\Hash::class;
                ${d}ownerSub = getenv('P0V3_OWNER_SUB');
                ${d}outsiderSub = getenv('P0V3_BOOKSTACK_OUTSIDER_SUB');
                ${d}ownerPassword = getenv('P0V3_OWNER_PASSWORD');
                ${d}ownerId = getenv('P0V3_BOOKSTACK_API_ID');
                ${d}ownerSecret = getenv('P0V3_BOOKSTACK_API_SECRET');
                ${d}outsiderId = getenv('P0V3_BOOKSTACK_OUTSIDER_API_ID');
                ${d}outsiderSecret = getenv('P0V3_BOOKSTACK_OUTSIDER_API_SECRET');
                if (!preg_match('/^[a-f0-9-]{36}${d}/D', ${d}ownerSub) ||
                    !preg_match('/^[a-f0-9-]{36}${d}/D', ${d}outsiderSub) || ${d}ownerSub === ${d}outsiderSub ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}ownerPassword) ||
                    !preg_match('/^p0v3-[a-f0-9]{32}${d}/D', ${d}ownerId) ||
                    !preg_match('/^p0v3-[a-f0-9]{32}${d}/D', ${d}outsiderId) || ${d}ownerId === ${d}outsiderId ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}ownerSecret) ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}outsiderSecret) || ${d}ownerSecret === ${d}outsiderSecret)
                    throw new RuntimeException('Foreign original actor grant');
                ${d}owner = ${d}db::table('users')->where('external_auth_id', ${d}ownerSub)->sole();
                ${d}outsider = ${d}db::table('users')->where('external_auth_id', ${d}outsiderSub)->sole();
                if (${d}owner->id === ${d}outsider->id ||
                    ${d}owner->email !== 'owner@localhost.invalid' ||
                    ${d}outsider->email !== 'outsider@localhost.invalid' ||
                    !${d}hash::check(${d}ownerPassword, ${d}owner->password))
                    throw new RuntimeException('Original native actors missing');
                ${d}tokens = ${d}db::table('api_tokens')->whereIn('token_id', [${d}ownerId, ${d}outsiderId])->get();
                if (${d}tokens->count() !== 2) throw new RuntimeException('Original native API grants missing');
                ${d}automated = ${d}tokens->firstWhere('token_id', ${d}ownerId);
                ${d}restricted = ${d}tokens->firstWhere('token_id', ${d}outsiderId);
                ${d}automation = ${d}db::table('users')->where('id', ${d}automated->user_id)->sole();
                if (${d}automation->email !== 'p0v3-automation@localhost.invalid' ||
                    ${d}restricted->user_id !== ${d}outsider->id ||
                    !${d}hash::check(${d}ownerSecret, ${d}automated->secret) ||
                    !${d}hash::check(${d}outsiderSecret, ${d}restricted->secret) ||
                    strtotime(${d}automated->expires_at) <= time() ||
                    strtotime(${d}restricted->expires_at) <= time())
                    throw new RuntimeException('Native token credential invalid');
                ${d}permissions = function (int ${d}userId) use (${d}db): array {
                    return ${d}db::table('role_user')->join('permission_role', 'role_user.role_id', '=', 'permission_role.role_id')
                        ->join('role_permissions', 'role_permissions.id', '=', 'permission_role.permission_id')
                        ->where('role_user.user_id', ${d}userId)->pluck('role_permissions.name')->unique()->sort()->values()->all();
                };
                ${d}ownerRequired = ['access-api', 'attachment-create-all', 'book-create-all', 'page-update-all'];
                if (array_diff(${d}ownerRequired, ${d}permissions(${d}automation->id)) ||
                    ${d}permissions(${d}outsider->id) !== ['access-api', 'book-view-own', 'chapter-view-own', 'page-view-own'])
                    throw new RuntimeException('Native API role scope changed');
                while (ob_get_level()) ob_end_clean();
                echo json_encode(['owner' => 'owner', 'outsider' => 'outsider',
                    'ownerNativeId' => ${d}owner->id, 'outsiderNativeId' => ${d}outsider->id,
                    'ownerNativeEmail' => ${d}owner->email, 'outsiderNativeEmail' => ${d}outsider->email,
                    'ownerSubjectUuid' => ${d}owner->external_auth_id,
                    'outsiderSubjectUuid' => ${d}outsider->external_auth_id], JSON_THROW_ON_ERROR), "\n";
            } catch (Throwable ${d}error) { while (ob_get_level()) ob_end_clean(); exit(1); }
        """.trimIndent() + "\n"
    }

    fun inputs(grants: FreshNativeIngressGrants, outsider: FreshBookstackOutsiderGrant? = null): Map<String, String> {
        val id = requireNotNull(grants.bookstackApiId)
        val secret = requireNotNull(grants.bookstackApiSecret)
        require(outsider == null || outsider.tokenId != id && outsider.tokenSecret != secret &&
            outsider.tokenSecret != grants.bookstackInternalToken)
        val d = '$'
        val outsiderInput = if (outsider == null) "" else """
                ${d}outsiderId = getenv('P0V3_BOOKSTACK_OUTSIDER_API_ID');
                ${d}outsiderSecret = getenv('P0V3_BOOKSTACK_OUTSIDER_API_SECRET');
                ${d}outsiderSub = getenv('P0V3_BOOKSTACK_OUTSIDER_SUB');
                if (!preg_match('/^p0v3-[a-f0-9]{32}${d}/D', ${d}outsiderId) || ${d}outsiderId === ${d}id ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}outsiderSecret) || ${d}outsiderSecret === ${d}secret ||
                    !preg_match('/^[a-f0-9-]{36}${d}/D', ${d}outsiderSub)) throw new RuntimeException('Foreign outsider grant');
        """.trimIndent()
        val outsiderCollision = if (outsider == null) "" else """
                    || ${d}db::table('roles')->where('system_name', 'p0v3-outsider')->exists()
                    || ${d}db::table('users')->where('external_auth_id', ${d}outsiderSub)->exists()
        """.trimIndent()
        val outsiderCreate = if (outsider == null) "" else """
                    // A distinct native read-capable non-member, bound to the
                    // freshly allocated Keycloak UUID. No owner page grants.
                    ${d}read = ${d}db::table('role_permissions')->whereIn('name',
                        ['access-api', 'book-view-own', 'chapter-view-own', 'page-view-own'])->pluck('id');
                    if (${d}read->count() !== 4 || ${d}read->unique()->count() !== 4)
                        throw new RuntimeException('Native outsider read policy absent');
                    ${d}outsiderRole = ${d}db::table('roles')->insertGetId([
                        'display_name' => 'P0v3 outsider reader', 'description' => 'Own content only',
                        'external_auth_id' => '', 'mfa_enforced' => 0, 'system_name' => 'p0v3-outsider']);
                    foreach (${d}read as ${d}permission) {
                        ${d}db::table('permission_role')->insert(['role_id' => ${d}outsiderRole, 'permission_id' => ${d}permission]);
                    }
                    ${d}outsiderUser = ${d}db::table('users')->insertGetId([
                        'name' => 'Fresh outsider', 'email' => 'outsider@localhost.invalid',
                        'password' => '', 'remember_token' => null, 'created_at' => now(), 'updated_at' => now(),
                        'email_confirmed' => 1, 'image_id' => 0, 'external_auth_id' => ${d}outsiderSub,
                        'slug' => 'p0v3-outsider', 'system_name' => null]);
                    ${d}db::table('role_user')->insert(['user_id' => ${d}outsiderUser, 'role_id' => ${d}outsiderRole]);
                    ${d}db::table('api_tokens')->insert(['name' => 'P0v3 outsider read API', 'user_id' => ${d}outsiderUser,
                        'token_id' => ${d}outsiderId, 'secret' => Illuminate\Support\Facades\Hash::make(${d}outsiderSecret),
                        'expires_at' => now()->addDays(90), 'created_at' => now(), 'updated_at' => now()]);
        """.trimIndent()
        val outsiderReadback = if (outsider == null) "" else """
                ${d}outsiderEntry = BookStack\Api\ApiToken::where('token_id', ${d}outsiderId)->sole();
                if (${d}outsiderEntry->user->external_auth_id !== ${d}outsiderSub ||
                    ${d}outsiderEntry->user->email !== 'outsider@localhost.invalid' ||
                    ${d}outsiderEntry->user_id === ${d}entry->user_id ||
                    !Illuminate\Support\Facades\Hash::check(${d}outsiderSecret, ${d}outsiderEntry->secret) ||
                    ${d}db::table('permission_role')->where('role_id', ${d}outsiderEntry->user->roles()->sole()->id)->count() !== 4 ||
                    ${d}db::table('permission_role')->join('role_permissions', 'role_permissions.id', '=', 'permission_role.permission_id')
                        ->where('permission_role.role_id', ${d}outsiderEntry->user->roles()->sole()->id)
                        ->where('role_permissions.name', 'page-view-all')->exists())
                    throw new RuntimeException('Native outsider scope/readback refused');
        """.trimIndent()
        return mapOf("bookstack-api.php" to """
            <?php
            declare(strict_types=1);
            error_reporting(0); ini_set('display_errors', '0'); umask(0077); ob_start();
            try {
                ${d}id = getenv('P0V3_BOOKSTACK_API_ID'); ${d}secret = getenv('P0V3_BOOKSTACK_API_SECRET');
                ${d}generation = getenv('P0V3_GENERATION');
                if (!preg_match('/^p0v3-[a-f0-9]{32}${d}/D', ${d}id) ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}secret) ||
                    !preg_match('/^q-[a-f0-9]{12}${d}/D', ${d}generation)) throw new RuntimeException('Foreign grant');
                $outsiderInput
                ${d}root = '/app/www/storage';
                if (!is_dir(${d}root) || is_link(${d}root)) throw new RuntimeException('Foreign storage');
                ${d}intent = ${d}root . '/p0v3-api-enrollment-intent.json';
                ${d}receipt = ${d}root . '/p0v3-api-enrollment-receipt.json';
                if (file_exists(${d}intent) || file_exists(${d}receipt)) throw new RuntimeException('Uncertain enrollment');
                ${d}fp = fopen(${d}intent, 'x');
                if (${d}fp === false) throw new RuntimeException('Intent unavailable');
                ${d}body = json_encode(['generation' => ${d}generation, 'id' => ${d}id,
                    'secretSha256' => hash('sha256', ${d}secret), 'attempted' => true${if (outsider == null) "" else ",\n                    'outsiderId' => ${d}outsiderId, 'outsiderSub' => ${d}outsiderSub,\n                    'outsiderSecretSha256' => hash('sha256', ${d}outsiderSecret)"}], JSON_THROW_ON_ERROR);
                if (fwrite(${d}fp, ${d}body) !== strlen(${d}body) || !fflush(${d}fp) || !fsync(${d}fp))
                    throw new RuntimeException('Intent uncertain');
                fclose(${d}fp);
                ${d}directory = fopen(${d}root, 'r');
                if (${d}directory === false || !fsync(${d}directory)) throw new RuntimeException('Intent directory uncertain');
                fclose(${d}directory);
                require '/app/www/vendor/autoload.php';
                ${d}app = require '/app/www/bootstrap/app.php';
                ${d}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${d}db = Illuminate\Support\Facades\DB::class;
                if (!Illuminate\Support\Facades\Schema::hasTable('api_tokens') ||
                    ${d}db::table('api_tokens')->count() !== 0 ||
                    ${d}db::table('roles')->where('system_name', 'automation')->exists() ||
                    ${d}db::table('users')->where('email', 'p0v3-automation@localhost.invalid')->exists()
                    $outsiderCollision)
                    throw new RuntimeException('Retained or unknown native identity');
                // Match the pinned OLD automation role, never the unrestricted admin role.
                ${d}names = ['access-api', 'content-export', 'page-create-all', 'page-view-all',
                    'page-update-all', 'chapter-create-all', 'chapter-view-all', 'chapter-update-all',
                    'book-create-all', 'book-view-all', 'book-update-all', 'bookshelf-view-all',
                    'image-create-all', 'image-update-all', 'attachment-create-all'];
                ${d}permissions = ${d}db::table('role_permissions')->whereIn('name', ${d}names)->pluck('id');
                if (${d}permissions->count() !== count(${d}names) ||
                    ${d}permissions->unique()->count() !== count(${d}names))
                    throw new RuntimeException('Native scoped API permissions absent');
                ${d}db::transaction(function () use (${d}db, ${d}permissions, ${d}id, ${d}secret${if (outsider == null) "" else ", ${d}outsiderId, ${d}outsiderSecret, ${d}outsiderSub"}) {
                    ${d}role = ${d}db::table('roles')->insertGetId([
                        'display_name' => 'P0v3 API automation', 'description' => 'Fresh scoped API identity',
                        'external_auth_id' => '', 'mfa_enforced' => 0, 'system_name' => 'automation']);
                    foreach (${d}permissions as ${d}permission) {
                        ${d}db::table('permission_role')->insert(['role_id' => ${d}role, 'permission_id' => ${d}permission]);
                    }
                    ${d}user = ${d}db::table('users')->insertGetId([
                        'name' => 'P0v3 automation', 'email' => 'p0v3-automation@localhost.invalid',
                        'password' => '', 'remember_token' => null, 'created_at' => now(), 'updated_at' => now(),
                        'email_confirmed' => 1, 'image_id' => 0, 'external_auth_id' => '',
                        'slug' => 'p0v3-automation', 'system_name' => null]);
                    ${d}db::table('role_user')->insert(['user_id' => ${d}user, 'role_id' => ${d}role]);
                    ${d}db::table('api_tokens')->insert(['name' => 'P0v3 private API', 'user_id' => ${d}user,
                        'token_id' => ${d}id, 'secret' => Illuminate\Support\Facades\Hash::make(${d}secret),
                        'expires_at' => now()->addDays(90), 'created_at' => now(), 'updated_at' => now()]);
                    $outsiderCreate
                });
                ${d}entry = BookStack\Api\ApiToken::where('token_id', ${d}id)->sole();
                if (${d}entry->user->email !== 'p0v3-automation@localhost.invalid' ||
                    !Illuminate\Support\Facades\Hash::check(${d}secret, ${d}entry->secret) ||
                    ${d}db::table('api_tokens')->count() !== ${if (outsider == null) 1 else 2} ||
                    ${d}db::table('permission_role')->where('role_id', ${d}entry->user->roles()->sole()->id)->count() !== count(${d}names))
                    throw new RuntimeException('Native API readback refused');
                $outsiderReadback
                ${d}fp = fopen(${d}receipt, 'x');
                if (${d}fp === false) throw new RuntimeException('Receipt unavailable');
                ${d}body = json_encode(['generation' => ${d}generation, 'id' => ${d}id,
                    'userId' => ${d}entry->user_id, 'enrolled' => true${if (outsider == null) "" else ",\n                    'outsiderId' => ${d}outsiderId, 'outsiderUserId' => ${d}outsiderEntry->user_id"}], JSON_THROW_ON_ERROR);
                if (fwrite(${d}fp, ${d}body) !== strlen(${d}body) || !fflush(${d}fp) || !fsync(${d}fp))
                    throw new RuntimeException('Receipt uncertain');
                fclose(${d}fp);
                ${d}directory = fopen(${d}root, 'r');
                if (${d}directory === false || !fsync(${d}directory)) throw new RuntimeException('Receipt directory uncertain');
                fclose(${d}directory);
            } catch (Throwable ${d}error) { while (ob_get_level()) ob_end_clean(); exit(1); }
            while (ob_get_level()) ob_end_clean();
        """.trimIndent() + "\n",
            "bookstack-api-grant.env" to "P0V3_BOOKSTACK_API_ID=$id\nP0V3_BOOKSTACK_API_SECRET=$secret\n" +
                (if (outsider == null) "" else "P0V3_BOOKSTACK_OUTSIDER_SUB=${outsider.subjectUuid}\n" +
                    "P0V3_BOOKSTACK_OUTSIDER_API_ID=${outsider.tokenId}\n" +
                    "P0V3_BOOKSTACK_OUTSIDER_API_SECRET=${outsider.tokenSecret}\n"))
    }
}
