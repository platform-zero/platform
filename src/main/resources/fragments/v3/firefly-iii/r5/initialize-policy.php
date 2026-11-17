<?php
/** Native CLI bootstrap + persisted policy check; contains no authentication. */
declare(strict_types=1);
try {
    if (PHP_SAPI !== 'cli' || !in_array($argv, [[$argv[0]], [$argv[0], '--check-only']], true)) {
        throw new RuntimeException('CLI policy arguments refused');
    }
    umask(0077);
    require_once '/opt/firefly-importer/RestoreAccessReset.php';
    require '/var/www/html/vendor/autoload.php';
    $app = require '/var/www/html/bootstrap/app.php';
    $app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    // PHP/Guzzle uses the system curl/openssl stores when importer verify is true.
    // The generation-issued ingress CA must be the store actually loaded by this PHP process.
    $ca = '/run/secrets/finance-ingress-ca.pem';
    if (ini_get('curl.cainfo') !== $ca || ini_get('openssl.cafile') !== $ca
        || getenv('CURL_CA_BUNDLE') !== $ca || getenv('SSL_CERT_FILE') !== $ca
        || config('importer.connection.verify') !== true
        || config('importer.url') !== 'https://firefly.datamancy.net'
        || !is_file($ca) || is_link($ca) || !is_readable($ca)) {
        throw new RuntimeException('native importer ingress trust refused');
    }
    $parsed = openssl_x509_parse((string) file_get_contents($ca));
    if ($parsed === false || !str_contains((string) ($parsed['extensions']['basicConstraints'] ?? ''), 'CA:TRUE')) {
        throw new RuntimeException('native importer ingress issuer refused');
    }
    if (config('session.driver') !== 'file' || config('session.files') !== storage_path('framework/sessions')
        || !in_array(config('session.lifetime'), [15, '15'], true)
        || config('session.cookie') !== '__Host-firefly_importer_app'
        || config('session.path') !== '/' || !in_array(config('session.domain'), [null, ''], true)
        || config('session.secure') !== true || config('session.http_only') !== true
        || config('session.same_site') !== 'lax') {
        throw new RuntimeException('native importer session policy refused');
    }
    if (($argv[1] ?? '') === '--check-only') {
        \P0\Finance\ImporterSubjects::assertPolicy();
    } else {
        \P0\Finance\ImporterSubjects::initialize();
    }
    $restorePlan = \P0\Finance\RestoreAccessReset::plan(storage_path(), ($argv[1] ?? '') === '--check-only');
    if ($restorePlan !== null) {
        \P0\Finance\RestoreAccessReset::resetSessions($restorePlan);
        \P0\Finance\RestoreAccessReset::finish($restorePlan);
    }
    fwrite(STDOUT, "Native importer issuer/client/key policy verified.\n");
} catch (Throwable $failure) {
    // Do not echo configuration, credentials or financial contents.
    fwrite(STDERR, "Native importer persisted policy refused.\n");
    exit(1);
}
