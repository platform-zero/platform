<?php
/** Versioned file-only surface for the pinned official importer.
 * Supported native state/PKCE/CSRF handlers remain responsible for their protocol.
 * No bank flows, automated uploads, debug log viewer or URL/PAT/client override.
 */
declare(strict_types=1);
namespace P0\Finance;

final class ManualFilePolicy
{
    public static function permits(string $path, string $method): bool
    {
        if ($method === 'GET' && in_array($path, ['/', '/health', '/token', '/token/validate', '/callback', '/flush', '/import/php_date',
            '/validate/file', '/api/import-flows', '/api/import-flows/validate/file', '/api/firefly-iii/validate', '/api/import-jobs'], true)) {
            return true;
        }
        if ($method === 'GET' && preg_match('~^/(?:authenticate-flow|new-import)(?:/file)?$~D', $path)) {
            return true;
        }
        if ($method === 'POST' && in_array($path, ['/authenticate-flow/file', '/new-import/file'], true)) {
            return true;
        }
        $uuid = '[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}';
        if (in_array($method, ['GET', 'POST'], true)
            && preg_match('~^/(?:configure-import|configure-roles|data-mapping)/'.$uuid.'$~D', $path)) {
            return true;
        }
        if ($method === 'GET' && preg_match('~^/(?:download-import-configuration/'.$uuid.'|(?:data-conversion|submit-data)/'.$uuid.'(?:/status)?)$~D', $path)) {
            return true;
        }
        // The pinned UI uses axios POST + native CSRF for starts. Do not preserve
        // upstream Route::any's unnecessary state-changing GET alternative.
        return $method === 'POST' && preg_match('~^/(?:check-duplicate-account/'.$uuid.'|(?:data-conversion|submit-data)/'.$uuid.'/start)$~D', $path) === 1;
    }
}
