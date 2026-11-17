<?php
/** Application resource ownership, NOT an OIDC/authentication implementation.
 * The supported gateway authenticates subjects. Native importer2.3.5's global
 * UUID job lookup lacks tenant ownership, so source integration binds each newly
 * created job BEFORE storage and checks ownership BEFORE native HTTP reads/writes.
 */
declare(strict_types=1);
namespace P0\Finance;

final class ImporterSubjects
{
    private static function directory(): string
    {
        $path = storage_path('app/p0-subject-owners');
        if (!is_dir($path) || is_link($path)) {
            abort(503, 'Importer identity policy not initialized.');
        }
        return $path;
    }

    private static function expectedPolicy(): array
    {
        $issuer = getenv('FIREFLY_OIDC_ISSUER') ?: '';
        $client = (string) config('importer.client_id');
        $key = (string) config('app.key');
        if (!preg_match('~^https://auth\.[a-z0-9.-]+/realms/p0v3$~D', $issuer)
            || !self::uuid($client) || !str_starts_with($key, 'base64:')
            || strlen(base64_decode(substr($key, 7), true) ?: '') !== 32
            || (string) config('importer.access_token') !== '') {
            abort(503, 'Importer identity/client/key configuration refused.');
        }
        $providers = config('importer.providers');
        $expectedProviders = ['file', 'sophtron', 'nordigen', 'simplefin', 'lunchflow', 'eb', 'akahu'];
        if (!is_array($providers) || count($providers) !== count($expectedProviders)) {
            abort(503, 'Unreviewed importer provider inventory refused.');
        }
        foreach ($expectedProviders as $provider) {
            if (($providers[$provider]['enabled'] ?? null) !== ($provider === 'file')) {
                abort(503, 'Only the reviewed file provider may be enabled.');
            }
        }
        foreach (['can_post_autoimport', 'can_post_files', 'fake_data', 'store_fake_data'] as $flag) {
            if (config('importer.'.$flag) !== false) {
                abort(503, 'Automated or fake importer input refused.');
            }
        }
        if (config('importer.auto_import_secret') !== '') {
            abort(503, 'Automated importer credentials refused.');
        }
        return ['schemaVersion' => 1, 'issuer' => $issuer, 'clientId' => $client,
            'keySha256' => hash('sha256', $key)];
    }

    public static function uuid(string $value): bool
    {
        return preg_match('/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/D', $value) === 1;
    }

    private static function read(string $path): array
    {
        if (!is_file($path) || is_link($path) || filesize($path) > 4096
            || (fileperms($path) & 0777) !== 0600) {
            abort(503, 'Importer identity metadata absent or unsafe.');
        }
        $value = json_decode(file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($value)) {
            abort(503, 'Importer identity metadata invalid.');
        }
        return $value;
    }

    public static function assertPolicy(): void
    {
        if (self::read(self::directory().'/policy.json') !== self::expectedPolicy()) {
            abort(503, 'Importer persisted issuer/client/key binding mismatch.');
        }
    }

    public static function initialize(): void
    {
        if (!app()->runningInConsole()) {
            abort(403);
        }
        umask(0077);
        $path = storage_path('app/p0-subject-owners');
        if (is_link($path)) {
            abort(503);
        }
        if (!is_dir($path) && !mkdir($path, 0700)) {
            abort(503);
        }
        $policy = self::expectedPolicy();
        $file = $path.'/policy.json';
        if (file_exists($file) || is_link($file)) {
            self::assertPolicy();
            return;
        }
        // Never adopt unbound existing jobs or make a first visitor their owner.
        if (array_diff(scandir($path), ['.', '..']) !== []
            || array_diff(\Illuminate\Support\Facades\Storage::disk('import-jobs')->allFiles(), ['.gitignore']) !== []) {
            abort(503, 'Unbound importer state requires explicit recovery.');
        }
        foreach (['configurations', 'framework/sessions', 'app/p0-configurations'] as $relative) {
            $existing = storage_path($relative);
            if (is_link($existing) || (is_dir($existing)
                && array_diff(scandir($existing), ['.', '..', '.gitignore']) !== [])) {
                abort(503, 'Unbound importer sessions/configuration require explicit recovery.');
            }
        }
        self::exclusiveWrite($file, $policy);
    }

    private static function exclusiveWrite(string $path, array $value): void
    {
        umask(0077);
        $handle = @fopen($path, 'x');
        if ($handle === false) {
            abort(503, 'Importer identity metadata collision.');
        }
        try {
            $bytes = json_encode($value, JSON_THROW_ON_ERROR)."\n";
            if (!flock($handle, LOCK_EX) || fwrite($handle, $bytes) !== strlen($bytes)
                || !fflush($handle) || !fsync($handle)) {
                abort(503, 'Importer identity metadata write failed.');
            }
        } finally {
            fclose($handle);
        }
    }

    public static function subject(): string
    {
        $subject = request()->server('HTTP_X_FORWARDED_USER');
        if (!is_string($subject) || !self::uuid($subject)) {
            abort(403, 'Validated financial subject missing or ambiguous.');
        }
        self::assertPolicy();
        return $subject;
    }

    private static function ownerKey(): string
    {
        return hash_hmac('sha256', getenv('FIREFLY_OIDC_ISSUER')."\0".self::subject(), (string) config('app.key'));
    }

    public static function recordOwner(string $job): void
    {
        if (app()->runningInConsole()) {
            // Native asynchronous service workers are privileged, not web users.
            // CLI-created jobs remain unbound and therefore inaccessible via HTTP.
            return;
        }
        if (!self::uuid($job)) {
            abort(503);
        }
        self::exclusiveWrite(self::directory().'/'.$job.'.json',
            ['schemaVersion' => 1, 'job' => $job, 'ownerKey' => self::ownerKey()]);
    }

    public static function assertOwner(string $job): void
    {
        if (app()->runningInConsole()) {
            return;
        }
        if (!self::ownsJob($job)) {
            abort(404, 'Import job not found.');
        }
    }

    public static function ownsJob(string $job): bool
    {
        if (!self::uuid($job)) {
            return false;
        }
        $file = self::directory().'/'.$job.'.json';
        if (!is_file($file) || is_link($file)) {
            return false;
        }
        $binding = self::read($file);
        return ($binding['schemaVersion'] ?? null) === 1 && ($binding['job'] ?? null) === $job
            && is_string($binding['ownerKey'] ?? null) && hash_equals(self::ownerKey(), $binding['ownerKey']);
    }

    public static function configureSubjectStorage(): void
    {
        umask(0077);
        $base = storage_path('app/p0-configurations');
        $path = $base.'/'.self::ownerKey();
        foreach ([$base, $path] as $directory) {
            if (is_link($directory) || (!is_dir($directory) && !mkdir($directory, 0700))
                || (fileperms($directory) & 0777) !== 0700) {
                abort(503, 'Private importer configuration directory refused.');
            }
        }
        // Native list/upload/config-selection handlers now share ONLY this
        // subject's store. Never list another subject's configuration filenames.
        config(['filesystems.disks.configurations.root' => $path]);
        \Illuminate\Support\Facades\Storage::forgetDisk('configurations');
    }
}
