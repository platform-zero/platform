<?php
/** A restored importer must not resume copied browser/Passport sessions. The
 * recovery owner creates the marker only after a verified cold import, before
 * the importer is started. No marker is needed on a fresh install or restart.
 * The marker is an intent, not a fabricated recovery acknowledgment.
 */
declare(strict_types=1);
namespace P0\Finance;

final class RestoreAccessReset
{
    public static function plan(string $storage, bool $checkOnly): ?array
    {
        $root = $storage.'/app/p0-subject-owners';
        $generation = getenv('P0V3_GENERATION');
        if (!is_string($generation) || !preg_match('/^q-[a-f0-9]{12}$/D', $generation)) {
            throw new \RuntimeException('Importer runtime generation missing');
        }
        $intent = $root.'/restore-session-reset.'.$generation.'.json';
        $done = $root.'/restore-session-reset.'.$generation.'.completed.json';
        $started = $root.'/restore-session-reset.'.$generation.'.started';
        if (is_link($root) || !is_dir($root) || is_link($intent) || is_link($done) || is_link($started)) {
            throw new \RuntimeException('Unsafe importer restore custody');
        }
        if (!file_exists($intent)) {
            return null;
        }
        if (file_exists($done) || file_exists($started) || !is_file($intent) || filesize($intent) > 1024
            || (fileperms($intent) & 0777) !== 0600) {
            throw new \RuntimeException('Ambiguous importer restore intent');
        }
        $marker = json_decode(file_get_contents($intent), true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($marker) || array_keys($marker) !== ['schemaVersion', 'sourceGeneration', 'targetGeneration']
            || $marker['schemaVersion'] !== 1
            || !is_string($marker['sourceGeneration']) || !is_string($marker['targetGeneration'])
            || !preg_match('/^q-[a-f0-9]{12}$/D', $marker['sourceGeneration'])
            || !preg_match('/^q-[a-f0-9]{12}$/D', $marker['targetGeneration'])
            || $marker['sourceGeneration'] === $marker['targetGeneration']
            || $marker['targetGeneration'] !== getenv('P0V3_GENERATION')) {
            throw new \RuntimeException('Foreign importer restore intent');
        }
        // Both the normal startup hook and an explicit check-only startup may
        // finish the same imported-state reset, before serving HTTP requests.
        return ['intent' => $intent, 'done' => $done, 'started' => $started,
            'sessions' => $storage.'/framework/sessions'];
    }

    public static function resetSessions(array $plan): void
    {
        $sessions = $plan['sessions'];
        if (is_link($sessions) || !is_dir($sessions)) {
            throw new \RuntimeException('Unsafe native session directory');
        }
        // A lost ACK after any unlink must not turn the next startup into a
        // second effect. Recovery may only reconcile this retained start marker.
        $start = fopen($plan['started'], 'x');
        if ($start === false) {
            throw new \RuntimeException('Importer session reset already attempted');
        }
        try {
            if (fwrite($start, "reset-started\n") !== 14 || !fflush($start) || !fsync($start)) {
                throw new \RuntimeException('Importer session reset intent uncertain');
            }
        } finally {
            fclose($start);
        }
        $custody = fopen(dirname($plan['started']), 'r');
        if ($custody === false || !fsync($custody)) {
            throw new \RuntimeException('Importer session reset intent durability uncertain');
        }
        fclose($custody);
        foreach (new \DirectoryIterator($sessions) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            if ($entry->getFilename() === '.gitignore' && $entry->isFile() && !$entry->isLink()) {
                continue;
            }
            // Reject links, foreign subdirectories and unknown files rather than
            // recursively deleting application state outside the session store.
            if ($entry->isLink() || !$entry->isFile()
                || !preg_match('/^[A-Za-z0-9]{40}$/D', $entry->getFilename())
                || !unlink($entry->getPathname())) {
                throw new \RuntimeException('Native session reset incomplete');
            }
        }
        $directory = fopen($sessions, 'r');
        if ($directory === false || !fsync($directory)) {
            throw new \RuntimeException('Native session reset durability uncertain');
        }
        fclose($directory);
    }

    public static function finish(array $plan): void
    {
        if (file_exists($plan['done']) || is_link($plan['intent'])
            || !rename($plan['intent'], $plan['done'])) {
            throw new \RuntimeException('Importer restore reset acknowledgment uncertain');
        }
        $directory = fopen(dirname($plan['done']), 'r');
        if ($directory === false || !fsync($directory)) {
            throw new \RuntimeException('Importer restore reset durability uncertain');
        }
        fclose($directory);
    }
}
