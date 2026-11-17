<?php
/** Native Laravel application data/session consistency, not an auth provider.
 * OIDC is handled by the supported gateway; Firefly issues native PKCE tokens.
 */
declare(strict_types=1);
namespace P0\Finance;

use App\Services\Session\Constants;
use App\Services\Shared\Authentication\SecretManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SubjectBoundary
{
    public function handle(Request $request, Closure $next): Response
    {
        ImporterSubjects::assertPolicy();
        if (!ManualFilePolicy::permits($request->getPathInfo(), $request->method())) {
            abort(403, 'Only deliberate manual file import is enabled.');
        }
        if ($request->is('health')) {
            return $next($request); // Native readiness only; no financial/session data.
        }
        $subject = ImporterSubjects::subject();
        $session = $request->session();
        $bound = $session->get('p0_finance_subject');
        if ($bound !== null && (!is_string($bound) || !hash_equals($bound, $subject))) {
            $session->invalidate();
            $session->regenerateToken();
            abort(403, 'Financial session changed; authenticate again.');
        }
        $before = SecretManager::getAccessToken();
        if ($bound === null && $before !== '') {
            $session->invalidate();
            $session->regenerateToken();
            abort(403, 'Unbound financial session refused.');
        }
        $session->put('p0_finance_subject', $subject);
        ImporterSubjects::configureSubjectStorage();
        if ($before !== '') {
            $this->verifyNativeOwner($before, $subject, $request);
        }
        $response = $next($request);
        $after = SecretManager::getAccessToken();
        if ($after !== '' && $after !== $before) {
            // In particular, verify AFTER the real native OAuth callback before
            // releasing its response. A stale finance SSO cookie cannot link A's
            // Passport token to B's importer session.
            $this->verifyNativeOwner($after, $subject, $request);
        }
        // This fixed public client is authorization-code/PKCE only. Its bounded
        // access token must be reauthorized; do not retain unused refresh tokens.
        $session->forget(Constants::SESSION_REFRESH_TOKEN);
        return $response;
    }

    private function verifyNativeOwner(string $token, string $subject, Request $request): void
    {
        try {
            $issuer = getenv('FIREFLY_OIDC_ISSUER') ?: '';
            if (!preg_match('~^https://auth\.([a-z0-9.-]+)/realms/p0v3$~D', $issuer, $match)
                || (string) config('importer.url') !== 'https://firefly.'.$match[1]
                || strpbrk($token, "\r\n") !== false || strlen($token) > 65536) {
                throw new \RuntimeException('native token transport policy mismatch');
            }
            $context = stream_context_create([
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
                'http' => ['timeout' => 10, 'follow_location' => 0, 'ignore_errors' => true,
                    'header' => "Accept: application/json\r\nAuthorization: Bearer ".$token."\r\n"],
            ]);
            $body = @file_get_contents('http://firefly-native-api:8081/api/v1/about/user', false, $context, 0, 65537);
            if ($body === false || strlen($body) > 65536
                || !preg_match('~^HTTP/\S+ 200(?: |$)~', $http_response_header[0] ?? '')) {
                throw new \RuntimeException('native financial token expired, unavailable or refused');
            }
            $user = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            if (($user['data']['attributes']['email'] ?? null) !== $subject) {
                throw new \RuntimeException('native financial token subject mismatch');
            }
        } catch (\Throwable $failure) {
            // Do not retain a token for another account, or echo API contents.
            $request->session()->forget([Constants::SESSION_ACCESS_TOKEN, Constants::SESSION_REFRESH_TOKEN]);
            abort(403, 'Financial token refused; authenticate again.');
        }
    }
}
