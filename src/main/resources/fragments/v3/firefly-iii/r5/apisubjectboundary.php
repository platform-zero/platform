<?php
/** Native API cookie/session consistency, not an authentication provider.
 * Browser requests authenticate at the supported gateway. Explicit native
 * Bearer requests use Passport and arrive through the cookie-stripping API path.
 */
declare(strict_types=1);
namespace P0\Finance;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class ApiSubjectBoundary
{
    public function handle(Request $request, Closure $next): Response
    {
        if (!$request->is('api/v1/*')) {
            return $next($request);
        }
        if ($request->bearerToken()) { // Match native Passport's bearer-vs-cookie selection, including empty/"0".
            return $next($request); // Native Passport verifies signature/revocation/owner.
        }
        $subject = $request->server('HTTP_X_FORWARDED_USER');
        if (!is_string($subject) || !preg_match('/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/D', $subject)) {
            abort(401, 'Validated financial session required.');
        }
        $user = Auth::guard('api')->user();
        if ($user !== null && (!is_string($user->email ?? null) || !hash_equals($subject, $user->email))) {
            abort(403, 'Financial cookie subject mismatch.');
        }
        return $next($request);
    }
}
