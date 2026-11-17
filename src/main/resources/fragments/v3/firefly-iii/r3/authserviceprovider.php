<?php
/**
 * Based on Firefly III6.7.9 app/Providers/AuthServiceProvider.php.
 * Copyright (c) 2019 james@firefly-iii.org
 * Integration changes: bounded native Passport token lifetimes.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * This program is free software under GNU AGPL version3 or later, WITHOUT ANY
 * WARRANTY; see https://www.gnu.org/licenses/agpl-3.0.html for the full license.
 */
declare(strict_types=1);
namespace FireflyIII\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Laravel\Passport\Passport;

/** Uses supported native Passport configuration; does not authenticate requests. */
class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        umask(0077);
        Passport::tokensExpireIn(now()->addMinutes(15));
        Passport::personalAccessTokensExpireIn(now()->addMinutes(15));
        Passport::refreshTokensExpireIn(now()->addMinutes(15));
        require_once '/opt/firefly/ApiSubjectBoundary.php';
        $this->app->booted(function (): void {
            $this->app['router']->pushMiddlewareToGroup('api', \P0\Finance\ApiSubjectBoundary::class);
        });
    }
}
