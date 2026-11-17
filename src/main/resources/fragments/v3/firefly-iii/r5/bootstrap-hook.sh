#!/bin/bash
# Versioned startup integration for the pinned official image. No composer,
# package download, startup build, live source rewrite or random key generation.
set -euo pipefail
umask 077
[[ "${APP_ENV:-}" == production && "${APP_DEBUG:-}" == false ]]
[[ "${FIREFLY_III_PATH:-}" == /var/www/html && "${AUTORUN_ENABLED:-}" == false ]]
[[ "${LOG_LEVEL:-warning}" != debug && "${LOG_OUTPUT_LEVEL:-warning}" != debug ]]
cd /var/www/html
/bin/bash -e /usr/local/bin/finalize-image.sh
mkdir -p storage/import-jobs storage/configurations
# Native supported runtime configuration caching, NOT dependency/image builds.
php artisan config:clear --no-ansi >/dev/null
php artisan config:cache --no-ansi >/dev/null
php artisan importer:version --no-ansi
php /opt/firefly-importer/initialize-policy.php
