#!/bin/sh
# Image-build smoke test only. No host volumes, TCP listeners, application accounts or Kopia claim.
set -eu
umask 077
root=$(mktemp -d /tmp/p0-timescale-smoke.XXXXXXXX)
initdb -D "$root/data" --auth-local=trust --auth-host=reject > "$root/init.log"
start() {
  pg_ctl -D "$root/data" -l "$root/server.log" -w -t 30 \
    -o "-c listen_addresses='' -c unix_socket_directories='$root' -c shared_preload_libraries=timescaledb -c timescaledb.max_background_workers=2 -c max_worker_processes=8 -c timescaledb.telemetry_level=off" start
}
export PGHOST="$root" PGUSER=postgres PGDATABASE=postgres
start
psql -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION timescaledb VERSION '2.31.0';
CREATE ROLE p0_artifact_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE ordinary;
REVOKE CREATE ON DATABASE ordinary FROM PUBLIC;
REVOKE CREATE ON DATABASE ordinary FROM p0_artifact_runtime;
CREATE TABLE sample(time timestamptz NOT NULL, value integer NOT NULL);
SELECT create_hypertable('sample', by_range('time'));
INSERT INTO sample VALUES ('2026-01-01 00:00Z', 17), ('2026-01-01 00:30Z', 23);
CREATE MATERIALIZED VIEW hourly WITH (timescaledb.continuous) AS
 SELECT time_bucket('1 hour', time) AS bucket, sum(value) AS value FROM sample GROUP BY 1 WITH NO DATA;
CALL refresh_continuous_aggregate('hourly', NULL, NULL);
SELECT add_continuous_aggregate_policy('hourly', start_offset => INTERVAL '2 days',
 end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '1 hour', initial_start => 'infinity'::timestamptz);
SELECT alter_job(job_id, scheduled => false) FROM timescaledb_information.jobs WHERE proc_name='policy_refresh_continuous_aggregate';
DO $$ BEGIN
 IF (SELECT value FROM hourly) <> 40 THEN RAISE EXCEPTION 'aggregate mismatch'; END IF;
 IF (SELECT extversion FROM pg_extension WHERE extname='timescaledb') <> '2.31.0' THEN RAISE EXCEPTION 'version mismatch'; END IF;
END $$;
SQL
if PGUSER=p0_artifact_runtime psql -X -d ordinary -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION timescaledb' > "$root/extension-denial.log" 2>&1; then
  echo 'Unexpected non-superuser extension creation' >&2; exit 1
fi
grep -Eqi 'permission denied|must be owner|must be superuser' "$root/extension-denial.log"
if PGUSER=p0_artifact_runtime psql -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE forbidden' > "$root/database-denial.log" 2>&1; then
  echo 'Unexpected runtime database creation' >&2; exit 1
fi
grep -q 'permission denied to create database' "$root/database-denial.log"
test "$(psql -XAt -d ordinary -c "SELECT count(*) FROM pg_extension WHERE extname='timescaledb'")" = 0
pg_ctl -D "$root/data" -m fast -w -t 30 stop
# A physical, stopped copy exercises extension/version restart compatibility, not a Kopia restore.
cp -a "$root/data" "$root/cold"
start
psql -X -v ON_ERROR_STOP=1 -c "INSERT INTO sample VALUES ('2026-01-02 00:00Z', 99)"
pg_ctl -D "$root/data" -m fast -w -t 30 stop
mv "$root/data" "$root/after-snapshot"
mv "$root/cold" "$root/data"
pg_ctl -D "$root/data" -l "$root/restored.log" -w -t 30 \
  -o "-c listen_addresses='' -c unix_socket_directories='$root' -c shared_preload_libraries=timescaledb -c timescaledb.max_background_workers=2 -c max_worker_processes=8 -c timescaledb.restoring=on -c timescaledb.telemetry_level=off" start
test "$(psql -XAt -c 'SHOW timescaledb.restoring')" = on
test "$(psql -XAt -c 'SELECT sum(value) FROM sample')" = 40
test "$(psql -XAt -c 'SELECT value FROM hourly')" = 40
test "$(psql -XAt -c "SELECT count(*) FROM timescaledb_information.jobs WHERE proc_name='policy_refresh_continuous_aggregate' AND NOT scheduled")" = 1
pg_ctl -D "$root/data" -m fast -w -t 30 stop
# Only this newly-created, successfully stopped build fixture is removed.
rm -rf -- "$root"
printf '%s\n' 'TIMESCALE_ARTIFACT_SMOKE_OK pg17.11 ts2.31.0 permissions hypertable aggregate policy-metadata cold-copy exclusion restoring-on'
