"""Read-only same-version Home Assistant 2026.10.4 cold-start admission, not a restore oracle."""
if not __debug__:
    raise SystemExit("Optimized Python refused before imports or effects")

import json
import os
import sqlite3
import stat
from pathlib import Path

TABLES = {"states", "state_attributes", "events", "event_data", "event_types", "recorder_runs",
          "schema_changes", "migration_changes", "states_meta", "statistics", "statistics_meta",
          "statistics_runs", "statistics_short_term"}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate storage key")
        result[key] = value
    return result


def regular(directory, name, maximum, private=False, allow_empty=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or not (0 if allow_empty else 1) <= info.st_size <= maximum or info.st_mode & (0o077 if private else 0o022)):
            raise ValueError("Unsafe or missing restored file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def storage(directory, name, version):
    with os.fdopen(regular(directory, name, 4 * 1024 * 1024, private=True), "rb") as stream:
        value = json.loads(stream.read(), object_pairs_hook=unique)
    if (value.get("key") != name or type(value.get("version")) is not int or value["version"] != version
            or not isinstance(value.get("data"), dict)):
        raise ValueError("Unreviewed storage version")
    return value["data"]


def verify(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("Exact restored root required")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.fdopen(regular(directory, "configuration.yaml", 1024 * 1024), "rb") as config:
            if not config.read().strip():
                raise ValueError("Missing original configuration")
        auth_dir = os.open(".storage", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            directory_info = os.fstat(auth_dir)
            if directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o022:
                raise ValueError("Unsafe restored authentication directory")
            auth = storage(auth_dir, "auth", 1)
            provider = storage(auth_dir, "auth_provider.homeassistant", 1)
            onboarding = storage(auth_dir, "onboarding", 4)
        finally:
            os.close(auth_dir)
        if set(onboarding["done"]) != {"user", "core_config", "integration", "analytics"}:
            raise ValueError("Incomplete original onboarding")
        owners = {u["id"] for u in auth["users"] if u["is_owner"] is True and u["is_active"] is True
                  and u["system_generated"] is False}
        usernames = {c["data"]["username"] for c in auth["credentials"] if c["user_id"] in owners
                     and c["auth_provider_type"] == "homeassistant" and c["auth_provider_id"] is None}
        if not owners or not any(u["username"] in usernames and isinstance(u["password"], str) and u["password"]
                                 for u in provider["users"]):
            raise ValueError("Original active owner credentials required")
        db = regular(directory, "home-assistant_v2.db", 8 * 1024 ** 3)
        try:
            # Cold import is fenced and has no other writer. Check sidecars before SQLite can open them.
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    sidecar = regular(directory, "home-assistant_v2.db" + suffix, 8 * 1024 ** 3, allow_empty=True)
                except FileNotFoundError:
                    continue
                os.close(sidecar)
            connection = sqlite3.connect(f"file:/proc/self/fd/{directory}/home-assistant_v2.db?mode=ro", uri=True, timeout=5)
            try:
                connection.execute("PRAGMA query_only=ON")
                if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise ValueError("Recorder integrity failed")
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not TABLES <= tables or connection.execute("SELECT MAX(schema_version) FROM schema_changes").fetchone() != (53,):
                    raise ValueError("Recorder schema requires unreviewed initialization or migration")
            finally:
                connection.close()
        finally:
            os.close(db)
    finally:
        os.close(directory)


def main():
    try:
        verify(Path("/config"))
    except Exception:
        raise SystemExit("Restored Home Assistant admission refused; original state retained") from None
    os.execve("/usr/local/bin/python3", ["/usr/local/bin/python3", "-m", "homeassistant", "--config", "/config"],
              {**os.environ, "HOME": "/config"})


if __name__ == "__main__":
    main()
