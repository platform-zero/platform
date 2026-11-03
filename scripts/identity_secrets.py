#!/usr/bin/env python3
"""Explicit scoped identity/secret operations. Never imported by a daemon boot hook.

Only private files carry bearer credentials or recovery shares. Mutations are intent
journalled before transport, never retried, and require a fresh operation ID. A lost
acknowledgement retains uncertainty; it is not permission to repeat an operation.
"""
import argparse
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import time
import urllib.parse
import uuid

MAX_BYTES = 1024 * 1024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")


class Refused(RuntimeError):
    """Safe, credential-free diagnostic."""


def require(value, message="Identity/secret operation refused"):
    if not value:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def object_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(value, dict), "JSON object required")
        return value
    except (ValueError, TypeError, UnicodeError):
        raise Refused("Invalid JSON") from None


def private_directory(path):
    path = Path(path).absolute()
    require(path.resolve() == path, "Symlinked private directory")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            "Owned mode-0700 directory required")
    return path


def private_read(path):
    path = Path(path).absolute()
    require(path.resolve() == path, "Symlinked private input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size <= MAX_BYTES,
                "Owned single-link mode-0600 bounded input required")
        data = os.read(fd, MAX_BYTES + 1)
        require(len(data) == info.st_size, "Private input changed")
        return data
    finally:
        os.close(fd)


def private_create(path, data):
    path = Path(path).absolute()
    private_directory(path.parent)
    require(len(data) <= MAX_BYTES, "Private output too large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_token(path):
    """Accept raw private tokens or the private custody envelope produced by rotate."""
    raw = private_read(path).decode().strip()
    token = object_json(raw).get("token") if raw.startswith("{") else raw
    require(isinstance(token, str) and 1 <= len(token) <= 65536 and "\r" not in token and "\n" not in token,
            "Invalid private token input")
    return token


class Https:
    """Hostname+CA verified and leaf-pinned HTTPS, no redirect or retry machinery."""
    def __init__(self, origin, ca_file, leaf_sha256):
        parsed = urllib.parse.urlsplit(origin)
        require(parsed.scheme == "https" and parsed.hostname and parsed.username is None and
                parsed.password is None and parsed.path in ("", "/") and not parsed.query and
                not parsed.fragment and HASH.fullmatch(leaf_sha256), "Exact pinned HTTPS origin required")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.origin = origin.rstrip("/")
        self.pin = leaf_sha256
        self.context = ssl.create_default_context(cadata=private_read(ca_file).decode("ascii"))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, path, token=None, body=None, form=None, expected=(200,)):
        require(path.startswith("/") and not path.startswith("//") and "#" not in path and
                "\r" not in path and "\n" not in path, "Invalid API path")
        require(body is None or form is None)
        headers = {"Accept": "application/json"}
        if token:
            require("\n" not in token and "\r" not in token)
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = canonical(body)
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(form).encode()
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=10, context=self.context)
        try:
            connection.connect()
            require(digest(connection.sock.getpeercert(binary_form=True)) == self.pin, "TLS leaf identity changed")
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, "API response too large")
            require(response.status in expected, "API operation failed")
            return object_json(raw) if raw else {}
        except Refused:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise Refused("HTTPS API unavailable; mutation outcome may be uncertain") from None
        finally:
            connection.close()


class Journal:
    """Private single-writer hash-linked append journal. No secret values in records."""
    def __init__(self, root):
        self.root = private_directory(root)
        self.path = self.root / "identity-secrets.jsonl"
        self.records = []

    @contextlib.contextmanager
    def locked(self):
        lock = self.root / "identity-secrets.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, "Unsafe journal lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.records = []
            if self.path.exists():
                raw = private_read(self.path)
                require(not raw or raw.endswith(b"\n"), "Interrupted journal append")
                for line in raw.splitlines():
                    record = object_json(line)
                    seal = record.pop("sha256", None)
                    require(record.get("previous") == self.head and record.get("sequence") == len(self.records) and
                            seal == digest(canonical(record)), "Journal chain changed")
                    record["sha256"] = seal
                    self.records.append(record)
            yield self
        finally:
            os.close(fd)

    @property
    def head(self):
        return self.records[-1]["sha256"] if self.records else "0" * 64

    def append(self, operation, phase, binding):
        record = {"sequence": len(self.records), "previous": self.head, "operation": operation,
                  "phase": phase, "binding": binding}
        record["sha256"] = digest(canonical(record))
        raw = canonical(record) + b"\n"
        require(sum(len(canonical(r)) + 1 for r in self.records) + len(raw) <= MAX_BYTES, "Journal capacity reached")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, "Unsafe journal file")
            require(os.write(fd, raw) == len(raw), "Partial journal append")
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.records.append(record)

    def execute(self, operation, binding, action):
        require(isinstance(operation, str) and ID.fullmatch(operation), "Invalid operation ID")
        with self.locked():
            require(not any(r["operation"] == operation for r in self.records), "Operation already journalled; do not replay")
            # An unresolved operation blocks this scope, even with a fresh caller-chosen ID.
            pending = {}
            for record in self.records:
                pending[record["operation"]] = record
            require(not any(r["phase"] != "complete" and r["binding"].get("scope") == binding.get("scope")
                            for r in pending.values()), "Scope has uncertain effects; reconciliation required")
            self.append(operation, "intent", binding)
            result = action()
            self.append(operation, "complete", binding)
            return result


class IdentityAuthority:
    def __init__(self, api, realm, client, client_secret, audience, allowed_subjects):
        require(ID.fullmatch(realm) and ID.fullmatch(client) and audience and allowed_subjects)
        self.api, self.realm, self.client = api, realm, client
        self.secret, self.audience, self.subjects = client_secret, audience, set(allowed_subjects)

    def authorize(self, bearer, scope, now=None):
        result = self.api.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token/introspect",
                                  form={"token": bearer, "client_id": self.client, "client_secret": self.secret})
        audience = result.get("aud", [])
        if isinstance(audience, str):
            audience = [audience]
        expires = result.get("exp")
        require(result.get("active") is True and result.get("iss") == self.api.origin + f"/realms/{self.realm}" and
                result.get("sub") in self.subjects and self.audience in audience and
                type(expires) is int and expires > (time.time() if now is None else now) and
                scope in result.get("scope", "").split(), "Scoped operator identity denied")
        return result["sub"]


class IdentityLifecycle:
    def __init__(self, api, realm, bearer, authority, journal):
        require(ID.fullmatch(realm))
        self.api, self.bearer, self.authority, self.journal = api, bearer, authority, journal
        self.base = f"/admin/realms/{realm}"

    def _run(self, operation, action, subject, effect):
        actor = self.authority.authorize(self.bearer, "identity:manage")
        return self.journal.execute(operation, {"action": action, "scope": self.api.origin + self.base,
                                               "subject": subject, "actor": actor}, effect)

    def onboard(self, operation, username, custody):
        require(ID.fullmatch(username), "Invalid username")
        require(not Path(custody).exists(), "Custody output exists")
        private_directory(Path(custody).absolute().parent)
        subject = str(uuid.uuid4())
        password = secrets.token_urlsafe(32)
        def effect():
            # Preserve the proposed subject/password before a possibly ambiguous create.
            private_create(custody, canonical({"subject": subject, "username": username, "temporaryPassword": password}))
            self.api.request("POST", self.base + "/users", self.bearer, {
                "id": subject, "username": username, "enabled": True,
                "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"],
                "credentials": [{"type": "password", "temporary": True, "value": password}]}, expected=(201,))
            user = self.api.request("GET", self.base + "/users/" + subject, self.bearer)
            require(user.get("id") == subject and user.get("username") == username and user.get("enabled") is True and
                    set(user.get("requiredActions", [])) == {"UPDATE_PASSWORD", "CONFIGURE_TOTP"}, "Onboarding readback failed")
            return {"subject": subject, "onboardingRequired": True}
        return self._run(operation, "onboard", subject, effect)

    def retire(self, operation, subject):
        require(str(uuid.UUID(subject)) == subject, "Exact subject UUID required")
        def effect():
            path = self.base + "/users/" + subject
            user = self.api.request("GET", path, self.bearer)
            require(user.get("id") == subject, "Foreign subject")
            self.api.request("PUT", path, self.bearer, {"enabled": False}, expected=(204,))
            self.api.request("POST", path + "/logout", self.bearer, expected=(204,))
            require(self.api.request("GET", path, self.bearer).get("enabled") is False, "Retirement readback failed")
            return {"subject": subject, "retired": True}
        return self._run(operation, "retire", subject, effect)

    def rotate_client(self, operation, client_id, custody):
        require(str(uuid.UUID(client_id)) == client_id, "Exact internal client UUID required")
        require(not Path(custody).exists(), "Custody output exists")
        private_directory(Path(custody).absolute().parent)
        def effect():
            path = self.base + "/clients/" + client_id
            client = self.api.request("GET", path, self.bearer)
            require(client.get("id") == client_id and client.get("publicClient") is False and
                    client.get("clientAuthenticatorType") == "client-secret", "Confidential client required")
            value = self.api.request("POST", path + "/client-secret", self.bearer).get("value")
            require(isinstance(value, str) and len(value) >= 16, "Missing rotated secret")
            private_create(custody, canonical({"clientId": client_id, "secret": value}))
            require(self.api.request("GET", path + "/client-secret", self.bearer).get("value") == value,
                    "Rotated credential readback failed")
            return {"clientId": client_id, "rotated": True}
        return self._run(operation, "rotate-client", client_id, effect)


    def retire_rotated_client(self, operation, client_id, replacement_secret):
        require(str(uuid.UUID(client_id)) == client_id, "Exact internal client UUID required")
        require(isinstance(replacement_secret, str) and len(replacement_secret) >= 16)
        def effect():
            path = self.base + "/clients/" + client_id + "/client-secret"
            require(self.api.request("GET", path, self.bearer).get("value") == replacement_secret,
                    "Replacement client credential changed")
            self.api.request("DELETE", path + "/rotated", self.bearer, expected=(204,))
            require(self.api.request("GET", path, self.bearer).get("value") == replacement_secret,
                    "Replacement client credential lost")
            return {"clientId": client_id, "previousSecretRetired": True}
        return self._run(operation, "retire-client-secret", client_id, effect)


class BaoLifecycle:
    def __init__(self, api, bearer, authority, journal):
        self.api, self.bearer, self.authority, self.journal = api, bearer, authority, journal

    def _lookup(self, token, policies):
        data = self.api.request("GET", "/v1/auth/token/lookup-self", token).get("data", {})
        require(set(data.get("policies", [])) == set(policies) and "root" not in policies and
                data.get("ttl", 0) > 0 and data.get("accessor"), "Exact scoped expiring Bao token required")
        return data

    def rotate(self, operation, operator_token, role, policies, custody, ttl=3600):
        actor = self.authority.authorize(self.bearer, "credentials:rotate")
        require(ID.fullmatch(role) and policies and all(ID.fullmatch(p) for p in policies) and
                "root" not in policies and type(ttl) is int and 60 <= ttl <= 86400, "Invalid scoped token request")
        require(not Path(custody).exists(), "Custody output exists")
        private_directory(Path(custody).absolute().parent)
        # Root is never accepted, even for this explicit operator command.
        operator = self.api.request("GET", "/v1/auth/token/lookup-self", operator_token).get("data", {})
        require("root" not in operator.get("policies", ["root"]) and operator.get("ttl", 0) > 0,
                "Scoped token administrator required")
        def effect():
            auth = self.api.request("POST", "/v1/auth/token/create/" + role, operator_token,
                                    {"policies": policies, "ttl": str(ttl) + "s", "renewable": False,
                                     "no_default_policy": "default" not in policies}).get("auth", {})
            token = auth.get("client_token")
            require(isinstance(token, str) and token, "Missing replacement token")
            # Persist even a rejected server response token for explicit revocation, not silent leakage.
            private_create(custody, canonical({"token": token, "accessor": auth.get("accessor"), "operation": operation}))
            observed = self._lookup(token, policies)
            require(observed["accessor"] == auth.get("accessor") and observed["ttl"] <= ttl and observed.get("orphan") is True,
                    "Replacement must have an independent scoped lease")
            return {"accessor": observed["accessor"], "rotated": True}
        return self.journal.execute(operation, {"action": "bao-rotate", "scope": self.api.origin,
                                               "actor": actor, "role": role, "policies": sorted(policies)}, effect)

    def retire(self, operation, old_token, replacement_token, policies):
        actor = self.authority.authorize(self.bearer, "credentials:rotate")
        old = self._lookup(old_token, policies)
        replacement = self._lookup(replacement_token, policies)
        require(old["accessor"] != replacement["accessor"] and replacement.get("orphan") is True,
                "Retirement requires a distinct independently leased replacement")
        def effect():
            self.api.request("POST", "/v1/auth/token/revoke-self", old_token, expected=(204,))
            self.api.request("GET", "/v1/auth/token/lookup-self", old_token, expected=(403,))
            # Replacement must be independent: parent-token revocation must not kill the new token.
            self._lookup(replacement_token, policies)
            return {"accessor": old["accessor"], "retired": True}
        return self.journal.execute(operation, {"action": "bao-retire", "scope": self.api.origin,
                                               "actor": actor, "accessor": old["accessor"],
                                               "replacement": replacement["accessor"]}, effect)

    def unseal(self, operation, binding, shares, verify_recovery):
        actor = self.authority.authorize(self.bearer, "bao:recover")
        # Callback must derive authority from verified generation import; caller flags are not authority.
        verify_recovery(binding)
        require(binding.get("endpoint") == self.api.origin and binding.get("leafSha256") == self.api.pin and
                binding.get("clusterId") and HASH.fullmatch(binding.get("snapshotReceiptSha256", "")),
                "Recovery target identity mismatch")
        require(isinstance(shares, list) and shares and all(isinstance(s, str) and 16 <= len(s) <= 4096 for s in shares) and
                len(set(shares)) == len(shares), "Distinct recovery shares required")
        state = self.api.request("GET", "/v1/sys/seal-status")
        require(state.get("initialized") is True and state.get("sealed") is True and state.get("progress") == 0 and
                state.get("cluster_id", binding["clusterId"]) == binding["clusterId"] and
                state.get("type") == "shamir" and type(state.get("t")) is int and state["t"] == len(shares),
                "Initialized sealed Shamir target with zero progress required")
        def effect():
            for index, share in enumerate(shares):
                # Revalidate local lineage before each effect; no stale recovery request reuse.
                verify_recovery(binding)
                state = self.api.request("POST", "/v1/sys/unseal", body={"key": share})
                require(state.get("initialized") is True and state.get("t") == len(shares), "Unseal state changed")
                if index < len(shares) - 1:
                    require(state.get("sealed") is True and state.get("progress") == index + 1, "Unexpected unseal progress")
            require(state.get("sealed") is False and state.get("cluster_id") == binding["clusterId"],
                    "Unsealed cluster identity mismatch; isolate target")
            return {"generation": binding["generation"], "unsealed": True, "publicActivation": False}
        return self.journal.execute(operation, {"action": "bao-recovery-unseal", "scope": self.api.origin,
                                               "actor": actor, "recovery": binding}, effect)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="owned mode-0600 operation request")
    args = parser.parse_args(argv)
    request = object_json(private_read(args.request))
    config = request["identity"]
    api = Https(config["origin"], config["caFile"], config["leafSha256"])
    bearer = read_token(config["bearerFile"])
    authority = IdentityAuthority(api, config["realm"], config["introspectionClient"],
                                  private_read(config["introspectionSecretFile"]).decode().strip(),
                                  config["audience"], config["allowedSubjects"])
    journal = Journal(request["journalDirectory"])
    operation, action = request["operation"], request["action"]
    identity = IdentityLifecycle(api, config["realm"], bearer, authority, journal)
    if action == "onboard":
        result = identity.onboard(operation, request["username"], request["custodyFile"])
    elif action == "retire-subject":
        result = identity.retire(operation, request["subject"])
    elif action == "rotate-client":
        result = identity.rotate_client(operation, request["clientId"], request["custodyFile"])
    elif action == "retire-client-secret":
        replacement = object_json(private_read(request["custodyFile"]))
        require(replacement.get("clientId") == request["clientId"], "Foreign client custody")
        result = identity.retire_rotated_client(operation, request["clientId"], replacement["secret"])
    elif action in ("rotate-bao-token", "retire-bao-token", "recovery-unseal"):
        config = request["bao"]
        bao = BaoLifecycle(Https(config["origin"], config["caFile"], config["leafSha256"]), bearer, authority, journal)
        if action == "rotate-bao-token":
            result = bao.rotate(operation, read_token(config["operatorTokenFile"]),
                                request["role"], request["policies"], request["custodyFile"], request.get("ttl", 3600))
        elif action == "retire-bao-token":
            result = bao.retire(operation, read_token(config["oldTokenFile"]),
                                read_token(config["replacementTokenFile"]), request["policies"])
        else:
            # Imported lazily; this verifier checks controller-owned generation records, not caller booleans.
            from identity_recovery import verify_recovery
            result = bao.unseal(operation, request["binding"],
                                object_json(private_read(config["sharesFile"]))["shares"], verify_recovery)
    else:
        raise Refused("Unknown identity/secret action")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        # No response body, exception text, token, password or share reaches stdout/stderr.
        print("Identity/secret operation failed; inspect private journal; do not automatically retry", file=sys.stderr)
        sys.exit(1)
