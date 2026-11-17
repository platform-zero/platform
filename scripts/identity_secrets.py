#!/usr/bin/env python3
"""Explicit scoped identity/secret operations. Never imported by a daemon boot hook.

Only private files carry bearer credentials or recovery shares. Mutations are intent
journalled before transport, never retried, and require a fresh operation ID. A lost
acknowledgement retains uncertainty; it is not permission to repeat an operation.
"""
if not __debug__:
    raise SystemExit("Optimized Python is prohibited")
import argparse
import base64
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

    def request(self, method, path, token=None, body=None, form=None, expected=(200,), array=False):
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
            if not raw:
                require(not array, "Missing JSON array response")
                return {}
            if array:
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        require(key not in result, "Duplicate JSON key")
                        result[key] = value
                    return result
                value = json.loads(raw, object_pairs_hook=unique)
                require(isinstance(value, list) and len(value) <= 10000, "Bounded JSON array required")
                return value
            return object_json(raw)
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
    def __init__(self, api, realm, client, client_secret, audience, allowed_subjects, generation, native_api):
        require(ID.fullmatch(realm) and ID.fullmatch(client) and audience == "controller" and allowed_subjects and
                isinstance(generation, str) and re.fullmatch(r"q-[a-f0-9]{12}", generation) and
                len(set(allowed_subjects)) == len(allowed_subjects) and
                all(isinstance(subject, str) and str(uuid.UUID(subject)) == subject for subject in allowed_subjects),
                "Exact original owner UUID and target/source generation required")
        self.api, self.native, self.realm, self.client = api, native_api, realm, client
        self.secret, self.audience, self.subjects, self.generation = client_secret, audience, set(allowed_subjects), generation

    def authorize(self, bearer, scope, now=None):
        result = self.api.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token/introspect",
                                  form={"token": bearer, "client_id": self.client, "client_secret": self.secret})
        audience = result.get("aud", [])
        if isinstance(audience, str):
            audience = [audience]
        expires = result.get("exp")
        require(result.get("active") is True and result.get("iss") == self.api.origin + f"/realms/{self.realm}" and
                result.get("sub") in self.subjects and self.audience in audience and
                result.get("azp") == "identity-controller" and result.get("p0v3_generation") == self.generation and
                type(expires) is int and expires > (time.time() if now is None else now) and
                scope in result.get("scope", "").split(), "Scoped operator identity denied")
        # Native realm authorization is independent of self-asserted OAuth `scope`.
        # The ORIGINAL pinned owner UUID is read back at the private admin endpoint,
        # which itself demands an actual realm-management view-users role in the JWT.
        original = self.native.request("GET", f"/admin/realms/{self.realm}/users/{result['sub']}", bearer)
        require(original.get("id") == result["sub"] and original.get("username") == "owner" and
                original.get("enabled") is True, "Original owner/native role readback denied")
        return result["sub"]


class OperatorPkce:
    """One-time, browser-mediated original-owner OAuth; no direct password grant.

    The operator navigates a real Keycloak UI with password+TOTP. A fixed, private
    start-site callback records only the returned code/state into protected custody;
    the controller explicitly redeems it once. Neither grant nor verifier is daemon input.
    """
    CLIENT = "identity-controller"
    REDIRECT = "https://start.datamancy.net/identity/operator/callback"

    def __init__(self, authority, journal):
        self.authority, self.journal = authority, journal
        require(authority.api.origin == "https://auth.datamancy.net", "Canonical issuer required")

    def prepare(self, operation, custody):
        require(not Path(custody).exists(), "Operator verifier custody already exists")
        private_directory(Path(custody).absolute().parent)
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        params = urllib.parse.urlencode({"client_id": self.CLIENT, "redirect_uri": self.REDIRECT,
                                         "response_type": "code", "scope": "openid", "state": state,
                                         "code_challenge": challenge, "code_challenge_method": "S256"})
        def effect():
            private_create(custody, canonical({"generation": self.authority.generation,
                                               "state": state, "verifier": verifier,
                                               "created": int(time.time()), "redirect": self.REDIRECT}))
            return {"authorizationUrl": self.authority.api.origin + "/realms/p0v3/protocol/openid-connect/auth?" + params,
                    "generation": self.authority.generation, "browserMfaRequired": True}
        return self.journal.execute(operation, {"action": "identity-operator-pkce-prepare",
                                               "scope": self.authority.api.origin + "/operator",
                                               "generation": self.authority.generation}, effect)

    def redeem(self, operation, redirect_url, custody, token_custody):
        prepared = object_json(private_read(custody))
        require(prepared.get("generation") == self.authority.generation and
                prepared.get("redirect") == self.REDIRECT and
                type(prepared.get("created")) is int and
                int(time.time()) - prepared["created"] in range(0, 301) and
                not Path(token_custody).exists(), "Fresh source/target operator PKCE proof required")
        private_directory(Path(token_custody).absolute().parent)
        redirect = urllib.parse.urlsplit(redirect_url)
        require(redirect.scheme == "https" and redirect.netloc == "start.datamancy.net" and
                redirect.path == "/identity/operator/callback" and not redirect.fragment and
                len(redirect.query) <= 8192, "Fixed operator callback required")
        parameters = urllib.parse.parse_qs(redirect.query, strict_parsing=True)
        require(set(parameters) == {"code", "state"} and len(parameters["code"]) == 1 and
                len(parameters["state"]) == 1 and
                16 <= len(parameters["code"][0]) <= 4096 and
                secrets.compare_digest(parameters["state"][0], prepared["state"]),
                "Unsolicited or ambiguous operator callback")
        code = parameters["code"][0]
        def effect():
            response = self.authority.api.request("POST", "/realms/p0v3/protocol/openid-connect/token",
                form={"grant_type": "authorization_code", "client_id": self.CLIENT,
                      "code": code, "redirect_uri": self.REDIRECT,
                      "code_verifier": prepared["verifier"]})
            token = response.get("access_token")
            require(response.get("token_type") == "Bearer" and type(response.get("expires_in")) is int and
                    response["expires_in"] in range(1, 301) and isinstance(token, str) and len(token) >= 24,
                    "No fresh scoped owner code grant")
            private_create(token_custody, canonical({"token": token, "generation": self.authority.generation}))
            for scope in ("identity:manage", "bao:recover", "credentials:rotate"):
                self.authority.authorize(token, scope)
            return {"generation": self.authority.generation, "operatorAuthorized": True,
                    "tokenSha256": digest(token.encode())}
        return self.journal.execute(operation, {"action": "identity-operator-pkce-redeem",
                                               "scope": self.authority.api.origin + "/operator",
                                               "generation": self.authority.generation,
                                               "codeSha256": digest(code.encode())}, effect)


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


    def adopt_recovered_generation(self, operation, binding, verify_recovery):
        """Feature-owned cold identity adoption. Only imported target Keycloak mappers change;
        original user/agent IDs and passwords remain in the recovered DB. No realm re-import.
        """
        actor = self.authority.authorize(self.bearer, "identity:manage")
        verified = verify_recovery(binding)
        require(isinstance(verified, dict) and verified.get("generation") == binding.get("generation") and
                verified.get("sourceGeneration") == binding.get("sourceGeneration") and
                verified.get("publicActivation") is False, "Recovered identity lineage differs from source")
        old = binding.get("sourceGeneration")
        new = binding.get("generation")
        require(isinstance(old, str) and isinstance(new, str) and old != new and
                re.fullmatch(r"q-[a-f0-9]{12}", old) and re.fullmatch(r"q-[a-f0-9]{12}", new) and
                self.authority.generation == old,
                "Only the original source-generation owner may adopt a distinct target")
        mappers = binding.get("clientMappers")
        require(isinstance(mappers, dict) and set(mappers) in (
                    {"keykeeper-human", "keykeeper-agent"},
                    {"keykeeper-human", "keykeeper-agent", "managed-lane-agent"},
                    {"keykeeper-human", "keykeeper-agent", "managed-lane-agent", "identity-controller"},
                    {"keykeeper-human", "keykeeper-agent", "managed-lane-agent", "identity-controller", "managed-lane-reader"}) and
                all(isinstance(value, dict) and set(value) == {"clientId", "mapperId"} and
                    all(isinstance(item, str) and str(uuid.UUID(item)) == item for item in value.values())
                    for value in mappers.values()),
                "Pinned native mapper IDs required")
        subject = binding.get("agentSubject")
        require(isinstance(subject, str) and str(uuid.UUID(subject)) == subject, "Original agent subject required")
        subjects = {"keykeeper-agent": subject}
        if "managed-lane-agent" in mappers:
            lane_subject = binding.get("managedLaneAgentSubject")
            require(isinstance(lane_subject, str) and str(uuid.UUID(lane_subject)) == lane_subject and
                    lane_subject != subject, "Distinct lane agent subject required")
            subjects["managed-lane-agent"] = lane_subject
        if "managed-lane-reader" in mappers:
            reader_subject = binding.get("managedLaneReaderSubject")
            require(isinstance(reader_subject, str) and str(uuid.UUID(reader_subject)) == reader_subject and
                    reader_subject not in subjects.values(), "Separate original native reader UUID required")
            subjects["managed-lane-reader"] = reader_subject
        if "identity-controller" in mappers:
            owner_subject = binding.get("ownerSubject")
            require(isinstance(owner_subject, str) and str(uuid.UUID(owner_subject)) == owner_subject and
                    owner_subject not in subjects.values() and owner_subject in self.authority.subjects,
                    "Original approved operator subject required")
            owner = self.api.request("GET", self.base + "/users/" + owner_subject, self.bearer)
            require(owner.get("id") == owner_subject and owner.get("username") == "owner" and
                    owner.get("enabled") is True, "Original owner native account changed")
        for client_name, original_subject in subjects.items():
            original = self.api.request("GET", self.base + "/users/" + original_subject, self.bearer)
            require(original.get("id") == original_subject and original.get("serviceAccountClientId") == client_name and
                    original.get("enabled") is True, "Original service-account principal changed")
        models = []
        for name in sorted(mappers):
            ids = mappers[name]
            client = self.api.request("GET", self.base + "/clients/" + ids["clientId"], self.bearer)
            require(client.get("id") == ids["clientId"] and client.get("clientId") == name and
                    client.get("enabled") is True, "Foreign OIDC client")
            path = self.base + "/clients/" + ids["clientId"] + "/protocol-mappers/models/" + ids["mapperId"]
            model = self.api.request("GET", path, self.bearer)
            config = model.get("config", {})
            require(model.get("id") == ids["mapperId"] and model.get("name") == (
                        "identity-generation" if name == "identity-controller" else "keykeeper-generation") and
                    model.get("protocolMapper") == "oidc-hardcoded-claim-mapper" and
                    config.get("claim.name") == "p0v3_generation" and config.get("claim.value") == old and
                    config.get("access.token.claim") == "true", "Recovered mapper did not retain source generation")
            models.append((path, model))
        def effect():
            for path, model in models:
                updated = dict(model, config=dict(model["config"], **{"claim.value": new}))
                self.api.request("PUT", path, self.bearer, updated, expected=(204,))
                observed = self.api.request("GET", path, self.bearer)
                require(observed.get("config", {}).get("claim.value") == new and
                        observed.get("id") == model["id"], "Target generation mapper was not adopted")
            for client_name, original_subject in subjects.items():
                restored = self.api.request("GET", self.base + "/users/" + original_subject, self.bearer)
                require(restored.get("id") == original_subject and restored.get("enabled") is True and
                        restored.get("serviceAccountClientId") == client_name,
                        "Principal changed during isolated adoption")
            # Invalidate all original cloned sessions only AFTER both mappers are adopted.
            # The administrator's own session is invalidated too; no later admin call is permitted.
            self.api.request("POST", self.base + "/logout", self.bearer, expected=(204,))
            return {"generation": new, "sourceGeneration": old, "agentSubject": subject,
                    "managedLaneAgentSubject": subjects.get("managed-lane-agent"),
                    "managedLaneReaderSubject": subjects.get("managed-lane-reader"),
                    "originalPrincipalPreserved": True, "priorSessionsRevoked": True, "publicActivation": False}
        return self.journal.execute(operation, {"action": "adopt-identity-generation", "scope": self.api.origin + self.base,
                                               "actor": actor, "sourceGeneration": old, "generation": new,
                                               "agentSubject": subject,
                                               "managedLaneAgentSubject": subjects.get("managed-lane-agent"),
                                               "managedLaneReaderSubject": subjects.get("managed-lane-reader"),
                                               "mappers": {key: mappers[key] for key in sorted(mappers)}}, effect)

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
        require(isinstance(data.get("policies"), list) and set(data["policies"]) == set(policies) and
                "root" not in policies and type(data.get("ttl")) is int and data["ttl"] > 0 and
                isinstance(data.get("accessor"), str) and data["accessor"],
                "Exact scoped expiring Bao token required")
        return data

    def rotate(self, operation, operator_token, role, policies, custody, ttl=86400):
        actor = self.authority.authorize(self.bearer, "credentials:rotate")
        require(role == "keeper" and policies == ["keykeeper"] and
                type(ttl) is int and 43200 <= ttl <= 86400,
                "Scoped keeper lease must outlive the eight-hour protected backup budget")
        require(not Path(custody).exists(), "Custody output exists")
        private_directory(Path(custody).absolute().parent)
        # The original or restored periodic issuer may mint the fixed role; root never may.
        operator = self._lookup(operator_token, ["keykeeper-issuer"])
        require(operator.get("orphan") is True and operator.get("period") == 86400 and
                operator.get("renewable") is True, "Live periodic issuer required")
        def effect():
            auth = self.api.request("POST", "/v1/auth/token/create/" + role, operator_token,
                                    {"policies": policies, "ttl": str(ttl) + "s", "renewable": False,
                                     "no_default_policy": "default" not in policies}).get("auth", {})
            token = auth.get("client_token")
            require(isinstance(token, str) and token, "Missing replacement token")
            # Persist even a rejected server response token for explicit revocation, not silent leakage.
            private_create(custody, canonical({"token": token, "accessor": auth.get("accessor"), "operation": operation}))
            observed = self._lookup(token, policies)
            require(observed["accessor"] == auth.get("accessor") and 36000 <= observed["ttl"] <= ttl and
                    observed.get("orphan") is True,
                    "Replacement must have a backup-budget-safe independent scoped lease")
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

    def initialize(self, operation, binding, custody, verify_install, shares=3, threshold=2):
        actor = self.authority.authorize(self.bearer, "bao:recover")
        proof = verify_install(binding)
        require(isinstance(proof, dict) and proof.get("generation") == binding.get("generation") and
                proof.get("member") == binding.get("member") and proof.get("publicActivation") is False,
                "Unpinned first-install Bao identity")
        require(self.authority.generation == binding.get("generation") and
                binding.get("endpoint") == self.api.origin and binding.get("leafSha256") == self.api.pin and
                type(shares) is int and type(threshold) is int and 2 <= threshold <= shares <= 10,
                "Exact install TLS and Shamir threshold required")
        require(not Path(custody).exists(), "Existing root custody; never reinitialize")
        private_directory(Path(custody).absolute().parent)
        status = self.api.request("GET", "/v1/sys/seal-status")
        require(status.get("initialized") is False and status.get("sealed") is True,
                "Only a genuinely uninitialized sealed Bao may be initialized")
        def effect():
            answer = self.api.request("POST", "/v1/sys/init", body={"secret_shares": shares,
                                                                       "secret_threshold": threshold})
            keys = answer.get("keys_base64")
            root = answer.get("root_token")
            require(isinstance(root, str) and len(root) >= 16 and isinstance(keys, list) and
                    len(keys) == shares and len(set(keys)) == shares and
                    all(isinstance(key, str) and len(key) >= 16 for key in keys),
                    "Bao initialization returned invalid private custody")
            state = self.api.request("GET", "/v1/sys/seal-status")
            require(state.get("initialized") is True and state.get("sealed") is True and
                    state.get("progress") == 0 and state.get("type") == "shamir" and
                    state.get("t") == threshold and isinstance(state.get("cluster_id"), str) and
                    ID.fullmatch(state["cluster_id"]), "Initialized Bao readback changed")
            private_create(custody, canonical({"token": root, "shares": keys, "clusterId": state["cluster_id"],
                                               "generation": binding["generation"], "threshold": threshold}))
            return {"generation": binding["generation"], "clusterId": state["cluster_id"],
                    "threshold": threshold, "initializedSealed": True, "publicActivation": False}
        return self.journal.execute(operation, {"action": "bao-initialize", "scope": self.api.origin,
                                               "actor": actor, "generation": binding["generation"],
                                               "member": binding["member"], "threshold": threshold,
                                               "shares": shares}, effect)

    def bootstrap_keykeeper(self, operation, binding, root_token, issuer_custody, recovery_custody, verify_install):
        """First install only: genuine KV-v2 mount, least-privilege policies and role.
        This operator-only root operation precedes explicit root retirement; neither the
        initial root nor issuer token is supplied to any daemon input.
        """
        actor = self.authority.authorize(self.bearer, "bao:recover")
        proof = verify_install(binding)
        require(isinstance(proof, dict) and proof.get("generation") == binding.get("generation") and
                proof.get("member") == binding.get("member") and proof.get("publicActivation") is False and
                self.authority.generation == binding.get("generation") and
                self.api.origin == binding.get("endpoint") and self.api.pin == binding.get("leafSha256"),
                "Keykeeper bootstrap requires the exact first-install Bao member")
        require(not Path(issuer_custody).exists() and not Path(recovery_custody).exists() and
                issuer_custody != recovery_custody, "Existing issuer/recovery custody; bootstrap cannot replay")
        private_directory(Path(issuer_custody).absolute().parent)
        private_directory(Path(recovery_custody).absolute().parent)
        state = self.api.request("GET", "/v1/sys/seal-status")
        require(state.get("initialized") is True and state.get("sealed") is False and
                state.get("cluster_id") == binding.get("clusterId"), "Foreign or sealed keykeeper bootstrap")
        mounts = self.api.request("GET", "/v1/sys/mounts", root_token).get("data", {})
        require(isinstance(mounts, dict) and mounts.get("sys/", {}).get("type") == "system" and
                "keykeeper/" not in mounts, "Original KV mount already exists or mounts unavailable")
        lookup = self.api.request("GET", "/v1/auth/token/lookup-self", root_token).get("data", {})
        require("root" in lookup.get("policies", []) and lookup.get("accessor"), "Initial root required only for bootstrap")
        keeper_policy = ('path "keykeeper/data/*" { capabilities = ["create", "read", "update"] }\n'
                         'path "keykeeper/metadata/*" { capabilities = ["list", "read"] }\n'
                         'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
                         'path "auth/token/revoke-self" { capabilities = ["update"] }\n')
        issuer_policy = ('path "auth/token/create/keeper" { capabilities = ["update"] }\n'
                         'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
                         'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
                         'path "auth/token/renew-self" { capabilities = ["update"] }\n')
        def effect():
            self.api.request("POST", "/v1/sys/mounts/keykeeper", root_token,
                             {"type": "kv", "options": {"version": "2"}}, expected=(204,))
            self.api.request("PUT", "/v1/sys/policies/acl/keykeeper", root_token,
                             {"policy": keeper_policy}, expected=(204,))
            self.api.request("PUT", "/v1/sys/policies/acl/keykeeper-issuer", root_token,
                             {"policy": issuer_policy}, expected=(204,))
            self.api.request("POST", "/v1/auth/token/roles/keeper", root_token,
                             {"allowed_policies": ["keykeeper"], "disallowed_policies": ["root"],
                              "orphan": True, "renewable": False, "token_explicit_max_ttl": "24h"}, expected=(204,))
            self.api.request("POST", "/v1/sys/auth/approle", root_token, {"type": "approle"}, expected=(204,))
            self.api.request("POST", "/v1/auth/approle/role/keeper-issuer", root_token,
                             {"token_policies": ["keykeeper-issuer"], "token_no_default_policy": True,
                              "token_period": "24h", "token_type": "service", "bind_secret_id": True,
                              "secret_id_num_uses": 0, "secret_id_ttl": "0s"}, expected=(204,))
            role_id = self.api.request("GET", "/v1/auth/approle/role/keeper-issuer/role-id", root_token).get("data", {})
            secret_id = self.api.request("POST", "/v1/auth/approle/role/keeper-issuer/secret-id", root_token).get("data", {})
            require(isinstance(role_id.get("role_id"), str) and len(role_id["role_id"]) >= 16 and
                    isinstance(secret_id.get("secret_id"), str) and len(secret_id["secret_id"]) >= 16 and
                    isinstance(secret_id.get("secret_id_accessor"), str), "Protected recovery role custody missing")
            private_create(recovery_custody, canonical({"generation": binding["generation"],
                "clusterId": binding["clusterId"], "roleId": role_id["role_id"],
                "secretId": secret_id["secret_id"], "secretAccessor": secret_id["secret_id_accessor"]}))
            result = self.api.request("POST", "/v1/auth/token/create", root_token,
                                      {"policies": ["keykeeper-issuer"], "no_default_policy": True,
                                       "orphan": True, "renewable": True,
                                       "period": "24h", "ttl": "24h"}).get("auth", {})
            token = result.get("client_token")
            require(isinstance(token, str) and len(token) >= 16 and result.get("accessor"),
                    "Scoped Keykeeper issuer token missing")
            private_create(issuer_custody, canonical({"token": token, "accessor": result["accessor"],
                                                      "generation": binding["generation"]}))
            issuer = self._lookup(token, ["keykeeper-issuer"])
            require(issuer["accessor"] == result["accessor"] and issuer.get("orphan") is True and
                    issuer["ttl"] in range(36000, 86401) and issuer.get("renewable") is True and
                    issuer.get("period") == 86400,
                    "Issuer token is not a renewable scoped orphan")
            mounted = self.api.request("GET", "/v1/sys/mounts", root_token).get("data", {})
            policy = self.api.request("GET", "/v1/sys/policies/acl/keykeeper", root_token).get("data", {})
            issuer_acl = self.api.request("GET", "/v1/sys/policies/acl/keykeeper-issuer", root_token).get("data", {})
            role = self.api.request("GET", "/v1/auth/token/roles/keeper", root_token).get("data", {})
            recovery_role = self.api.request("GET", "/v1/auth/approle/role/keeper-issuer", root_token).get("data", {})
            recovery_id = self.api.request("GET", "/v1/auth/approle/role/keeper-issuer/role-id", root_token).get("data", {})
            require(mounted.get("keykeeper/", {}).get("type") == "kv" and
                    mounted["keykeeper/"].get("options", {}).get("version") == "2" and
                    policy.get("policy") == keeper_policy and issuer_acl.get("policy") == issuer_policy and
                    role.get("allowed_policies") == ["keykeeper"] and role.get("orphan") is True and
                    recovery_role.get("token_policies") == ["keykeeper-issuer"] and
                    recovery_role.get("bind_secret_id") is True and
                    type(recovery_role.get("secret_id_num_uses")) is int and recovery_role["secret_id_num_uses"] == 0 and
                    type(recovery_role.get("secret_id_ttl")) is int and recovery_role["secret_id_ttl"] == 0 and
                    recovery_role.get("token_no_default_policy") is True and
                    recovery_role.get("token_period") == 86400 and
                    recovery_id.get("role_id") == role_id["role_id"],
                    "Keykeeper KV-v2/policy/role/recovery readback failed")
            return {"generation": binding["generation"], "clusterId": binding["clusterId"],
                    "kvMount": "keykeeper", "recoveryAccessorSha256": digest(secret_id["secret_id_accessor"].encode()),
                    "issuerAccessorSha256": digest(issuer["accessor"].encode()),
                    "publicActivation": False}
        return self.journal.execute(operation, {"action": "bao-bootstrap-keykeeper", "scope": self.api.origin,
                                               "actor": actor, "generation": binding["generation"],
                                               "clusterId": binding["clusterId"]}, effect)

    def recover_issuer(self, operation, binding, recovery_custody, target_issuer_custody, verify_recovery):
        """An aged cold snapshot cannot reuse an expired source issuer lease. Login with the
        ORIGINAL protected AppRole secret only after imported target isolation and a fresh
        TARGET-generation owner PKCE bearer; mint a distinct scoped issuer, never a root.
        """
        actor = self.authority.authorize(self.bearer, "bao:recover")
        proof = verify_recovery(binding)
        require(isinstance(proof, dict) and proof.get("generation") == binding.get("generation") and
                proof.get("sourceGeneration") == binding.get("sourceGeneration") and
                proof.get("publicActivation") is False and self.authority.generation == binding.get("generation") and
                binding.get("endpoint") == self.api.origin and binding.get("leafSha256") == self.api.pin and
                HASH.fullmatch(binding.get("sourceRecoveryCustodySha256", "")),
                "Reissuing an issuer requires isolated source-bound cold recovery")
        raw = private_read(recovery_custody)
        require(digest(raw) == binding["sourceRecoveryCustodySha256"],
                "Original anchored AppRole custody changed")
        original = object_json(raw)
        require(original.get("generation") == binding.get("sourceGeneration") and
                original.get("clusterId") == binding.get("clusterId") and
                all(isinstance(original.get(key), str) and len(original[key]) >= 16
                    for key in ("roleId", "secretId", "secretAccessor")) and
                not Path(target_issuer_custody).exists() and
                Path(recovery_custody).absolute() != Path(target_issuer_custody).absolute(),
                "Recovered issuer must not overwrite original scoped authority")
        private_directory(Path(target_issuer_custody).absolute().parent)
        state = self.api.request("GET", "/v1/sys/seal-status")
        require(state.get("initialized") is True and state.get("sealed") is False and
                state.get("cluster_id") == original["clusterId"], "Recovered Bao cluster is foreign or sealed")
        def effect():
            # Read the controller's imported evidence again immediately before the effect.
            verify_recovery(binding)
            grant = self.api.request("POST", "/v1/auth/approle/login", body={
                "role_id": original["roleId"], "secret_id": original["secretId"]}).get("auth", {})
            token = grant.get("client_token")
            require(isinstance(token, str) and len(token) >= 16 and grant.get("accessor"),
                    "No native recovered scoped issuer")
            private_create(target_issuer_custody, canonical({"token": token, "accessor": grant["accessor"],
                                                              "generation": binding["generation"]}))
            observed = self._lookup(token, ["keykeeper-issuer"])
            require(observed["accessor"] == grant["accessor"] and observed.get("orphan") is True and
                    observed.get("period") == 86400 and observed.get("renewable") is True and
                    observed["ttl"] in range(36000, 86401), "Recovered issuer is not independent and periodic")
            return {"generation": binding["generation"], "sourceGeneration": binding["sourceGeneration"],
                    "clusterId": binding["clusterId"], "issuerAccessorSha256": digest(observed["accessor"].encode()),
                    "publicActivation": False}
        return self.journal.execute(operation, {"action": "bao-recover-keykeeper-issuer",
                                               "scope": self.api.origin, "actor": actor,
                                               "sourceGeneration": binding["sourceGeneration"],
                                               "generation": binding["generation"],
                                               "clusterId": binding["clusterId"],
                                               "sourceRecoveryCustodySha256": digest(raw)}, effect)

    def renew_issuer(self, operation, issuer_token, cluster_id):
        actor = self.authority.authorize(self.bearer, "bao:recover")
        status = self.api.request("GET", "/v1/sys/seal-status")
        require(status.get("initialized") is True and status.get("sealed") is False and
                status.get("cluster_id") == cluster_id, "Cannot renew issuer on a sealed/foreign cluster")
        before = self._lookup(issuer_token, ["keykeeper-issuer"])
        require(before.get("orphan") is True and before.get("renewable") is True and
                before.get("period") == 86400 and before.get("ttl") in range(1, 86401),
                "Only live periodic scoped issuer can renew itself")
        def effect():
            self.api.request("POST", "/v1/auth/token/renew-self", issuer_token, {"increment": "24h"})
            after = self._lookup(issuer_token, ["keykeeper-issuer"])
            require(after.get("accessor") == before.get("accessor") and after.get("renewable") is True and
                    after.get("orphan") is True and after.get("period") == 86400 and
                    after.get("ttl") in range(36000, 86401),
                    "Renewal must preserve the same scoped issuer")
            return {"issuerAccessorSha256": digest(after["accessor"].encode()), "renewed": True,
                    "clusterId": cluster_id}
        return self.journal.execute(operation, {"action": "bao-renew-keykeeper-issuer", "scope": self.api.origin,
                                               "actor": actor, "clusterId": cluster_id,
                                               "issuerAccessorSha256": digest(before["accessor"].encode())}, effect)

    def retire_initial_root(self, operation, root_token, cluster_id):
        actor = self.authority.authorize(self.bearer, "bao:recover")
        require(isinstance(cluster_id, str) and ID.fullmatch(cluster_id), "Exact Bao cluster required")
        state = self.api.request("GET", "/v1/sys/seal-status")
        require(state.get("initialized") is True and state.get("sealed") is False and
                state.get("cluster_id") == cluster_id, "Cannot retire root for foreign or sealed cluster")
        identity = self.api.request("GET", "/v1/auth/token/lookup-self", root_token).get("data", {})
        require("root" in identity.get("policies", []) and identity.get("accessor"), "Initial root token required")
        with self.journal.locked():
            require(any(record.get("phase") == "complete" and
                        record.get("binding", {}).get("action") == "bao-bootstrap-keykeeper" and
                        record["binding"].get("scope") == self.api.origin and
                        record["binding"].get("clusterId") == cluster_id for record in self.journal.records),
                    "Read back scoped Bao KV/token bootstrap before irreversible root retirement")
        def effect():
            self.api.request("POST", "/v1/auth/token/revoke-self", root_token, expected=(204,))
            self.api.request("GET", "/v1/auth/token/lookup-self", root_token, expected=(403,))
            return {"clusterId": cluster_id, "rootRetired": True}
        return self.journal.execute(operation, {"action": "bao-root-retirement", "scope": self.api.origin,
                                               "actor": actor, "clusterId": cluster_id,
                                               "accessorSha256": digest(identity["accessor"].encode())}, effect)

    def unseal(self, operation, binding, shares, verify_recovery, mode="recovery"):
        require(mode in ("recovery", "install"))
        actor = self.authority.authorize(self.bearer, "bao:recover")
        # Callback must derive authority from verified generation import; caller flags are not authority.
        verify_recovery(binding)
        require(self.authority.generation == binding.get("generation") and
                binding.get("endpoint") == self.api.origin and binding.get("leafSha256") == self.api.pin and
                isinstance(binding.get("clusterId"), str) and ID.fullmatch(binding["clusterId"]) and
                HASH.fullmatch(binding.get("snapshotReceiptSha256", "")) and
                isinstance(binding.get("generation"), str) and re.fullmatch(r"q-[a-f0-9]{12}", binding["generation"]),
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
        # Explicit public lineage only: never journal future optional fields containing
        # recovery shares, bootstrap keys or a root/recovery token.
        lineage = {name: binding[name] for name in ("generation", "clusterId", "snapshotReceiptSha256", "leafSha256")}
        return self.journal.execute(operation, {"action": "bao-recovery-unseal" if mode == "recovery" else "bao-install-unseal",
                                               "scope": self.api.origin,
                                               "actor": actor, "recovery": lineage}, effect)


def identity_admin_https(config):
    """Private Keycloak admin is always independently pinned, including for Bao actions.

    The public issuer handles introspection/PKCE only; a Bao API origin must never be
    used to read `/admin/realms/p0v3/users/{uuid}`. There is no fallback to Bao.
    """
    require(config.get("origin") == "https://keycloak:8443" and config.get("realm") == "p0v3",
            "Separate original private Keycloak admin transport and realm required")
    return Https(config["origin"], config["caFile"], config["leafSha256"])


def bao_https(config):
    require(config.get("origin") == "https://bao:8200", "Separate private Bao API origin required")
    return Https(config["origin"], config["caFile"], config["leafSha256"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="owned mode-0600 operation request")
    args = parser.parse_args(argv)
    request = object_json(private_read(args.request))
    config = request["identity"]
    require(config["authorityOrigin"] == "https://auth.datamancy.net",
            "Public issuer introspection must be separately pinned")
    api = identity_admin_https(config)
    authority_api = Https(config["authorityOrigin"], config["authorityCaFile"], config["authorityLeafSha256"])
    operation, action = request["operation"], request["action"]
    bearer = None if action in ("prepare-operator-pkce", "redeem-operator-pkce") else read_token(config["bearerFile"])
    authority = IdentityAuthority(authority_api, config["realm"], config["introspectionClient"],
                                  private_read(config["introspectionSecretFile"]).decode().strip(),
                                  config["audience"], config["allowedSubjects"], config["generation"], api)
    journal = Journal(request["journalDirectory"])
    identity = IdentityLifecycle(api, config["realm"], bearer, authority, journal)
    if action == "prepare-operator-pkce":
        prepared = OperatorPkce(authority, journal).prepare(operation, request["custodyFile"])
        private_create(request["authorizationCustodyFile"], canonical(prepared))
        result = {"generation": authority.generation, "authorizationPrepared": True}
    elif action == "redeem-operator-pkce":
        result = OperatorPkce(authority, journal).redeem(operation, request["redirectUrl"],
                                                        request["custodyFile"], request["tokenCustodyFile"])
    elif action == "onboard":
        result = identity.onboard(operation, request["username"], request["custodyFile"])
    elif action == "retire-subject":
        result = identity.retire(operation, request["subject"])
    elif action == "rotate-client":
        result = identity.rotate_client(operation, request["clientId"], request["custodyFile"])
    elif action == "retire-client-secret":
        replacement = object_json(private_read(request["custodyFile"]))
        require(replacement.get("clientId") == request["clientId"], "Foreign client custody")
        result = identity.retire_rotated_client(operation, request["clientId"], replacement["secret"])
    elif action == "adopt-identity-generation":
        from identity_recovery import verify_recovery
        result = identity.adopt_recovered_generation(operation, request["binding"], verify_recovery)
    elif action in ("rotate-bao-token", "retire-bao-token", "retire-bao-root", "initialize-bao", "install-unseal",
                    "bootstrap-bao-keykeeper", "renew-bao-issuer", "recover-bao-issuer", "recovery-unseal"):
        config = request["bao"]
        bao = BaoLifecycle(bao_https(config), bearer, authority, journal)
        if action == "rotate-bao-token":
            result = bao.rotate(operation, read_token(config["operatorTokenFile"]),
                                request["role"], request["policies"], request["custodyFile"], request.get("ttl", 86400))
        elif action == "retire-bao-token":
            result = bao.retire(operation, read_token(config["oldTokenFile"]),
                                read_token(config["replacementTokenFile"]), request["policies"])
        elif action == "retire-bao-root":
            result = bao.retire_initial_root(operation, read_token(config["initialRootFile"]), request["clusterId"])
        elif action == "bootstrap-bao-keykeeper":
            from identity_recovery import verify_install
            result = bao.bootstrap_keykeeper(operation, request["binding"], read_token(config["initialRootFile"]),
                                             request["issuerCustodyFile"], request["recoveryCustodyFile"], verify_install)
        elif action == "renew-bao-issuer":
            result = bao.renew_issuer(operation, read_token(config["issuerCustodyFile"]), request["clusterId"])
        elif action == "recover-bao-issuer":
            from identity_recovery import verify_recovery
            result = bao.recover_issuer(operation, request["binding"], request["sourceRecoveryCustodyFile"],
                                        request["targetIssuerCustodyFile"], verify_recovery)
        elif action == "initialize-bao":
            from identity_recovery import verify_install
            result = bao.initialize(operation, request["binding"], request["custodyFile"], verify_install,
                                    request.get("shares", 3), request.get("threshold", 2))
        elif action == "install-unseal":
            from identity_recovery import verify_install
            binding = request["binding"]
            custody = object_json(private_read(config["initialRootFile"]))
            require(custody.get("generation") == binding.get("generation") and
                    custody.get("clusterId") == binding.get("clusterId") and
                    type(custody.get("threshold")) is int and
                    custody["threshold"] in range(2, len(custody.get("shares", [])) + 1),
                    "Foreign initialized Bao custody")
            result = bao.unseal(operation, binding, custody["shares"][:custody["threshold"]], verify_install, mode="install")
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
