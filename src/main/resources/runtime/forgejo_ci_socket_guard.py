#!/usr/bin/env python3
"""Fail-closed Docker-compatible rootless CI socket guard (no canonical Podman fallback).

Run as the dedicated worker UID in a private systemd service. The runner lives
in a separate rootless container with ONLY this socket mounted. Do not mount
/run/user/<uid>/podman/podman.sock, registration, or Platform inputs there.
Unrecognised Docker APIs fail closed; this is deliberately not a generic proxy.
"""
import hashlib
import http.client
import json
import os
import re
import select
import socket
import socketserver
import stat
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

UID = 784
MAX_REQUEST = 1_048_576
MAX_REPLY = 33_554_432
HASH = re.compile(r"[a-f0-9]{64}\Z")
CID = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"(?:/v[0-9]+\.[0-9]+)?(/.*)\Z")
# A Docker Config has execution inputs, not authority over host namespaces.
# Every authority-bearing HostConfig key must be explicitly reviewed here.
CREATE_FIELDS = frozenset({"Image", "Cmd", "Env", "User", "WorkingDir", "Labels",
    "AttachStdin", "AttachStdout", "AttachStderr", "OpenStdin", "StdinOnce", "Tty",
    "Hostname", "StopSignal", "HostConfig"})
HOST_FIELDS = frozenset({"NetworkMode", "Memory", "MemorySwap", "NanoCpus", "PidsLimit",
    "CapDrop", "SecurityOpt", "Privileged", "Binds", "Mounts", "PortBindings",
    "PublishAllPorts", "ReadonlyRootfs", "AutoRemove", "PidMode", "IpcMode",
    "UsernsMode", "UTSMode", "CgroupnsMode", "ShmSize", "LogConfig"})
SAFE_NAMESPACE = (None, "", "private")


def canonical(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def record(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


class UnixHttp(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout=45):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path
        self.backend_timeout = timeout

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.backend_timeout)
        self.sock.connect(self.socket_path)


class Guard(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, config):
        self.config = config
        self.state = Path(config["state"])
        self.socket_path = config["listen"]
        self.backend_path = config["backend"]
        self.image = config["image"]
        self.image_id = "sha256:" + config["imageId"]
        self.memory = config["memoryMiB"] * 1048576
        self.network = config["network"]
        self.ca_mount = config["caMount"]
        self.job_id = None
        self.requested = None
        self.exec_ids = set()
        self.started = False
        self.effect_lock = threading.RLock()
        for path in (self.state, Path(self.socket_path).parent):
            details = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != UID or details.st_mode & 0o077:
                raise ValueError("foreign or shared CI directory")
        raw = os.stat(self.backend_path, follow_symlinks=False)
        if not stat.S_ISSOCK(raw.st_mode) or raw.st_uid != UID:
            raise ValueError("foreign worker engine socket")
        if list(self.state.iterdir()):
            # An incomplete create/start/stop cannot be relabelled a fresh job.
            raise ValueError("existing CI effect must be reconciled by the original owner")
        if os.path.lexists(self.socket_path):
            raise ValueError("existing guard socket; never unlink an uncertain owner")
        self.verify_network()
        super().__init__(self.socket_path, Handler)
        os.chmod(self.socket_path, 0o600)

    def request(self, method, path, body=b"", headers=None):
        connection = UnixHttp(self.backend_path, timeout=1900 if
            "/wait" in path or "/logs" in path else 45)
        try:
            connection.request(method, path, body=body, headers=headers or {"Content-Type": "application/json"})
            reply = connection.getresponse()
            data = reply.read(MAX_REPLY + 1)
            if len(data) > MAX_REPLY:
                raise ValueError("unbounded worker engine reply")
            return reply.status, data, reply.getheaders()
        finally:
            connection.close()

    def verify_network(self):
        status, payload, _ = self.request("GET", "/v1.41/networks/" + self.network)
        if status != 200:
            raise ValueError("missing owned rootless CI network")
        details = canonical(payload)
        if (details.get("Name") != self.network or details.get("Internal") is not True or
                details.get("Driver") != "bridge" or details.get("Attachable") is True or
                details.get("Ingress") is True):
            raise ValueError("CI transport is not a dedicated internal rootless bridge")

    def stream_exec(self, target, body, peer):
        """Only a previously journalled exec ID may use Docker's hijacked stream."""
        worker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        worker.settimeout(45)
        worker.connect(self.backend_path)
        try:
            worker.sendall((f"POST {target} HTTP/1.1\r\nHost: localhost\r\n"
                            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                            "Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n").encode() + body)
            header = bytearray()
            while b"\r\n\r\n" not in header and len(header) <= 16384:
                block = worker.recv(4096)
                if not block:
                    raise ValueError("native CI exec stream missing")
                header.extend(block)
            if len(header) > 16384 or not header.startswith((b"HTTP/1.1 101 ", b"HTTP/1.1 200 ")):
                raise ValueError("native CI exec stream unacknowledged")
            peer.sendall(header)
            worker.setblocking(False)
            peer.setblocking(False)
            live = {worker, peer}
            sizes = {worker: 0, peer: 0}
            until = time.monotonic() + 1800
            while live:
                if time.monotonic() > until:
                    raise ValueError("CI exec stream timed out; keep native intent uncertain")
                ready, _, _ = select.select(list(live), [], [], 1)
                for source in ready:
                    try:
                        chunk = source.recv(65536)
                    except BlockingIOError:
                        continue
                    destination = peer if source is worker else worker
                    if not chunk:
                        live.remove(source)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    sizes[source] += len(chunk)
                    if sizes[source] > MAX_REPLY:
                        raise ValueError("CI exec output exceeded bound")
                    destination.settimeout(30)
                    destination.sendall(chunk)
                    destination.setblocking(False)
        finally:
            worker.close()

    def validate_create(self, entry):
        if not isinstance(entry, dict) or set(entry) - CREATE_FIELDS or "HostConfig" not in entry:
            raise ValueError("unsupported Docker Config field")
        host = entry["HostConfig"]
        if not isinstance(host, dict) or set(host) - HOST_FIELDS:
            raise ValueError("unsupported Docker HostConfig authority field")
        if (entry.get("Image") != self.image or entry.get("User") != "1000:1000" or
                entry.get("WorkingDir") not in (None, "", "/workspace") or
                entry.get("StopSignal") not in (None, "", "SIGTERM") or
                entry.get("Hostname") not in (None, "") and not
                    re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", entry["Hostname"]) or
                any(entry.get(key) not in (None, False) for key in
                    ("AttachStdin", "OpenStdin", "StdinOnce", "Tty")) or
                any(entry.get(key) not in (None, True) for key in
                    ("AttachStdout", "AttachStderr"))):
            raise ValueError("unsupported CI container process or TTY")
        cmd = entry.get("Cmd")
        if cmd is not None and (not isinstance(cmd, list) or len(cmd) not in range(1, 33) or
                any(not isinstance(arg, str) or len(arg) > 32768 or "\x00" in arg for arg in cmd)):
            raise ValueError("unbounded CI process command")
        labels = entry.get("Labels", {})
        if not isinstance(labels, dict) or len(labels) > 32 or any(
                not isinstance(key, str) or not isinstance(value, str) or
                not re.fullmatch(r"(?:com\.github\.actions|org\.forgejo\.actions)\.[a-z0-9.-]{1,96}", key) or
                len(value) > 4096 for key, value in labels.items()):
            raise ValueError("unreviewed OCI label")
        if (host.get("NetworkMode") != self.network or host.get("Memory") != self.memory or
                host.get("MemorySwap") != self.memory or host.get("NanoCpus") != 2_000_000_000 or
                host.get("PidsLimit") != 256 or host.get("CapDrop") != ["ALL"] or
                host.get("SecurityOpt") != ["no-new-privileges"] or
                host.get("Binds") != [self.ca_mount] or
                any(host.get(key) not in (None, [], {}, False) for key in
                    ("Privileged", "Mounts", "PortBindings", "PublishAllPorts",
                     "ReadonlyRootfs", "AutoRemove")) or
                any(host.get(key) not in SAFE_NAMESPACE for key in
                    ("PidMode", "IpcMode", "UsernsMode", "UTSMode", "CgroupnsMode")) or
                host.get("ShmSize") not in (None, 0, 67_108_864) or
                host.get("LogConfig") not in (None, {}, {"Type": "journald", "Config": {}})):
            raise ValueError("CI request contains unreviewed namespace/device/cap/network authority")
        self.validate_env(entry.get("Env", []))
        self.require_private_ca(entry.get("Env", []))

    @staticmethod
    def validate_env(env):
        if not isinstance(env, list) or len(env) > 128 or any(
                not isinstance(item, str) or len(item) > 8192 or "\x00" in item for item in env):
            raise ValueError("unbounded job environment")
        seen = set()
        for item in env:
            if "=" not in item:
                raise ValueError("invalid job environment")
            name, _, value = item.partition("=")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                raise ValueError("invalid CI environment name")
            upper = name.upper()
            if upper in seen:
                raise ValueError("duplicate CI environment name")
            seen.add(upper)
            # Forgejo's job-scoped checkout/artifact tokens never include the
            # host runner registration credential or an engine socket.
            if (upper in ("DOCKER_HOST", "CONTAINER_HOST", "FORGEJO_RUNNER_TOKEN",
                          "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") or
                    (upper.endswith("TOKEN") and upper not in
                     ("GITHUB_TOKEN", "GITEA_TOKEN", "ACTIONS_RUNTIME_TOKEN")) or
                    upper.endswith(("SECRET", "PASSWORD", "_KEY"))):
                raise ValueError("job environment exposes host capability")
            if upper == "ACTIONS_RESULTS_URL" and value != "https://forgejo.datamancy.net":
                raise ValueError("CI results transport left the private Forgejo origin")
            if (upper in ("ACTIONS_RUNTIME_URL", "GITHUB_SERVER_URL", "GITHUB_API_URL",
                          "GITEA_SERVER_URL", "GITEA_API_URL") and
                    not value.startswith("https://forgejo.datamancy.net/")):
                raise ValueError("CI job transport is not the private Forgejo origin")

    @staticmethod
    def require_private_ca(env):
        values = dict(item.split('=', 1) for item in env)
        trust = '/etc/ssl/certs/p0v3-ci-forgejo-ca.pem'
        if any(values.get(name) != trust for name in
               ('SSL_CERT_FILE', 'GIT_SSL_CAINFO', 'NODE_EXTRA_CA_CERTS', 'CURL_CA_BUNDLE')):
            raise ValueError('CI checkout/artifact transport has no pinned private CA')

    def inspect(self, cid):
        status, data, _ = self.request("GET", "/v1.41/containers/" + cid + "/json")
        if status != 200:
            raise ValueError("native container readback missing")
        detail = canonical(data)
        host = detail["HostConfig"]
        config = detail["Config"]
        network = detail["NetworkSettings"]
        endpoint = network["Networks"].get(self.network, {})
        expected = self.requested
        if expected is None:
            raise ValueError("no original bounded create request")
        if (detail["Id"] != cid or detail["Image"] != self.image_id or
                config.get("Image") != self.image or config.get("User") != "1000:1000" or
                host["NetworkMode"] != self.network or
                set(network["Networks"]) != {self.network} or
                host.get("Memory") != self.memory or host.get("MemorySwap") != self.memory or
                host.get("NanoCpus") != 2_000_000_000 or host.get("PidsLimit") != 256 or
                host.get("Privileged") is not False or host.get("CapDrop") != ["ALL"] or
                host.get("SecurityOpt") != ["no-new-privileges"] or
                host.get("PublishAllPorts") not in (None, False) or
                host.get("ReadonlyRootfs") not in (None, False) or
                host.get("AutoRemove") not in (None, False) or
                host.get("ShmSize") not in (0, 67_108_864) or
                host.get("OomKillDisable") not in (None, False) or
                host.get("LogConfig") not in (None, {}, {"Type": "journald", "Config": {}}) or
                host.get("Binds") != [self.ca_mount] or
                any(host.get(key) not in (None, [], {}, "") for key in
                    ("Devices", "DeviceRequests", "VolumesFrom", "Mounts", "CapAdd",
                     "GroupAdd", "Links", "ExtraHosts", "PortBindings", "Tmpfs", "Sysctls",
                     "Dns", "DnsOptions", "DnsSearch", "CgroupParent")) or
                any(host.get(key) not in SAFE_NAMESPACE for key in
                    ("PidMode", "IpcMode", "UsernsMode", "UTSMode", "CgroupnsMode")) or
                not isinstance(detail.get("Mounts"), list) or len(detail["Mounts"]) != 1 or
                detail["Mounts"][0].get("Source") != self.ca_mount.split(':')[0] or
                detail["Mounts"][0].get("Destination") != "/etc/ssl/certs/p0v3-ci-forgejo-ca.pem" or
                detail["Mounts"][0].get("RW") is not False or
                network.get("Ports") not in (None, {}) or
                endpoint.get("Aliases") not in (None, [], [self.network]) or
                endpoint.get("IPAMConfig") not in (None, {}) or
                endpoint.get("Links") not in (None, []) or
                endpoint.get("DriverOpts") not in (None, {})):
            raise ValueError("native namespace/device/cap/network authority differs from reviewed create")
        # Podman may add benign image-defined variables, but may not inject a
        # host socket path or host credential into the effective job process.
        self.validate_env(config.get("Env", []))
        self.require_private_ca(config.get("Env", []))
        return detail

    def verify_kernel(self, detail):
        """An inspect claim is not proof that the running payload is confined."""
        state = detail["State"]
        pid = state.get("Pid")
        if state.get("Running") is not True or not isinstance(pid, int) or pid <= 1:
            raise ValueError("CI payload is not a live native process")
        root = Path(f"/proc/{pid}")
        mappings = [list(map(int, line.split())) for line in (root / "uid_map").read_text().splitlines()]
        if (not mappings or any(len(row) != 3 or row[2] <= 0 or row[1] == 0 for row in mappings)):
            raise ValueError("CI payload has an unreviewed host UID map")
        mapped = [host + 1000 - inside for inside, host, length in mappings
                  if inside <= 1000 < inside + length]
        if (len(mapped) != 1 or not 2_949_120 <= mapped[0] < 3_014_656 or
                root.stat().st_uid != mapped[0]):
            raise ValueError("CI UID 1000 did not map into the dedicated subordinate range")
        for kind in ("user", "pid", "ipc", "uts", "mnt", "net"):
            if (root / "ns" / kind).stat().st_ino == Path("/proc/self/ns", kind).stat().st_ino:
                raise ValueError("CI payload shares a host namespace")
        fields = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines() if ":" in line)
        if (fields.get("Uid", "").split() != [str(mapped[0])] * 4 or
                fields.get("CapEff", "").strip() != "0000000000000000" or
                fields.get("NoNewPrivs", "").strip() != "1" or
                fields.get("Seccomp", "").strip() != "2"):
            raise ValueError("CI payload is missing kernel privilege/seccomp confinement")
        paths = [line.removeprefix("0::") for line in (root / "cgroup").read_text().splitlines()
                 if line.startswith("0::/")]
        if len(paths) != 1 or "user-784.slice" not in paths[0].split("/"):
            raise ValueError("CI payload escaped dedicated rootless cgroup")
        cgroup_root = Path("/sys/fs/cgroup").resolve()
        cgroup = (cgroup_root / paths[0].lstrip("/")).resolve()
        if cgroup_root not in cgroup.parents:
            raise ValueError("foreign kernel CI cgroup path")
        if ((cgroup / "memory.max").read_text().strip() != str(self.memory) or
                (cgroup / "memory.swap.max").read_text().strip() != "0" or
                (cgroup / "pids.max").read_text().strip() != "256"):
            raise ValueError("CI payload kernel memory/swap/PID limits differ")
        cpu = (cgroup / "cpu.max").read_text().split()
        if (len(cpu) != 2 or not cpu[0].isdigit() or not cpu[1].isdigit() or
                int(cpu[1]) <= 0 or int(cpu[0]) > 2 * int(cpu[1])):
            raise ValueError("CI payload has unbounded kernel CPU budget")

    def authorize(self, method, resource, body, query):
        if method == "GET" and resource in ("/_ping", "/version", "/info") and not query:
            return
        if method == "GET" and resource.startswith("/images/") and resource.endswith("/json"):
            if resource.removeprefix("/images/").removesuffix("/json") != self.image:
                raise ValueError("unapproved image readback")
            return
        if method == "POST" and resource == "/containers/create" and not query:
            if self.job_id is not None or list(self.state.iterdir()):
                raise ValueError("one job only, no uncertain create replay")
            self.requested = canonical(body)
            self.validate_create(self.requested)
            self.verify_network()
            record(self.state / "create.intent.json", {"requestSha256": hashlib.sha256(body).hexdigest()})
            return
        parts = resource.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "containers" and parts[1] == self.job_id:
            action = parts[2:]  # start/wait/inspect/logs/exec/stop/remove
            if method == "GET" and action in (["json"], ["logs"]):
                return
            if method == "POST" and action == ["start"] and not query:
                if self.started or (self.state / "start.intent.json").exists():
                    raise ValueError("uncertain CI start cannot be replayed")
                self.verify_network()
                self.inspect(self.job_id)
                record(self.state / "start.intent.json", {"id": self.job_id})
                return
            if method == "POST" and action == ["wait"] and not body and query in ("", "condition=not-running"):
                if (self.state / "wait.intent.json").exists():
                    raise ValueError("CI terminal wait result is uncertain; no second wait")
                record(self.state / "wait.intent.json", {"id": self.job_id})
                return
            if method == "POST" and action == ["exec"] and not query:
                arguments = canonical(body)
                if (not isinstance(arguments, dict) or set(arguments) -
                        {"AttachStdin", "AttachStdout", "AttachStderr", "Tty", "Cmd",
                         "Env", "WorkingDir", "User", "Privileged"} or
                        arguments.get("Privileged") not in (None, False) or
                        arguments.get("User") not in (None, "", "1000:1000") or
                        arguments.get("Tty") not in (None, False) or
                        arguments.get("AttachStdin") not in (None, False) or
                        arguments.get("WorkingDir") not in (None, "", "/workspace") or
                        not isinstance(arguments.get("Cmd"), list) or
                        not 1 <= len(arguments["Cmd"]) <= 32 or
                        any(not isinstance(part, str) or len(part) > 32768 or "\x00" in part
                            for part in arguments["Cmd"])):
                    raise ValueError("unreviewed CI exec authority")
                self.validate_env(arguments.get("Env", []))
                record(self.state / f"exec-create-{len(self.exec_ids)}.intent.json",
                    {"id": self.job_id, "requestSha256": hashlib.sha256(body).hexdigest()})
                return
            if method == "POST" and action == ["stop"] and not query:
                if (self.state / "stop.intent.json").exists():
                    raise ValueError("uncertain CI stop cannot be replayed")
                record(self.state / "stop.intent.json", {"id": self.job_id})
                return
            if method == "DELETE" and not action and not query:
                if not ((self.state / "stop.result.json").exists() or
                        (self.state / "wait.result.json").exists()):
                    raise ValueError("container removal requires original stop or terminal ACK")
                return
        if len(parts) == 3 and parts[0] == "exec" and parts[1] in self.exec_ids and parts[2] == "start":
            if method == "POST":
                arguments = canonical(body)
                if (not isinstance(arguments, dict) or set(arguments) - {"Detach", "Tty"} or
                        arguments.get("Detach") not in (None, False) or
                        arguments.get("Tty") not in (None, False) or query):
                    raise ValueError("unreviewed detached/TTY job exec")
                if (self.state / f"exec-start-{parts[1]}.intent.json").exists():
                    raise ValueError("CI step was already started or is uncertain")
                record(self.state / f"exec-start-{parts[1]}.intent.json", {"id": parts[1]})
                return
        raise ValueError("Docker API not enrolled for private CI")


class Handler(socketserver.BaseRequestHandler):
    def respond(self, status, data, headers=()):
        reason = http.client.responses.get(status, "Error")
        self.request.sendall(f"HTTP/1.1 {status} {reason}\r\n".encode())
        for name, value in headers:
            if name.lower() not in ("transfer-encoding", "connection", "content-length", "set-cookie"):
                self.request.sendall(f"{name}: {value}\r\n".encode())
        self.request.sendall(f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)

    def handle(self):
        try:
            self.request.settimeout(45)
            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) <= 16384:
                block = self.request.recv(4096)
                if not block:
                    raise ValueError("incomplete CI request")
                raw.extend(block)
            if len(raw) > 16384:
                raise ValueError("oversized CI headers")
            head, rest = bytes(raw).split(b"\r\n\r\n", 1)
            lines = head.decode("ascii", "strict").split("\r\n")
            method, target, protocol = lines.pop(0).split(" ")
            if protocol != "HTTP/1.1" or method not in ("GET", "POST", "DELETE"):
                raise ValueError("unsupported CI HTTP request")
            headers = {}
            for line in lines:
                key, sep, value = line.partition(":")
                key = key.lower()
                if not sep or key in headers or key not in (
                        "host", "user-agent", "accept", "content-length", "content-type", "connection"):
                    raise ValueError("ambiguous CI HTTP header")
                headers[key] = value.strip()
            count = int(headers.get("content-length", "0"))
            if not 0 <= count <= MAX_REQUEST or len(rest) > count:
                raise ValueError("oversized/ambiguous CI request body")
            while len(rest) < count:
                block = self.request.recv(count - len(rest))
                if not block:
                    raise ValueError("truncated CI request")
                rest += block
            url = urlsplit(target)
            if url.scheme or url.netloc or url.fragment:
                raise ValueError("foreign CI HTTP target")
            match = VERSION.fullmatch(url.path)
            if match is None:
                raise ValueError("unsupported CI API version")
            resource = match.group(1)
            # Mutating APIs are serialized through their native ACK and durable
            # result. Concurrent read-only log/inspect streams remain possible.
            effect = method in ("POST", "DELETE") and not (
                method == "POST" and resource.endswith("/wait"))
            if effect:
                self.server.effect_lock.acquire()
            try:
                self.operate(method, target, resource, rest, url.query)
            finally:
                if effect:
                    self.server.effect_lock.release()
        except (ValueError, KeyError, TypeError, AttributeError, IndexError,
                UnicodeError, OSError, http.client.HTTPException):
            try:
                self.respond(403, b"private CI socket request denied\n")
            except OSError:
                pass

    def operate(self, method, target, resource, rest, query):
            self.server.authorize(method, resource, rest, query)
            match = re.fullmatch(r"/exec/([a-f0-9]{64})/start", resource)
            if match is not None:
                execution = match.group(1)
                self.server.stream_exec(target, rest, self.request)
                status, reply, _ = self.server.request("GET", f"/v1.41/exec/{execution}/json")
                if status != 200 or canonical(reply).get("Running") is not False:
                    raise ValueError("native CI exec terminal readback missing")
                record(self.server.state / f"exec-start-{execution}.result.json",
                    {"id": execution, "exitCode": canonical(reply).get("ExitCode")})
                return
            status, reply, response_headers = self.server.request(method, target, rest)
            if resource == "/containers/create":
                if status != 201:
                    raise ValueError("native CI create did not acknowledge; intent remains uncertain")
                created = canonical(reply)["Id"]
                if not isinstance(created, str) or not CID.fullmatch(created):
                    raise ValueError("native CI create ID unavailable; intent remains uncertain")
                self.server.inspect(created)
                self.server.job_id = created
                record(self.server.state / "create.result.json", {"id": created,
                    "replySha256": hashlib.sha256(reply).hexdigest()})
            elif resource == "/containers/" + str(self.server.job_id) + "/start":
                if status != 204:
                    raise ValueError("native CI start result missing; preserve intent")
                self.server.verify_kernel(self.server.inspect(self.server.job_id))
                self.server.started = True
                record(self.server.state / "start.result.json", {"id": self.server.job_id})
            elif resource == "/containers/" + str(self.server.job_id) + "/wait":
                if status != 200:
                    raise ValueError("native CI terminal wait lost its original result")
                terminal = canonical(reply)
                code = terminal.get("StatusCode")
                if (not isinstance(code, int) or code not in range(0, 256) or
                        self.server.inspect(self.server.job_id)["State"]["Running"] is not False):
                    raise ValueError("CI job lacks a terminal native state")
                record(self.server.state / "wait.result.json", {"id": self.server.job_id,
                    "exitCode": code, "replySha256": hashlib.sha256(reply).hexdigest()})
            elif resource == "/containers/" + str(self.server.job_id) + "/stop":
                if status not in (204, 304):
                    raise ValueError("native CI stop result missing; preserve intent")
                inspected = self.server.inspect(self.server.job_id)
                if inspected["State"]["Running"]:
                    raise ValueError("CI job still running after stop")
                record(self.server.state / "stop.result.json", {"id": self.server.job_id})
            elif resource == "/containers/" + str(self.server.job_id) + "/exec":
                if status != 201:
                    raise ValueError("native CI exec create lacks original result")
                execution = canonical(reply).get("Id")
                if not isinstance(execution, str) or not CID.fullmatch(execution):
                    raise ValueError("native CI exec ID missing")
                record(self.server.state / f"exec-create-{len(self.server.exec_ids)}.result.json", {"id": execution})
                self.server.exec_ids.add(execution)
            self.respond(status, reply, response_headers)


def main():
    if len(sys.argv) != 2 or os.geteuid() != UID or os.getegid() != UID:
        raise SystemExit("dedicated rootless CI account required")
    config_path = Path(sys.argv[1])
    details = config_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != UID or details.st_mode & 0o077:
        raise SystemExit("foreign CI guard configuration")
    config = canonical(config_path.read_bytes())
    if set(config) != {"schemaVersion", "generation", "state", "listen", "backend", "image", "imageId", "network", "caMount", "memoryMiB"}:
        raise SystemExit("foreign CI guard configuration fields")
    generation = config["generation"]
    base = f"/home/webservices-lab-ci-runner/.local/share/p0v3-ci/{generation}"
    if (config["schemaVersion"] != 1 or not re.fullmatch(r"q-[a-f0-9]{12}", generation) or
            config["state"] != base + "/guard-state" or config["listen"] != base + "/guard.sock" or
            config["backend"] != "/run/user/784/podman/podman.sock" or
            config["network"] != f"p0v3-ci-{generation}-internal" or
            config["caMount"] != base + "/transport-ca.pem:/etc/ssl/certs/p0v3-ci-forgejo-ca.pem:ro" or
            not HASH.fullmatch(config["imageId"]) or
            not re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", config["image"]) or
            not isinstance(config["memoryMiB"], int) or not 512 <= config["memoryMiB"] <= 8192):
        raise SystemExit("invalid CI guard owner/image boundary")
    with Guard(config) as server:
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
