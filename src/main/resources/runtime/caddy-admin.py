"""Pinned-controller helper: one bounded Caddy request in a verified container network namespace.
No shell, arbitrary destination, container file execution, DNS, host admin exposure, or write replay.
"""
import base64
import ctypes
import http.client
import json
import os
import re
import signal
import sys

MAXIMUM = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def enter_namespace(pid, container_id):
    require(os.geteuid() == 0, "namespace helper requires root")
    # Pin the namespace before inspecting identity. A later PID exit/reuse cannot redirect the FD.
    descriptor = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="ascii") as stream:
            cgroups = stream.read(65537)
        require(len(cgroups) <= 65536 and re.search(r"(?<![a-f0-9])" + re.escape(container_id) + r"(?![a-f0-9])", cgroups),
                "PID does not belong to audited container")
        require(os.fstat(descriptor).st_ino == os.stat(f"/proc/{pid}/ns/net").st_ino, "PID namespace changed")
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(descriptor, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot enter pinned network namespace")
    finally:
        os.close(descriptor)


def exchange(request, enter=enter_namespace, connection=http.client.HTTPConnection):
    require(set(request) == {"pid", "containerId", "method", "path", "etag", "body"}, "invalid helper protocol")
    pid, container_id = request["pid"], request["containerId"]
    require(type(pid) is int and 1 < pid <= 2147483647 and isinstance(container_id, str) and
            re.fullmatch(r"[a-f0-9]{64}", container_id), "invalid audited target")
    method, path, etag = request["method"], request["path"], request["etag"]
    body = None if request["body"] is None else base64.b64decode(request["body"], validate=True)
    read = method == "GET" and path == "/config/" and etag is None and body is None
    mutation = ((method == "POST" and path == "/config/") or
                (method == "PATCH" and re.fullmatch(r"/config/apps/http/servers/[a-z][a-z0-9-]{0,63}/routes", path)))
    require(read or (mutation and isinstance(etag, str) and re.fullmatch(r'"/config/ [a-f0-9]{16}"', etag)
                    and body is not None and 1 <= len(body) <= MAXIMUM), "unapproved Caddy request")
    enter(pid, container_id)
    client = connection("127.0.0.1", 2019, timeout=10)
    try:
        headers = {} if etag is None else {"If-Match": etag, "Content-Type": "application/json"}
        client.request(method, path, body=body, headers=headers)
        response = client.getresponse()
        data = response.read(MAXIMUM + 1)
        require(len(data) <= MAXIMUM, "Caddy body exceeds bound")
        return {"status": response.status, "etag": response.getheader("ETag"), "body": base64.b64encode(data).decode("ascii")}
    finally:
        client.close()


def expired(*_):
    raise TimeoutError("namespace exchange deadline exceeded")


def main():
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        require(0 < len(raw) <= 8 * 1024 * 1024, "oversized helper request")
        result = exchange(json.loads(raw))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.flush()
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Configurations can contain credentials; never include exceptions/response bodies in logs.
        sys.stderr.write("Caddy namespace exchange failed; a dispatched write must not be replayed\n")
        raise SystemExit(1)
