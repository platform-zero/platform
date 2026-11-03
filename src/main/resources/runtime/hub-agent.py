"""Fixed-command per-user notebook lifecycle. No runtime socket, arbitrary argv or environment API."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def retire_descendants():
    # This agent must be PID 1 in its dedicated notebook PID namespace.
    if os.getpid() != 1:
        raise RuntimeError('Refusing process cleanup outside the dedicated PID namespace')
    def remaining():
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except ChildProcessError:
                break
        return [int(p.name) for p in Path('/proc').iterdir() if p.name.isdecimal() and int(p.name) > 1]
    for pid in remaining():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while remaining() and time.monotonic() < deadline:
        time.sleep(0.05)
    leftovers = remaining()
    for pid in leftovers:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return not leftovers


class Notebook:
    def __init__(self, journal, command, spawn=subprocess.Popen, retire=retire_descendants):
        self.journal = Path(journal)
        self.command = tuple(command)
        self.spawn = spawn
        self.retire = retire
        self.child = None
        self.lock = threading.Lock()
        self.blocked = self.journal.exists() and self.journal.read_text() != 'stopped\n'

    def record(self, state):
        pending = self.journal.with_suffix('.pending')
        # A partial prior journal must not be silently replaced.
        with pending.open('x') as stream:
            os.chmod(pending, 0o600)
            stream.write(state + '\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, self.journal)
        descriptor = os.open(self.journal.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def status(self):
        if self.blocked or self.journal.with_suffix('.pending').exists():
            return 'blocked'
        if self.child is None:
            return 'stopped'
        return 'running' if self.child.poll() is None else 'failed'

    def start(self):
        with self.lock:
            if self.status() != 'stopped':
                return 409
            self.blocked = True
            self.record('starting')
            self.child = self.spawn(self.command, stdin=subprocess.DEVNULL, start_new_session=True)
            self.record('running')
            self.blocked = False
            return 201

    def stop(self):
        with self.lock:
            if self.status() == 'stopped':
                return 204
            if self.status() != 'running':
                return 409
            self.blocked = True
            self.record('stopping')
            self.child.terminate()
            try:
                code = self.child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.child.kill(); self.child.wait(timeout=10)
                self.record('forced-failure')
                return 500
            if code not in (0, -signal.SIGTERM):
                self.record('exit-failure')
                return 500
            if not self.retire():
                self.record('descendant-failure')
                return 500
            self.child = None
            self.record('stopped')
            self.blocked = False
            return 204


def handler(notebook, key):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, content=b''):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(content)

        def authorized(self):
            token = self.headers.get('Authorization', '')
            return hmac.compare_digest(hashlib.sha256(token.encode()).digest(), hashlib.sha256(('Bearer ' + key).encode()).digest())

        def do_GET(self):
            if self.path == '/health':
                self.respond(200 if notebook.status() in ('running', 'stopped') else 503)
            elif self.path == '/state' and self.authorized():
                self.respond(200, json.dumps({'state': notebook.status()}).encode())
            else:
                self.respond(403)

        def do_POST(self):
            if not self.authorized():
                self.respond(403); return
            if self.headers.get('Content-Length') != '0' or self.headers.get('Transfer-Encoding') is not None:
                self.respond(400); return
            try:
                if self.path == '/start':
                    self.respond(notebook.start())
                elif self.path == '/stop':
                    self.respond(notebook.stop())
                else:
                    self.respond(404)
            except Exception:
                # Fail closed without logging credentials or accepting a second start.
                notebook.blocked = True
                self.respond(500)
    return Handler


def main():
    if os.getpid() != 1:
        raise RuntimeError('Notebook agent requires its dedicated PID namespace')
    os.umask(0o077)
    key = Path('/run/secrets/control-key').read_text().strip()
    if len(key) != 64 or any(c not in '0123456789abcdef' for c in key):
        raise ValueError('Invalid lifecycle credential')
    home = Path('/home/jovyan')
    (home / 'work').mkdir(exist_ok=True)
    notebook = Notebook(home / '.p0-hub-state', ['/opt/conda/bin/jupyterhub-singleuser', '--config=/run/secrets/notebook.py', '--ServerApp.certfile=/run/secrets/web.pem', '--ServerApp.keyfile=/run/secrets/web-key.pem'])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/run/secrets/web.pem', '/run/secrets/web-key.pem')
    class Server(ThreadingHTTPServer):
        daemon_threads = False
        def get_request(self):
            client, address = self.socket.accept()
            client.settimeout(5)
            try:
                # Only this namespace (readiness) and the Hub controller may reach control.
                if address[0] not in ('127.0.0.1', client.getsockname()[0]) and address[0] != socket.gethostbyname('controller'):
                    raise OSError('Control peer denied')
                return context.wrap_socket(client, server_side=True), address
            except Exception:
                client.close()
                raise
    server = Server(('0.0.0.0', 8444), handler(notebook, key))
    def shutdown(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown); signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        result = notebook.stop()
        if result != 204:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
