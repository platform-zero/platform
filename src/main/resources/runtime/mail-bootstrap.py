"""Exclusive native Stalwart provisioning, never an automatic recovery path."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def durable(path, value):
    with path.open('xb') as stream:
        stream.write(value); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def resolve(value, ids, passwords):
    if isinstance(value, str):
        if value.startswith('#'):
            return ids[value[1:]]
        if value.startswith('@password:'):
            return passwords[value.split(':', 1)[1]]
    if isinstance(value, dict):
        return {resolve(k, ids, passwords): resolve(v, ids, passwords) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, ids, passwords) for v in value]
    return value


def api(method, arguments, credential):
    client = http.client.HTTPConnection('127.0.0.1', 8080, timeout=20)
    try:
        client.request('POST', '/jmap/', json.dumps({'using': ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'], 'methodCalls': [[method, arguments, 'p0']]}), {'Authorization': 'Basic ' + base64.b64encode(credential.encode()).decode(), 'Content-Type': 'application/json'})
        response = client.getresponse(); body = response.read(1048577)
        if response.status != 200 or len(body) > 1048576:
            raise RuntimeError('Bounded native API request failed')
        calls = json.loads(body)['methodResponses']
        if len(calls) != 1 or calls[0][0] != method or calls[0][2] != 'p0':
            raise RuntimeError('Unexpected native API response')
        return calls[0][1]
    finally:
        client.close()


def stop(child):
    if child.poll() is not None:
        raise RuntimeError('Native initializer exited unexpectedly')
    child.terminate()
    try:
        status = child.wait(timeout=25)
    except subprocess.TimeoutExpired:
        child.kill(); child.wait(timeout=10)
        raise RuntimeError('Native initializer required forced shutdown')
    if status != 0:
        raise RuntimeError('Native initializer shutdown failed')


def initialize(root, configuration):
    os.umask(0o077)
    if os.getpid() != 1 or (root / 'store').exists():
        raise RuntimeError('Fresh dedicated initializer required; no replay')
    seed = (configuration / 'mail-seed.json').read_bytes()
    durable(root / 'bootstrap.intent', hashlib.sha256(seed).hexdigest().encode())
    users = json.loads((configuration / 'users.json').read_text()); passwords = {}
    for user, password in users.items():
        if user not in ('alice', 'bob', 'outsider') or len(password) != 64 or any(c not in '0123456789abcdef' for c in password):
            raise RuntimeError('Invalid fixture credential')
        result = subprocess.run(['/usr/bin/openssl', 'passwd', '-6', '-stdin'], input=(password + '\n').encode(), capture_output=True, timeout=10, check=True)
        passwords[user] = result.stdout.decode().strip()
        if not passwords[user].startswith('$6$'):
            raise RuntimeError('Native password hashing failed')
    credential = os.environ['STALWART_RECOVERY_ADMIN']
    def interrupted(signum, frame):
        raise InterruptedError('Initializer interrupted; explicit reconciliation required')
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with (root / 'bootstrap-native.log').open('xb') as log:
        child = subprocess.Popen(['/usr/local/bin/stalwart', '--config', str(configuration / 'mail-store.json')], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 60
            while True:
                if child.poll() is not None:
                    raise RuntimeError('Native recovery listener exited')
                try:
                    api('x:NetworkListener/get', {}, credential)
                    break
                except InterruptedError:
                    raise
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Native recovery listener deadline exceeded')
                    time.sleep(0.2)
            ids = {}
            for index, step in enumerate(json.loads(seed)):
                arguments = resolve(step['arguments'], ids, passwords)
                durable(root / ('step-%02d.intent' % index), json.dumps({'method': step['method'], 'sha256': hashlib.sha256(json.dumps(arguments, sort_keys=True).encode()).hexdigest()}).encode())
                result = api(step['method'], arguments, credential)
                durable(root / ('step-%02d.response' % index), json.dumps(result).encode())
                if result.get('notCreated') or result.get('notUpdated') or result.get('notDestroyed'):
                    raise RuntimeError('Native provisioning rejected; no replay')
                if set(result.get('created', {})) != set(arguments.get('create', {})) or set(result.get('updated', {})) != set(arguments.get('update', {})):
                    raise RuntimeError('Native provisioning response incomplete')
                if 'bindBuiltinApplication' in step:
                    applications = result.get('list', [])
                    if step['method'] != 'x:Application/get' or len(applications) != 1 or applications[0].get('resourceUrl') != 'https://github.com/stalwartlabs/webui/releases/download/v2/webui.zip':
                        raise RuntimeError('Unexpected built-in application; no mutation authorized')
                    ids[step['bindBuiltinApplication']] = applications[0]['id']
                ids.update({key: value['id'] for key, value in result.get('created', {}).items()})
            durable(root / 'object-ids.json', json.dumps(ids).encode())
        finally:
            stop(child)
    if not (root / 'store/CURRENT').is_file():
        raise RuntimeError('Native store missing after provisioning')
    durable(root / 'ready', (configuration / 'generation').read_bytes())


if __name__ == '__main__':
    initialize(Path('/data'), Path('/run/secrets'))
