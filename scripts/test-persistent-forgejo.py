#!/usr/bin/env python3
"""A regular user's real Git push/clone and issue/comment journey on owned, private Forgejo.
Retains fixtures and a private receipt. Not browser, encrypted restore or full-stack acceptance.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import urllib.error
import urllib.request
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='forgejo-r2')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'forgejo', 'forgejo-init'}
    values = dict(line.split('=', 1) for line in (base / name / 'forgejo.env').read_text().splitlines())
    run_id = 'p0v3-forgejo-' + uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    directory.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'persistent-private-forgejo-not-full-stack', 'passed': False}
    origin = ''
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    user = 'journey-' + uuid.uuid4().hex[:12]
    password = secrets.token_hex(32)
    authorization = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
    admin_authorization = 'Basic ' + base64.b64encode(('p0v3-bootstrap:' + values['BOOTSTRAP_PASSWORD']).encode()).decode()

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Forgejo runtime lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['container', 'inspect', 'p0v3-live-' + name + '-forgejo'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(address).is_private
            origin = 'http://' + address + ':3000'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, payload=None, admin=False):
        headers = {'Authorization': admin_authorization if admin else authorization, 'Accept': 'application/json'}
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        try:
            with opener.open(urllib.request.Request(origin + '/api/v1' + path, data=body, headers=headers), timeout=20) as response:
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raise RuntimeError('Private Forgejo API returned ' + str(error.code)) from None

    git_env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy')}
    git_env.update(HOME=str(directory), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                   GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='http.extraHeader', GIT_CONFIG_VALUE_0='Authorization: ' + authorization,
                   GIT_CONFIG_KEY_1='http.followRedirects', GIT_CONFIG_VALUE_1='false', GIT_AUTHOR_NAME='Private journey',
                   GIT_AUTHOR_EMAIL=user + '@localhost.invalid', GIT_COMMITTER_NAME='Private journey', GIT_COMMITTER_EMAIL=user + '@localhost.invalid')

    def git(*args, cwd=directory):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=cwd, env=git_env,
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, 'Private Git operation failed: ' + args[0]
        return result.stdout.strip()

    try:
        runtime('apply-private')
        receipt['phase'] = 'regular-user'
        created = api('/admin/users', {'username': user, 'email': user + '@localhost.invalid', 'password': password,
                                      'must_change_password': False, 'send_notify': False}, admin=True)
        assert created['login'] == user and not created['is_admin']
        fd = os.open(directory / 'user.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump({'username': user, 'password': password}, out)
        repository = api('/user/repos', {'name': 'lifecycle', 'private': True, 'auto_init': False})
        assert repository['private']
        receipt['phase'] = 'git-push'
        source = directory / 'source'
        source.mkdir(mode=0o700)
        git('init', '-b', 'main', cwd=source)
        content = 'Private Forgejo lifecycle fixture ' + run_id + '\n'
        (source / 'README.md').write_text(content)
        git('add', 'README.md', cwd=source)
        git('commit', '-m', 'Private lifecycle fixture', cwd=source)
        commit = git('rev-parse', 'HEAD', cwd=source)
        git('remote', 'add', 'origin', origin + '/' + user + '/lifecycle.git', cwd=source)
        git('push', '-u', 'origin', 'main', cwd=source)
        issue = api('/repos/' + user + '/lifecycle/issues', {'title': 'Persistent workflow ' + run_id, 'body': 'Private fixture'})
        issue_path = '/repos/' + user + '/lifecycle/issues/' + str(issue['number'])
        api(issue_path + '/comments', {'body': 'Git push and issue creation succeeded'})
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        assert api('/user')['login'] == user
        git('clone', origin + '/' + user + '/lifecycle.git', 'readback')
        readback = directory / 'readback'
        assert git('rev-parse', 'HEAD', cwd=readback) == commit
        assert (readback / 'README.md').read_text() == content
        assert api(issue_path)['title'] == issue['title']
        assert api(issue_path + '/comments')[0]['body'] == 'Git push and issue creation succeeded'
        receipt.update(passed=True, phase='complete', regularUserNotAdmin=True, gitPushCloneVerified=True,
                       issueAndCommentPersisted=True, cleanStopRestartVerified=True, encryptedRestoreTest=False, browserJourney=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
