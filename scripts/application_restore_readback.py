"""Historical native readback only: never invokes provisioning, migrations, Git pushes or fixture creation."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import base64
import ipaddress
import json
import re
import subprocess
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fixture_id(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(re.escape(prefix) + r'[a-f0-9]{12}', value):
        raise ValueError('Invalid source fixture identity')
    return value


def verify_applications(base, source_receipt, target, out, phase, run, pod, env):
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    canonical = source_receipt.get('canonicalCore', False)
    planka_kind = 'canonical-core' if canonical else 'planka'

    def origin(kind, role, port):
        network = 'p0v3-live-' + target + '-' + kind + ('-planka-web' if kind == 'canonical-core' else '-net')
        name = 'p0v3-live-' + target + '-' + kind + '-' + role
        address = run(phase + '-' + kind + '-address', pod + ['inspect', '--format',
            '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}', name])
        assert ipaddress.ip_address(address).is_private
        return 'http://' + address + ':' + str(port)

    def api(url, authorization=None, payload=None, denied=False):
        headers = {'Accept': 'application/json'}
        if authorization:
            headers['Authorization'] = authorization
        data = None if payload is None else json.dumps(payload).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        try:
            with opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=20) as response:
                raw = response.read(2097153)
                assert not denied and len(raw) <= 2097152
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            assert denied and error.code in (401, 403, 404), 'Unexpected native application denial'
            return None

    forgejo_id = fixture_id(source_receipt['forgejoReceipt'], 'p0v3-forgejo-')
    fixture = base / 'image-acquisition-receipts' / forgejo_id
    original = json.loads((fixture / 'receipt.json').read_text())
    assert original['passed'] and original['gitPushCloneVerified']
    credentials = json.loads((fixture / 'user.json').read_text())
    user = credentials['username']
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', user)
    authorization = 'Basic ' + base64.b64encode((user + ':' + credentials['password']).encode()).decode()
    url = origin('forgejo', 'forgejo', 3000)
    assert api(url + '/api/v1/user', authorization)['login'] == user
    issues = api(url + '/api/v1/repos/' + user + '/lifecycle/issues', authorization)
    issue = next(i for i in issues if i['title'] == 'Persistent workflow ' + forgejo_id)
    assert any(c['body'] == 'Git push and issue creation succeeded' for c in
               api(url + '/api/v1/repos/' + user + '/lifecycle/issues/' + str(issue['number']) + '/comments', authorization))
    api(url + '/api/v1/repos/' + user + '/lifecycle', denied=True)
    git_env = {**env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_CONFIG_COUNT': '2', 'GIT_CONFIG_KEY_0': 'http.extraHeader', 'GIT_CONFIG_VALUE_0': 'Authorization: ' + authorization,
               'GIT_CONFIG_KEY_1': 'http.followRedirects', 'GIT_CONFIG_VALUE_1': 'false'}

    def git(*args):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args], capture_output=True, env=git_env, timeout=120)
        assert result.returncode == 0, 'Native restored Git readback failed'
        return result.stdout.strip()

    checkout = out / (phase + '-git-clone')
    assert not checkout.exists()
    git('clone', url + '/' + user + '/lifecycle.git', str(checkout))
    expected = git('--git-dir=' + str(fixture / 'source/.git'), 'rev-parse', 'HEAD')
    assert git('-C', str(checkout), 'rev-parse', 'HEAD') == expected
    assert (checkout / 'README.md').read_bytes() == (fixture / 'source/README.md').read_bytes()

    planka_id = fixture_id(source_receipt['plankaReceipt'], 'p0v3-planka-')
    original = json.loads((base / 'image-acquisition-receipts' / planka_id / 'receipt.json').read_text())
    assert original['passed'] and original['cardMoveAndCommentPersisted']
    if canonical:
        source = fixture_id(source_receipt['generation'], 'q-')
        credentials_file = base / 'runtime-deployments' / (source + '-canonical-core') / 'planka-bootstrap.env'
    else:
        credentials_file = base / 'runtime-deployments' / (target + '-planka') / 'planka.env'
    values = dict(line.split('=', 1) for line in credentials_file.read_text().splitlines())
    url = origin(planka_kind, 'planka', 1337) + '/api'
    token = api(url + '/access-tokens', payload={'emailOrUsername': values['DEFAULT_ADMIN_EMAIL'], 'password': values['DEFAULT_ADMIN_PASSWORD']})['item']
    assert isinstance(token, str) and token
    auth = 'Bearer ' + token
    for key in ('cardId', 'boardId', 'doneListId', 'projectId'):
        assert re.fullmatch(r'[0-9]+', str(original[key]))
    card_url = url + '/cards/' + str(original['cardId'])
    saved = api(card_url, auth)['item']
    assert saved['name'] == 'Persistent task ' + planka_id
    assert saved['listId'] == original['doneListId'] and saved['boardId'] == original['boardId']
    assert any(c['text'] == 'Created, moved and retained through restart' for c in api(card_url + '/comments', auth)['items'])
    assert api(url + '/projects/' + str(original['projectId']), auth)['item']['name'] == planka_id
    api(card_url, denied=True)
    return {'historicalGitCommitAndBytes': True, 'historicalIssueAndComment': True,
            'historicalProjectCardMoveAndComment': True, 'anonymousAccessDenied': True,
            'fixtureCreationOrInitializerReplay': False, 'browserJourney': False}
