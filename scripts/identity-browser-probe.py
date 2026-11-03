#!/usr/bin/env python3
"""Runs inside a private test client container; input contains disposable test credentials.
Prints outcome flags only, never codes, tokens, passwords or enrollment secrets.
"""
import base64
import hashlib
import hmac
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'action': attrs.get('action', ''), 'fields': {}}
            self.forms.append(self.current)
        elif tag == 'input' and self.current is not None and attrs.get('name'):
            self.current['fields'][attrs['name']] = attrs.get('value', '')
    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None

def totp(secret, timestamp):
    digest = hmac.new(secret.encode('utf-8'), struct.pack('>Q', int(timestamp) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def main():
    inputs = json.load(sys.stdin)
    base = inputs['base']
    restored = inputs.get('mode') == 'restored'
    if restored:
        saved = json.loads(Path('/tmp/p0v3-browser-state.json').read_text())
        inputs['temporaryPassword'] = saved['password']
        inputs['newPassword'] = saved['password']
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def get(url):
        with opener.open(url, timeout=20) as response:
            return response.read().decode(), response.geturl()
    def post(url, fields):
        request = urllib.request.Request(url, urllib.parse.urlencode(fields).encode(),
            {'Content-Type': 'application/x-www-form-urlencoded'})
        with opener.open(request, timeout=20) as response:
            return response.read().decode(), response.geturl()
    token_url = base + '/realms/p0v3/protocol/openid-connect/token'
    try:
        post(token_url, {'grant_type': 'password', 'client_id': 'onboarding-probe',
                        'username': 'new-human', 'password': inputs['temporaryPassword']})
        raise AssertionError('Unenrolled identity obtained a token')
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read())
        assert error.code == 400 and payload['error'] == 'invalid_grant', 'Unexpected initial grant denial'
    captured = {}
    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            captured.update(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'callback received')
        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(('127.0.0.1', 18765), Callback)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state = secrets.token_urlsafe(24)
    callback = 'http://127.0.0.1:18765/callback'
    auth = base + '/realms/p0v3/protocol/openid-connect/auth?' + urllib.parse.urlencode({
        'client_id': 'onboarding-probe', 'redirect_uri': callback, 'response_type': 'code',
        'scope': 'openid', 'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'})
    def form(html, current_url, required):
        parser = FormParser()
        parser.feed(html)
        matches = [f for f in parser.forms if required in f['fields']]
        assert len(matches) == 1, 'Required browser form not found: ' + required + '; fields=' + str([list(f['fields']) for f in parser.forms])
        f = matches[0]
        return urllib.parse.urljoin(current_url, f['action']), f['fields']
    try:
        html, url = get(auth)
        action, fields = form(html, url, 'username')
        fields.update(username='new-human', password=inputs['temporaryPassword'])
        html, url = post(action, fields)
        assert not captured, 'Unexpected early callback before password reset'
        completed = set()
        raw_secret = saved['secret'] if restored else None
        for _ in range(1 if restored else 2):
            assert not captured, 'Token flow completed before both required actions'
            parser = FormParser()
            parser.feed(html)
            names = {name for f in parser.forms for name in f['fields']}
            if restored and 'otp' in names:
                action, fields = form(html, url, 'otp')
                fields['otp'] = totp(raw_secret, time.time())
                completed.add('restored-totp')
            elif 'password-new' in names and 'password' not in completed:
                action, fields = form(html, url, 'password-new')
                fields.update({'password-new': inputs['newPassword'], 'password-confirm': inputs['newPassword']})
                completed.add('password')
            elif 'totpSecret' in names and 'totp' not in completed:
                action, fields = form(html, url, 'totpSecret')
                # Keycloak TotpBean exposes the raw HmacOTP secret in this hidden field;
                # the manually displayed key is its Base32 encoding, not the field itself.
                raw_secret = fields['totpSecret']
                fields.update(totp=totp(raw_secret, time.time()), userLabel='private-acceptance-device')
                completed.add('totp')
            else:
                raise AssertionError('Unexpected required action form fields: ' + str(sorted(names)))
            html, url = post(action, fields)
        assert completed == ({'restored-totp'} if restored else {'password', 'totp'})
        assert captured.get('state') == [state] and len(captured.get('code', [])) == 1, 'No completed callback after TOTP enrollment'
        body, _ = post(token_url, {'grant_type': 'authorization_code', 'client_id': 'onboarding-probe',
            'code': captured['code'][0], 'redirect_uri': callback, 'code_verifier': verifier})
        token = json.loads(body)
        assert token.get('access_token') and token.get('id_token')
        if not restored:
            fd = os.open('/tmp/p0v3-browser-state.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as out:
                json.dump({'secret': raw_secret, 'password': inputs['newPassword']}, out)
            print(json.dumps({'unenrolledTokenDenied': True, 'passwordResetCompleted': True,
                              'totpEnrollmentCompleted': True, 'pkceCodeExchangeSucceeded': True}))
        else:
            print(json.dumps({'restoredPasswordOnlyDenied': True, 'restoredTotpLoginSucceeded': True,
                              'restoredPkceCodeExchangeSucceeded': True}))
    finally:
        server.shutdown()
        server.server_close()

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        message = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
        print('Identity browser probe failed: ' + message, file=sys.stderr)
        raise SystemExit(1)
