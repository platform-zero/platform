"""Bounded, exact-leaf private TLS client for the synthetic Keykeeper composite."""
if not __debug__:
    raise SystemExit('Optimized Python disables safety checks; refusing effects')
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
from urllib.parse import urlencode


class Client:
    def __init__(self, podman, base, name, host, port, prefix):
        assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
        assert host in ('keeper', 'identity') and port == 8443
        self.podman, self.base, self.name = podman, base, name
        self.host, self.port = host, port
        self.context = ssl.create_default_context(cafile=str(base / name / (prefix + 'ca.pem')))
        self.leaf = ssl.PEM_cert_to_DER_cert((base / name / (prefix + 'web.pem')).read_text())
        self.refresh()

    def refresh(self):
        self.info = json.loads(subprocess.check_output(self.podman + ['inspect', 'p0v3-live-' + self.name + '-' + self.host]))[0]
        assert self.info['State']['Running'] and not self.info['HostConfig']['PortBindings']
        assert self.info['Config']['Labels']['io.p0v3.private-deployment'] == self.name
        network = 'p0v3-live-' + self.name + '-net'
        assert set(self.info['NetworkSettings']['Networks']) == {network}
        self.address = self.info['NetworkSettings']['Networks'][network]['IPAddress']
        assert ipaddress.ip_address(self.address).is_private

    def request(self, method, path, body=None, token=None, expected=(200,), form=False):
        assert method in ('GET', 'POST', 'PUT', 'DELETE')
        assert path.startswith('/') and not any(c in path for c in '\r\n ') and len(path) < 8192
        assert token is None or (isinstance(token, str) and 1 <= len(token) <= 8192 and not any(c in token for c in '\r\n '))
        payload = b'' if body is None else (urlencode(body).encode() if form else json.dumps(body).encode())
        assert len(payload) <= 65536
        headers = 'Host: ' + self.host + ':8443\r\nContent-Type: ' + ('application/x-www-form-urlencoded' if form else 'application/json') + '\r\nContent-Length: ' + str(len(payload)) + '\r\nConnection: close\r\n'
        if token: headers += 'Authorization: Bearer ' + token + '\r\n'
        with socket.create_connection((self.address, self.port), timeout=15) as raw, self.context.wrap_socket(raw, server_hostname=self.host) as tls:
            assert tls.getpeercert(binary_form=True) == self.leaf
            tls.sendall((method + ' ' + path + ' HTTP/1.1\r\n' + headers + '\r\n').encode() + payload)
            with http.client.HTTPResponse(tls) as response:
                response.begin()
                content = response.read(1048577)
                assert len(content) <= 1048576 and response.status in expected, 'Unexpected private response status ' + str(response.status)
                return json.loads(content) if content else {}
