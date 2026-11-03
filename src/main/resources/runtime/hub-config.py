"""Native Hub with a bounded, preallocated per-user container spawner; fixture identities only."""
import asyncio
import hmac
import json
import os
from pathlib import Path
import ssl
import urllib.request
from jupyterhub.auth import Authenticator
from jupyterhub.spawner import Spawner


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FixtureAuthenticator(Authenticator):
    async def authenticate(self, handler, data):
        username = data.get('username', '')
        password = data.get('password', '')
        expected = self.identities.get(username)
        if expected is not None and hmac.compare_digest(password.encode(), expected.encode()):
            return username
        return None


class FixedContainerSpawner(Spawner):
    def entry(self):
        if self.user.name not in self.assignments or self.name:
            raise ValueError('No allocated notebook for this principal')
        return self.assignments[self.user.name]

    async def request(self, action, method='GET'):
        entry = self.entry()
        context = ssl.create_default_context(cafile='/run/secrets/trust.pem')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        request = urllib.request.Request('https://' + self.user.name + ':8444/' + action,
            data=b'' if method == 'POST' else None, method=method,
            headers={'Authorization': 'Bearer ' + entry['controlKey']})
        def call():
            # Administrative calls are made once; redirects and ambiguous retries are forbidden.
            with opener.open(request, timeout=45) as response:
                data = response.read(1025)
                if len(data) > 1024:
                    raise ValueError('Lifecycle response exceeded bound')
                return response.status, data
        return await asyncio.to_thread(call)

    async def start(self):
        self.api_token = self.entry()['serverToken']
        status, _ = await self.request('start', 'POST')
        if status != 201:
            raise RuntimeError('Notebook start was not acknowledged')
        return 'https://' + self.user.name + ':8888'

    async def poll(self):
        status, data = await self.request('state')
        state = json.loads(data)['state']
        if status != 200 or state not in ('running', 'stopped'):
            raise RuntimeError('Notebook state requires reconciliation')
        return None if state == 'running' else 0

    async def stop(self, now=False):
        status, _ = await self.request('stop', 'POST')
        if status != 204:
            raise RuntimeError('Notebook shutdown was not clean')


def configure(c, settings):
    FixtureAuthenticator.identities = settings['passwords']
    FixedContainerSpawner.assignments = settings['servers']
    c.JupyterHub.authenticator_class = FixtureAuthenticator
    c.Authenticator.allowed_users = set(settings['passwords'])
    c.Authenticator.admin_users = set()
    c.JupyterHub.spawner_class = FixedContainerSpawner
    c.JupyterHub.allow_named_servers = False
    c.JupyterHub.admin_access = False
    c.JupyterHub.cleanup_servers = True
    c.JupyterHub.bind_url = 'http://0.0.0.0:8000'
    c.JupyterHub.hub_bind_url = 'http://0.0.0.0:8081'
    # CHP shares this container; its default route must not loop back through user-origin ingress.
    # Remote single-user servers have an explicit verified-HTTPS API URL in immutable inputs.
    c.JupyterHub.hub_connect_url = 'http://127.0.0.1:8081'
    c.JupyterHub.public_url = 'https://hub:8443/'
    c.JupyterHub.subdomain_host = 'https://hub:8443'
    c.JupyterHub.cookie_host_prefix_enabled = True
    c.JupyterHub.db_url = 'sqlite:////state/hub.sqlite'
    c.JupyterHub.cookie_secret_file = '/state/cookie-secret'
    c.JupyterHub.pid_file = '/tmp/hub.pid'
    c.JupyterHub.log_level = 'WARN'
    c.ConfigurableHTTPProxy.auth_token = settings['proxyToken']
    c.ConfigurableHTTPProxy.debug = False
    c.ConfigurableHTTPProxy.pid_file = '/tmp/proxy.pid'
    c.Spawner.default_url = '/lab'
    c.Spawner.start_timeout = 90
    c.Spawner.http_timeout = 90
    c.Spawner.poll_interval = 30
    c.Spawner.disable_user_config = True


if 'get_config' in globals():
    configure(get_config(), json.loads(Path('/run/secrets/hub-settings.json').read_text()))
