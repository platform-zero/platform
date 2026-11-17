"""Native Hub with a bounded, preallocated per-user container spawner; fixture identities only."""
import asyncio
from datetime import datetime, timezone, timedelta
import hmac
import http.client
import json
import os
import re
import socket
from pathlib import Path
import ssl
import urllib.request
from jupyterhub.auth import Authenticator
from jupyterhub.spawner import Spawner
from tornado.web import HTTPError


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


class NotebookControlConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('p0-notebook-parent', timeout=45)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(45)
        self.sock.connect('/run/p0-notebooks/control.sock')


class FixedContainerSpawner(Spawner):
    def entry(self):
        if self.user.name not in self.assignments or self.name:
            # Native user-visible quota denial, not an accidental 500 or a fallback
            # spawn of a third notebook sharing somebody else's original home.
            raise HTTPError(403, 'No allocated notebook for this principal')
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

    async def parent(self, action, method='GET'):
        entry = self.entry()
        generation = self.notebook_generation
        if (action not in ('start','stop','state') or method not in ('GET','POST') or
            not re.fullmatch(r'q-[a-f0-9]{12}', generation)):
            raise RuntimeError('Unbound notebook lifecycle')
        # This endpoint accepts exactly the assigned user, generation, and
        # Hub-owned per-user control key. Neither Podman nor systemd is exposed
        # to the container. A lost response is never retried with a new ID.
        intent = os.urandom(16).hex() if method == 'POST' else None
        def call():
            connection = NotebookControlConnection()
            try:
                headers = {'Authorization':'Bearer '+entry['parentControlKey'],
                    'X-P0-Generation':generation, 'X-P0-Notebook-User':self.user.name}
                if intent: headers['X-P0-Intent'] = intent
                connection.request(method,'/v1/notebooks/'+self.user.name+'/'+action,
                    body=b'' if method == 'POST' else None,headers=headers)
                response = connection.getresponse()
                data = response.read(1025)
                if len(data) > 1024 or response.getheader('Content-Length') != str(len(data)):
                    raise RuntimeError('Unbounded parent lifecycle response')
                return response.status,data
            finally:
                connection.close()
        return await asyncio.to_thread(call)

    async def start(self):
        self.api_token = self.entry()['serverToken']
        parent, _ = await self.parent('start','POST')
        if parent != 201: raise RuntimeError('Native notebook container start not acknowledged')
        status, _ = await self.request('start', 'POST')
        if status != 201:
            raise RuntimeError('Notebook child start uncertain; parent container remains fenced')
        return 'https://' + self.user.name + ':8888'

    async def poll(self):
        parent, data = await self.parent('state')
        if parent != 200 or json.loads(data)['state'] not in ('running','stopped'):
            raise RuntimeError('Native notebook state requires reconciliation')
        if json.loads(data)['state'] == 'stopped': return 0
        activity = self.user.last_activity
        if not isinstance(activity, datetime):
            raise RuntimeError('No authoritative Hub activity timestamp for idle retirement')
        if activity.tzinfo is None:
            activity = activity.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - activity > timedelta(hours=2):
            await self.stop(now=True)  # One original child stop, then one typed parent STOP.
            return 0
        status, data = await self.request('state')
        state = json.loads(data)['state']
        if status != 200 or state not in ('running', 'stopped'):
            raise RuntimeError('Notebook state requires reconciliation')
        return None if state == 'running' else 0

    async def stop(self, now=False):
        state, data = await self.parent('state')
        if state != 200 or json.loads(data)['state'] != 'running':
            raise RuntimeError('Notebook container not running; no inferred stop ACK')
        status, _ = await self.request('stop', 'POST')
        if status != 204: raise RuntimeError('Notebook child shutdown not acknowledged')
        terminal, _ = await self.parent('stop','POST')
        if terminal != 204: raise RuntimeError('Native container stop uncertain')


def configure(c, settings):
    FixtureAuthenticator.identities = settings['passwords']
    FixedContainerSpawner.assignments = settings['servers']
    FixedContainerSpawner.notebook_generation = settings['notebookGeneration']
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
