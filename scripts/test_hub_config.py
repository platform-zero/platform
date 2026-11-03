"""Mock-only native Hub adapter tests; no SDK service, requests, credentials or processes."""
import importlib.util
import json
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).parents[1] / 'src/main/resources/runtime/hub-config.py'
modules = {name: types.ModuleType(name) for name in ('jupyterhub', 'jupyterhub.auth', 'jupyterhub.spawner')}
modules['jupyterhub.auth'].Authenticator = type('Authenticator', (), {})
modules['jupyterhub.spawner'].Spawner = type('Spawner', (), {})
with patch.dict(sys.modules, modules):
    spec = importlib.util.spec_from_file_location('hub_config', SOURCE)
    config = importlib.util.module_from_spec(spec); spec.loader.exec_module(config)


def settings():
    return {'passwords': {'alice': '1'*64, 'bob': '2'*64, 'outsider': '3'*64}, 'proxyToken': '4'*64,
            'servers': {'alice': {'serverToken': '5'*64, 'controlKey': '6'*64}, 'bob': {'serverToken': '7'*64, 'controlKey': '8'*64}}}


def traits():
    return types.SimpleNamespace(**{name: types.SimpleNamespace() for name in ('JupyterHub', 'Authenticator', 'ConfigurableHTTPProxy', 'Spawner')})


class HubConfigTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.c = traits(); config.configure(self.c, settings())
        self.spawner = config.FixedContainerSpawner()
        self.spawner.user = types.SimpleNamespace(name='alice'); self.spawner.name = ''

    async def test_fixture_authentication_and_no_admin_or_cross_origin_cookies(self):
        auth = config.FixtureAuthenticator()
        self.assertEqual(await auth.authenticate(None, {'username': 'alice', 'password': '1'*64}), 'alice')
        for data in ({}, {'username': 'foreign', 'password': '1'*64}, {'username': 'alice', 'password': '2'*64}):
            self.assertIsNone(await auth.authenticate(None, data))
        self.assertFalse(self.c.JupyterHub.admin_access)
        self.assertFalse(self.c.JupyterHub.allow_named_servers)
        self.assertTrue(self.c.JupyterHub.cookie_host_prefix_enabled)
        self.assertTrue(self.c.JupyterHub.cleanup_servers)
        self.assertEqual(self.c.JupyterHub.subdomain_host, 'https://hub:8443')
        self.assertEqual(self.c.JupyterHub.hub_connect_url, 'http://127.0.0.1:8081')
        self.assertEqual(self.c.Authenticator.admin_users, set())
        self.assertEqual(config.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://foreign.invalid'), None)

    async def test_no_dynamic_users_or_named_servers(self):
        self.spawner.user.name = 'outsider'
        with self.assertRaises(ValueError): self.spawner.entry()
        self.spawner.user.name = 'alice'; self.spawner.name = 'other'
        with self.assertRaises(ValueError): self.spawner.entry()

    async def test_native_lifecycle_acknowledgments_and_failures(self):
        async def request(action, method='GET'):
            self.assertIn((action, method), [('start', 'POST'), ('state', 'GET'), ('stop', 'POST')])
            return {'start': (201, b''), 'state': (200, b'{"state":"running"}'), 'stop': (204, b'')}[action]
        self.spawner.request = request
        self.assertEqual(await self.spawner.start(), 'https://alice:8888')
        self.assertEqual(self.spawner.api_token, '5'*64)
        self.assertIsNone(await self.spawner.poll()); await self.spawner.stop()
        for status, body, operation, failure in [(409,b'', 'start',True), (500,b'', 'stop',True), (200,b'{"state":"blocked"}','poll',True), (500,b'{"state":"running"}','poll',True), (200,b'{"state":"stopped"}','poll',False)]:
            async def response(*args): return status, body
            self.spawner.request = response
            if failure:
                with self.assertRaises(RuntimeError): await getattr(self.spawner, operation)()
            else: self.assertEqual(await self.spawner.poll(), 0)

    async def test_https_control_is_fixed_bounded_no_proxy_redirect_or_retry(self):
        response = Mock(); response.status = 201; response.read.return_value = b''
        manager = Mock(); manager.__enter__ = Mock(return_value=response); manager.__exit__ = Mock(return_value=False)
        opener = Mock(); opener.open.return_value = manager
        with patch.object(config.ssl, 'create_default_context') as tls, patch.object(config.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(await self.spawner.request('start', 'POST'), (201, b''))
            req = opener.open.call_args.args[0]
            self.assertEqual(req.full_url, 'https://alice:8444/start')
            self.assertEqual(req.method, 'POST'); self.assertEqual(req.data, b'')
            self.assertEqual(req.get_header('Authorization'), 'Bearer ' + '6'*64)
            tls.assert_called_once_with(cafile='/run/secrets/trust.pem')
            response.read.assert_called_once_with(1025)
            response.read.return_value = b'x'*1025
            with self.assertRaises(ValueError): await self.spawner.request('state')
            opener.open.reset_mock(); opener.open.side_effect = TimeoutError('ambiguous write')
            with self.assertRaises(TimeoutError): await self.spawner.request('start', 'POST')
            opener.open.assert_called_once()

    async def test_native_configuration_entrypoint(self):
        c = traits()
        with patch.dict(sys.modules, modules), patch.object(Path, 'read_text', return_value=json.dumps(settings())):
            runpy.run_path(str(SOURCE), init_globals={'get_config': lambda: c})
        self.assertEqual(c.JupyterHub.public_url, 'https://hub:8443/')
        self.assertEqual(c.ConfigurableHTTPProxy.pid_file, '/tmp/proxy.pid')


if __name__ == '__main__':
    unittest.main()
