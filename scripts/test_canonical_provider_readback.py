import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from canonical_provider_readback import verify_provider


class CanonicalProviderReadbackTest(unittest.TestCase):
    name = 'q-abcdef123456-canonical-core'

    def observed(self):
        def member(networks):
            return {'NetworkSettings': {'Networks': {'p0v3-live-' + self.name + '-' + n: {'IPAddress': '10.89.0.2'} for n in networks}}}
        return [member(['planka-web', 'planka-data']), member(['net', 'db-admin', 'planka-data']), member(['net'])]

    def test_checks_are_native_and_do_not_provision(self):
        results = [subprocess.CompletedProcess([], 0, json.dumps(self.observed()), ''),
                   subprocess.CompletedProcess([], 0, '{"unitFixture": true}', '')]
        with patch('canonical_provider_readback.subprocess.run', side_effect=results) as run:
            self.assertEqual({'unitFixture': True}, verify_provider(self.name, ['dedicated-podman'], {}))
            script = run.call_args.kwargs['input']
            for required in ('pg_stat_ssl', 'rolcanlogin', 'rejectUnauthorized: true', "['42501']", "['28000']", 'net.connect'):
                self.assertIn(required, script)
            self.assertNotIn('PASSWORD', script)
            self.assertEqual(['exec', '-i', 'p0v3-live-' + self.name + '-planka', 'node'], run.call_args.args[0][1:])

    def test_foreign_names_rejected_before_command(self):
        with patch('canonical_provider_readback.subprocess.run') as run:
            for name in ('foundation-r3', '../foreign', 'q-abcdef123456-planka'):
                with self.assertRaises(AssertionError): verify_provider(name, [], {})
            run.assert_not_called()

    def test_unexpected_network_stops_before_client(self):
        observed = self.observed()
        observed[0]['NetworkSettings']['Networks']['foreign'] = {'IPAddress': '10.89.0.3'}
        with patch('canonical_provider_readback.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(observed), '')) as run:
            with self.assertRaises(AssertionError): verify_provider(self.name, [], {})
            self.assertEqual(1, run.call_count)

    def test_failed_inspect_or_native_client_cannot_pass(self):
        for results in ([subprocess.CompletedProcess([], 1, '', '')], [subprocess.CompletedProcess([], 0, json.dumps(self.observed()), ''), subprocess.CompletedProcess([], 1, '', '')]):
            with patch('canonical_provider_readback.subprocess.run', side_effect=results):
                with self.assertRaises(AssertionError): verify_provider(self.name, [], {})

    def test_optimized_execution_refused(self):
        module = Path(__file__).with_name('canonical_provider_readback.py')
        result = subprocess.run([sys.executable, '-O', str(module)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)


if __name__ == '__main__':
    unittest.main()
