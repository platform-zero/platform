"""Source-only negative/error tests for the fixed private-network denial protocol.
Never run during the implementation-only phase.
"""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_qualifier',
    Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/native-qualifier.py')
qualifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualifier)


class NativeQualifierSourceTests(unittest.TestCase):
    def valid(self):
        return {'operation': 'native-network-denial', 'operationId': 'nq-0123456789ab',
                'invocationId': 'case-original-alloy', 'caseClaimSha256': 'a' * 64,
                'qclientPid': 1234, 'qclientContainerId': 'b' * 64,
                'qclientNetnsInode': 45, 'table': 'p0v3_qc_0123456789ab',
                'targetAddress': '10.42.1.9', 'targetPort': 3100,
                'targetContainerId': 'c' * 64, 'targetPid': 5678,
                'targetNetnsInode': 46, 'serviceId': 'alloy',
                'processId': 'loki', 'requestSha256': 'd' * 64}

    def test_foreign_process_port_host_or_claim_rejected_before_namespace(self):
        changes = ({'processId': 'alloy'}, {'targetPort': 3500}, {'targetPort': 443},
                   {'targetAddress': '127.0.0.1'}, {'targetAddress': '8.8.8.8'},
                   {'targetAddress': '::1'}, {'serviceId': 'grafana'},
                   {'qclientNetnsInode': 1}, {'qclientContainerId': 'bad'},
                   {'caseClaimSha256': 'fake'}, {'operation': 'generic-net-client'},
                   {'unexpectedSecret': 'private'})
        with patch.object(qualifier.os, 'open') as opened:
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    qualifier.probe({**self.valid(), **change})
            opened.assert_not_called()

    def test_counter_requires_exact_native_drop_rule(self):
        correct = {'nftables': [
            {'chain': {'name': name, 'policy': 'drop' if name == 'out' else 'accept'}}
            for name in ('dst', 'out', 'in')] + [
            {'rule': {'chain': 'out', 'expr': [{'counter': {'packets': 11}}, {'drop': None}]}}
            for _ in range(7)]}
        with patch.object(qualifier.subprocess, 'run') as process:
            process.return_value.returncode = 0
            process.return_value.stdout = __import__('json').dumps(correct).encode()
            self.assertEqual(11, qualifier.counter('p0v3_qc_0123456789ab'))
            correct['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
            process.return_value.stdout = __import__('json').dumps(correct).encode()
            with self.assertRaises(ValueError):
                qualifier.counter('p0v3_qc_0123456789ab')


if __name__ == '__main__':
    unittest.main()
