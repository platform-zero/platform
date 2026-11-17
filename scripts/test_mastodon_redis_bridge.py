"""Fixed Mastodon v4.7.4/Sidekiq8.1.6/SUJ8.1.0 broker source regressions; unexecuted."""
if not __debug__:
    raise SystemExit('Optimized test imports forbidden')
import hashlib
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/mastodon_redis_bridge.py'
spec = importlib.util.spec_from_file_location('mastodon_native_redis_bridge', SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class FixedMastodonNativeRedisProfile(unittest.TestCase):
    generation = 'q-abcdef123456'
    lua = b'return redis.call("HGET", KEYS[1], ARGV[1])'
    sha = hashlib.sha1(lua).hexdigest()

    def profile(self):
        return bridge.Profile(self.generation, {self.sha: hashlib.sha256(self.lua).hexdigest()})

    def test_native_unprefixed_sidekiq_rails_streaming_and_suj_are_admitted(self):
        profile = self.profile()
        for key in (b'feed:home:42', b'cache:accounts/42', b'queue:default', b'queues', b'processes',
                    b'schedule', b'retry', b'dead', b'schedules', b'schedules_changed',
                    b'sidekiq-scheduler:states', b'uniquejobs:a:RUN:LOCKED',
                    b'p0v3-mastodon-q-abcdef123456:123:abcdef123456:work',
                    b'subscribed:timeline:42:notifications'):
            profile.key(key)
        profile.check([b'SCRIPT', b'LOAD', self.lua])
        profile.check([b'EVALSHA', self.sha.encode(), b'1', b'uniquejobs:a:RUN:LOCKED', b'arg'])
        profile.check([b'SSCAN', b'processes', b'0', b'COUNT', b'50'])
        profile.check([b'PUBLISH', b'timeline:direct:42', b'event'])
        profile.check([b'SUBSCRIBE', b'timeline:42:notifications'])
        profile.check([b'PUBLISH', b'uniquejobs:changelog', b'entry'])
        self.assertEqual('INFO', profile.check([b'INFO']))
        self.assertEqual('INFO', profile.check([b'INFO', b'server']))

    def test_unknown_keys_cross_generation_global_metadata_and_script_bypass_fail_closed(self):
        profile = self.profile()
        for operation in ([b'GET', b'app:erp:secret'], [b'SET', b'app:mastodon:fictional', b'x'],
                          [b'GET', b'p0v3-mastodon-q-111111111111:123:abcdef123456:work'],
                          [b'DEL', b'queue:default', b'app:erp:secret'], [b'INFO', b'keyspace'], [b'CONFIG', b'GET', b'*'],
                          [b'PUBSUB', b'CHANNELS'], [b'ACL', b'LIST'], [b'MONITOR'], [b'MIGRATE'],
                          [b'FLUSHALL'], [b'SELECT', b'0'], [b'SCAN', b'0'], [b'KEYS', b'*'],
                          [b'PUBLISH', b'erp:events', b'leak'], [b'SUBSCRIBE', b'erp:events'],
                          [b'SCRIPT', b'FLUSH', self.lua], [b'SCRIPT', b'LOAD', self.lua + b' '],
                          [b'EVAL', self.lua, b'0'], [b'EVALSHA', b'0' * 40, b'0']):
            with self.subTest(operation=operation[0]):
                with self.assertRaises(ValueError): profile.check(operation)

    def test_native_multi_key_script_shape_and_budget_reject_missing_foreign_or_huge(self):
        profile = self.profile()
        for operation in ([b'DEL'], [b'MSET', b'queue:default'],
                          [b'BLPOP', b'queue:default', b'60'],
                          [b'EVALSHA', self.sha.encode(), b'2', b'uniquejobs:a'],
                          [b'EVALSHA', self.sha.encode(), b'2', b'uniquejobs:a', b'erp:private'],
                          [b'SCAN', b'0', b'MATCH', b'*', b'COUNT', b'50'],
                          [b'SCAN', b'0', b'MATCH', b'uniquejobs:*', b'COUNT', b'999999']):
            with self.subTest(operation=operation[0]):
                with self.assertRaises(ValueError): profile.check(operation)

    def test_hello_sanitizes_global_provider_id_and_refuses_modules(self):
        values = [b'server', b'valkey', b'version', b'8.1.1', b'proto', b'3',
                  b'id', b'987654', b'mode', b'standalone', b'role', b'master', b'modules', []]
        sanitized = bridge.public_hello(b'%', values, b'3', b'8.1.1')
        self.assertNotIn(b'987654', sanitized)
        self.assertIn(b':0\r\n', sanitized)
        with self.assertRaises(ValueError):
            bridge.public_hello(b'%', values[:-1] + [[b'private-module']], b'3', b'8.1.1')
        with self.assertRaises(ValueError):
            bridge.public_hello(b'%', values, b'3', b'8.1.2')

    def test_frontend_virtual_db0_only_never_grants_provider_select(self):
        self.assertTrue(bridge.virtual_select([b'SELECT', b'0']))
        self.assertTrue(bridge.virtual_select([b'select', b'0']))
        self.assertFalse(bridge.virtual_select([b'PING']))
        for operation in ([b'SELECT', b'1'], [b'SELECT', b'0', b'1'], [b'SELECT', b'-1']):
            with self.assertRaises(ValueError): bridge.virtual_select(operation)

    def test_script_load_lost_ack_readback_never_resends_global_script(self):
        class Native:
            def __init__(self, response):
                self.replies = bytearray(response); self.sent = []
            def sendall(self, value): self.sent.append(value)
            def recv(self, count):
                result = self.replies[:count]; del self.replies[:count]
                return bytes(result)
        sha = self.sha.encode()
        with tempfile.TemporaryDirectory() as directory:
            broker = bridge.Bridge.__new__(bridge.Bridge)
            broker.profile = self.profile(); broker.journal = directory
            broker.scriptLock = threading.Lock()
            first = Native(b'+' + sha + b'\r\n*1\r\n:1\r\n')
            self.assertEqual(broker.script_load(first, [b'SCRIPT', b'LOAD', self.lua]), b'+' + sha + b'\r\n')
            self.assertEqual(len(first.sent), 2)  # one LOAD, one exact SHA readback
            lost = Native(b'*1\r\n:1\r\n')
            self.assertEqual(broker.script_load(lost, [b'SCRIPT', b'LOAD', self.lua]), b'+' + sha + b'\r\n')
            self.assertEqual(lost.sent, [bridge.frame((b'SCRIPT', b'EXISTS', sha))])
            missing = Native(b'*1\r\n:0\r\n')
            with self.assertRaises(ValueError):
                broker.script_load(missing, [b'SCRIPT', b'LOAD', self.lua])
            self.assertEqual(missing.sent, [bridge.frame((b'SCRIPT', b'EXISTS', sha))])

    def test_resp_wire_is_bounded_and_roundtrips_binary_native_lua(self):
        receiver, sender = socket.socketpair()
        try:
            data = bridge.frame([b'SCRIPT', b'LOAD', self.lua + b'\x00'])
            sender.sendall(data)
            marker, items, raw = bridge.read_frame(receiver)
            self.assertEqual(marker, b'*')
            self.assertEqual(items, [b'SCRIPT', b'LOAD', self.lua + b'\x00'])
            self.assertEqual(raw, data)
            sender.sendall(b'*1\r\n$9999999999\r\n')
            with self.assertRaises(ValueError): bridge.read_frame(receiver)
        finally:
            sender.close(); receiver.close()


if __name__ == '__main__':
    unittest.main()
