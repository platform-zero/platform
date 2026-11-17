"""Injected, source-only ERP cache isolation regressions; never import an image/runtime."""
import asyncio
import os
import unittest
from unittest.mock import patch

import erpnext_redis_bridge as bridge


class FakeWriter:
    def __init__(self):
        self.sent = bytearray()
        self.closed = False

    def write(self, payload):
        self.sent.extend(payload)

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class ErpBridgeSourceTest(unittest.TestCase):
    def test_native_site_qualified_keys_and_other_product_enumeration_denied(self):
        permitted = bridge.permitted
        self.assertTrue(permitted([b'KEYS', b'p0_erp|account:*']))
        for pattern in (b'*', b'rq:*', b'cache:*', b'app:other:*', b'p0_er*',
                        b'p0_erp|[a-z]*', b'p0_erp|\\*'):
            self.assertFalse(permitted([b'KEYS', pattern]))
        for command in (b'SCAN', b'SSCAN', b'HSCAN', b'ZSCAN', b'RANDOMKEY',
                        b'PUBSUB', b'CONFIG', b'ACL', b'FLUSHDB', b'FLUSHALL',
                        b'EVAL', b'MODULE', b'MIGRATE', b'RESTORE', b'OBJECT', b'DUMP'):
            self.assertFalse(permitted([command, b'*']))
        self.assertFalse(permitted([b'SELECT', b'1']))
        self.assertTrue(permitted([b'SELECT', b'0']))

    def test_exact_native_realtime_and_rq_channels_not_arbitrary_sidekiq_or_matrix(self):
        for channel in (b'events', b'open_in_editor', b'rq:pubsub:worker-123'):
            self.assertTrue(bridge.permitted([b'SUBSCRIBE', channel]))
            self.assertTrue(bridge.permitted([b'PUBLISH', channel, b'original-state']))
        for channel in (b'timeline:public', b'queue:default', b'others', b'rq:pubsub:*',
                        b'rq:pubsub:worker\nadmin', b'app:other:event'):
            self.assertFalse(bridge.permitted([b'SUBSCRIBE', channel]))
            self.assertFalse(bridge.permitted([b'PUBLISH', channel, b'x']))
        self.assertFalse(bridge.permitted([b'PSUBSCRIBE', b'*']))
        self.assertFalse(bridge.permitted([b'PUBLISH', b'events']))

    def test_rq_clearing_lua_must_be_exact_original_source_and_only_owned_queue(self):
        self.assertTrue(bridge.permitted([b'SCRIPT', b'LOAD', bridge.RQ_EMPTY]))
        self.assertTrue(bridge.permitted([b'EVALSHA', bridge.RQ_EMPTY_SHA, b'1',
                                          b'rq:queue:p0v3-erp:default']))
        self.assertFalse(bridge.permitted([b'SCRIPT', b'LOAD', bridge.RQ_EMPTY + b'\nredis.call("keys","*")']))
        self.assertFalse(bridge.permitted([b'EVALSHA', bridge.RQ_EMPTY_SHA, b'1',
                                           b'rq:queue:other:default']))
        self.assertFalse(bridge.permitted([b'EVALSHA', bridge.RQ_EMPTY_SHA, b'0']))
        self.assertFalse(bridge.permitted([b'EVALSHA', b'0' * 40, b'1',
                                           b'rq:queue:p0v3-erp:short']))

    def test_bounded_resp_rejects_inline_null_or_oversized_and_never_forwards(self):
        async def parse(payload):
            reader = asyncio.StreamReader()
            reader.feed_data(payload); reader.feed_eof()
            return await bridge.request(reader)
        self.assertEqual([b'PING'], asyncio.run(parse(bridge.frame(b'PING'))))
        for payload in (b'KEYS *\r\n', b'*-1\r\n', b'*1\r\n$-1\r\n',
                        b'*1\r\n$2\r\na', b'*1\r\n$999999999999\r\n'):
            with self.assertRaises((ValueError, asyncio.IncompleteReadError)):
                asyncio.run(parse(payload))

    def test_foreign_client_password_aborts_before_any_provider_command(self):
        async def run():
            client = asyncio.StreamReader()
            client.feed_data(bridge.frame(b'AUTH', b'erp-app', b'foreign'))
            client.feed_eof()
            provider = asyncio.StreamReader()
            provider.feed_data(b'+OK\r\n')
            upstream = FakeWriter(); downstream = FakeWriter()
            async def connect(host, port):
                self.assertEqual(('valkey', 6379), (host, port))
                return provider, upstream
            with patch.dict(os.environ, {'ERP_CLIENT_PASSWORD': 'a' * 64,
                                         'ERP_PROVIDER_PASSWORD': 'b' * 64}), \
                    patch.object(bridge.asyncio, 'open_connection', side_effect=connect):
                await bridge.client_connected(client, downstream)
            self.assertTrue(downstream.closed)
            self.assertTrue(upstream.closed)
            self.assertEqual(bridge.frame(b'AUTH', b'erpnext', b'b' * 64), bytes(upstream.sent))
            self.assertEqual(b'', bytes(downstream.sent))
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
