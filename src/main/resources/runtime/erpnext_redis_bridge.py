#!/usr/bin/env python3
"""Fixed authenticated ERPNext Frappe-15.125.0/RQ-1.15.1 Redis protocol bridge.

One shared Valkey remains the storage owner. Only this isolated process receives its
native ACL credential. ERP clients receive a DIFFERENT bridge credential and cannot
join cache-data. The exact native RQ/cache key/channel ACL is an additional boundary.
Valkey 7.2.15 KEYS has no ACL key spec: permit ONLY a site-qualified cache query;
never allow arbitrary SCAN, metadata enumeration, scripting or other product keys.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re

LIMIT = 1048576
SITE_PREFIX = b'p0_erp|'
QUEUE_PREFIX = b'rq:queue:p0v3-erp:'
CHANNELS = {b'events', b'open_in_editor'}
AUTH_USER = b'erp-app'
PROVIDER_USER = b'erpnext'
FORBIDDEN = {b'SCAN', b'SSCAN', b'HSCAN', b'ZSCAN', b'RANDOMKEY', b'PUBSUB',
             b'FLUSHALL', b'FLUSHDB', b'SWAPDB', b'MONITOR', b'CONFIG', b'ACL',
             b'FUNCTION', b'MODULE', b'MIGRATE', b'RESTORE', b'RENAME', b'RENAMENX',
             b'SORT', b'COPY', b'EVAL', b'DUMP', b'OBJECT', b'PSUBSCRIBE', b'PUNSUBSCRIBE'}
KEY_PATTERN = re.compile(rb'p0_erp\|[a-zA-Z0-9_@:.|/*-]{0,128}')
QUEUE_PATTERN = re.compile(rb'rq:queue:p0v3-erp:(short|default|long)')
WORKER_CHANNEL = re.compile(rb'rq:pubsub:[a-zA-Z0-9_.:@-]{1,128}')

# Exact original RQ 1.15.1 rq/queue.py Queue.empty register_script bytes.
# Internally it deletes rq:job:<original-site>::<job-id>, constrained by the
# provider's fixed native rq:[^q]* key ACL. Never accept arbitrary Lua text.
RQ_EMPTY = ('\n'
    '            local prefix = "rq:job:"\n'
    '            local q = KEYS[1]\n'
    '            local count = 0\n'
    '            while true do\n'
    '                local job_id = redis.call("lpop", q)\n'
    '                if job_id == false then\n'
    '                    break\n'
    '                end\n'
    '\n'
    '                -- Delete the relevant keys\n'
    '                redis.call("del", prefix..job_id)\n'
    '                redis.call("del", prefix..job_id..":dependents")\n'
    '                count = count + 1\n'
    '            end\n'
    '            return count\n'
    '        ').encode()
RQ_EMPTY_SHA = hashlib.sha1(RQ_EMPTY).hexdigest().encode()


def verify_pinned_image():
    """Pure readback before networking/listening. The signed source manifest is
    produced by fixed Kotlin constants, not supplied by an application process.
    A changing tag/latest-release timestamp is never substituted for exact bytes.
    """
    source = Path('/run/secrets/erp-source-attestation.json')
    pinned = json.loads(source.read_text())
    if (set(pinned) != {'frappeVersion', 'rqVersion', 'redisVersion', 'hashes'} or
        pinned['frappeVersion'] != '15.125.0' or pinned['rqVersion'] != '1.15.1' or
        pinned['redisVersion'] != '4.5.5' or len(pinned['hashes']) != 14):
        raise ValueError('Foreign pinned Frappe/RQ source manifest')
    for package, version in [('frappe', '15.125.0'), ('rq', '1.15.1'), ('redis', '4.5.5')]:
        if importlib.metadata.version(package) != version:
            raise ValueError('ERP image dependency version changed')
    frappe = Path('/home/frappe/frappe-bench/apps/frappe')
    rq = Path(importlib.metadata.distribution('rq').locate_file('rq'))
    for name, expected in pinned['hashes'].items():
        if (not re.fullmatch(r'[a-f0-9]{64}', expected) or
            name not in {
                'frappe/installer.py', 'frappe/commands/site.py',
                'frappe/utils/redis_wrapper.py', 'frappe/utils/redis_queue.py',
                'frappe/utils/background_jobs.py', 'frappe/database/__init__.py',
                'frappe/database/mariadb/database.py', 'frappe/database/db_manager.py',
                'frappe/realtime.py', 'realtime/index.js', 'node_utils.js',
                'rq/queue.py', 'rq/worker.py', 'rq/command.py'}):
            raise ValueError('Foreign ERP source file')
        path = (rq / name.removeprefix('rq/')) if name.startswith('rq/') else frappe / name
        if (not path.is_file() or path.is_symlink() or path.stat().st_size > LIMIT or
            hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError('Pinned ERP image source changed')


def frame(*parts):
    return b'*' + str(len(parts)).encode() + b'\r\n' + b''.join(
        b'$' + str(len(part)).encode() + b'\r\n' + part + b'\r\n' for part in parts)


async def request(reader):
    line = await reader.readline()
    if not line or not line.endswith(b'\r\n') or len(line) > 32 or not line.startswith(b'*'):
        raise ValueError('Only bounded RESP arrays accepted')
    count = int(line[1:-2])
    if count not in range(1, 1025):
        raise ValueError('Invalid request arity')
    parts = []
    total = 0
    for _ in range(count):
        size_line = await reader.readline()
        if not size_line.endswith(b'\r\n') or len(size_line) > 32 or not size_line.startswith(b'$'):
            raise ValueError('Only bounded bulk strings accepted')
        size = int(size_line[1:-2])
        if size < 0 or size > LIMIT or total + size > LIMIT:
            raise ValueError('Request exceeds fixed bound')
        data = await reader.readexactly(size + 2)
        if data[-2:] != b'\r\n':
            raise ValueError('Invalid bulk terminator')
        parts.append(data[:-2]); total += size
    return parts


def permitted(parts):
    command = parts[0].upper()
    if command in FORBIDDEN:
        return False
    if command == b'SCRIPT':
        return len(parts) == 3 and parts[1].upper() == b'LOAD' and parts[2] == RQ_EMPTY
    if command == b'EVALSHA':
        return (len(parts) == 4 and parts[1].lower() == RQ_EMPTY_SHA and
                parts[2] == b'1' and QUEUE_PATTERN.fullmatch(parts[3]) is not None)
    if command == b'KEYS':
        return (len(parts) == 2 and KEY_PATTERN.fullmatch(parts[1]) is not None and
                parts[1].startswith(SITE_PREFIX))
    if command == b'SELECT':
        return len(parts) == 2 and parts[1] == b'0'
    if command in (b'PUBLISH', b'SUBSCRIBE', b'UNSUBSCRIBE'):
        channels = parts[1:2] if command == b'PUBLISH' else parts[1:]
        if command == b'PUBLISH' and len(parts) != 3:
            return False
        if command == b'UNSUBSCRIBE' and not channels:
            return True  # This connection could only subscribe to approved channels.
        return bool(channels) and all(
            channel in CHANNELS or WORKER_CHANNEL.fullmatch(channel) is not None
            for channel in channels)
    if command == b'HELLO':
        return len(parts) == 2 and parts[1] in (b'2', b'3')
    return command not in (b'AUTH', b'QUIT')


async def relay(source, target):
    while data := await source.read(65536):
        target.write(data)
        await target.drain()


async def client_connected(client_reader, client_writer):
    upstream = None
    try:
        client_password = os.environ['ERP_CLIENT_PASSWORD'].encode('ascii')
        provider_password = os.environ['ERP_PROVIDER_PASSWORD'].encode('ascii')
        if (not all(re.fullmatch(rb'[a-f0-9]{64}', p) for p in (client_password, provider_password)) or
                client_password == provider_password):
            raise ValueError('Distinct sealed bridge and provider keys required')
        upstream_reader, upstream = await asyncio.wait_for(asyncio.open_connection('valkey', 6379), 5)
        upstream.write(frame(b'AUTH', PROVIDER_USER, provider_password))
        await upstream.drain()
        if await asyncio.wait_for(upstream_reader.readexactly(5), 5) != b'+OK\r\n':
            raise ValueError('Native provider ACL authentication denied')
        first = await asyncio.wait_for(request(client_reader), 5)
        if not ((len(first) == 3 and first[0].upper() == b'AUTH' and
                 first[1] == AUTH_USER and first[2] == client_password) or
                (len(first) == 5 and first[0].upper() == b'HELLO' and
                 first[1] in (b'2', b'3') and first[2].upper() == b'AUTH' and
                 first[3] == AUTH_USER and first[4] == client_password)):
            raise ValueError('Exact bridge authentication required')
        if first[0].upper() == b'AUTH':
            client_writer.write(b'+OK\r\n')
        else:
            upstream.write(frame(b'HELLO', first[1])); await upstream.drain()
        await client_writer.drain()

        async def commands():
            while True:
                parts = await request(client_reader)
                if not permitted(parts):
                    raise ValueError('Foreign native Redis command or key enumeration')
                upstream.write(frame(*parts)); await upstream.drain()
        tasks = [asyncio.create_task(commands()), asyncio.create_task(relay(upstream_reader, client_writer))]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass  # Deny by closing connection; never retry or print private payloads.
    finally:
        client_writer.close()
        if upstream: upstream.close()


async def main():
    verify_pinned_image()
    server = await asyncio.start_server(client_connected, '0.0.0.0', 6379, limit=LIMIT + 4096)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
