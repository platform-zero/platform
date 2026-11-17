#!/usr/bin/env python3
"""Fixed Mastodon v4.7.4 Redis protocol broker; NOT an arbitrary Redis proxy.

One generation, one provider, one isolated logical DB. The application is connected
ONLY to this bridge network. Provider administration credentials never reach Rails,
Sidekiq or streaming. No original data is imported by this process. An authenticated
native copy/import producer and controller must bind the rendered SUJ 8.1.0 scripts
and complete provider ACL BEFORE starting this bridge. Unexpected commands fail
closed, including metadata, Lua and SELECT. No fallback Redis service is started.
"""
if not __debug__:
    raise SystemExit('Optimized Python forbidden before Mastodon broker imports/effects')
import hashlib
import hmac
import json
import os
import re
import select
import socket
import stat
import sys
import threading

VERSION = ('mastodon-4.7.4', 'sidekiq-8.1.6', 'sidekiq-unique-jobs-8.1.0', 'sidekiq-scheduler-6.0.2')
GENERATION = re.compile(r'q-[a-f0-9]{12}\Z')
SHA1 = re.compile(r'[a-f0-9]{40}\Z')
SHA256 = re.compile(r'[a-f0-9]{64}\Z')
TOKEN = re.compile(r'[a-zA-Z0-9_-]{32,128}\Z')
CHANNEL = re.compile(rb'(?:timeline:[a-z0-9:_-]{1,128}|uniquejobs:[a-zA-Z0-9:_-]{1,128})\Z')
PROCESS = re.compile(rb'p0v3-mastodon-q-[a-f0-9]{12}:[0-9]+:[a-f0-9]{12}(?::work|-signals)?\Z')
KEY = re.compile(rb'(?:feed:[a-zA-Z0-9:_-]{1,180}|cache:[^\r\n\x00]{1,180}|queue:[a-zA-Z0-9_-]{1,90}|'
                 rb'uniquejobs:[a-zA-Z0-9:_-]{1,180}|subscribed:timeline:[a-z0-9:_-]{1,128}|'
                 rb'stat:[a-z0-9:_-]{1,90}|sidekiq-scheduler:[a-z0-9:_-]{1,90})\Z')
LITERAL_KEYS = {b'queues', b'schedule', b'retry', b'dead', b'processes', b'schedules',
                b'schedules_changed', b'sidekiq-scheduler:states'}
SINGLE = frozenset('GET SET SETEX PSETEX GETDEL GETSET GETEX SETNX INCR INCRBY INCRBYFLOAT DECR '
                   'DECRBY EXPIRE EXPIREAT PEXPIRE PEXPIREAT TTL PTTL PERSIST TYPE '
                   'HGET HSET HSETNX HGETALL HMGET HMSET HDEL HLEN HEXISTS HINCRBY HSCAN '
                   'SADD SREM SCARD SMEMBERS SISMEMBER SSCAN SPOP SRANDMEMBER '
                   'ZADD ZREM ZCARD ZSCORE ZRANGE ZREVRANGE ZRANGEBYSCORE ZREVRANGEBYSCORE '
                   'ZREMRANGEBYSCORE ZREMRANGEBYRANK ZCOUNT ZSCAN ZINCRBY '
                   'LPUSH RPUSH LPOP RPOP LLEN LREM LRANGE LTRIM LINDEX LSET'.split())
MULTIKEY = frozenset('DEL EXISTS MGET UNLINK WATCH RPOPLPUSH BRPOPLPUSH'.split())
BLOCKING = frozenset('BLPOP BRPOP BLMOVE'.split())
NO_KEYS = frozenset('PING ECHO QUIT MULTI EXEC DISCARD UNWATCH'.split())
MAX_FRAME = 2 * 1024 * 1024
MAX_BULK = 1024 * 1024
MAX_ARGS = 1024
MAX_CLIENTS = 24


def private(path, maximum=262144):
    if not os.path.isabs(path) or os.path.normpath(path) != path or os.path.islink(path):
        raise ValueError('Unsafe broker input path')
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
            info.st_mode & 0o077 or info.st_size not in range(1, maximum + 1)):
        raise ValueError('Unsafe broker input custody')
    with open(path, 'rb') as source:
        data = source.read(maximum + 1)
    if len(data) != info.st_size:
        raise ValueError('Broker custody changed during read')
    return data


def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('Foreign broker or native script manifest')
    return value


class Profile:
    """Release-specific, generation-bound native key/channel/command/script surface."""
    def __init__(self, generation, scripts):
        if not GENERATION.fullmatch(generation) or type(scripts) is not dict or not scripts or len(scripts) > 64:
            raise ValueError('Unpinned SUJ 8.1.0 script profile')
        self.generation = generation.encode()
        self.scripts = {}
        for sha, digest in scripts.items():
            if not SHA1.fullmatch(sha) or not SHA256.fullmatch(digest):
                raise ValueError('Foreign rendered SUJ script digest')
            self.scripts[sha.encode()] = digest

    def key(self, key):
        if not 1 <= len(key) <= 200 or not (KEY.fullmatch(key) or PROCESS.fullmatch(key) and
                key.startswith(b'p0v3-mastodon-' + self.generation + b':') or key in LITERAL_KEYS):
            raise ValueError('Unknown or foreign native Mastodon key')

    def channel(self, channel):
        if not CHANNEL.fullmatch(channel) or len(channel) > 180:
            raise ValueError('Unknown/foreign native PubSub channel')

    def check(self, argv):
        if not argv or len(argv) > MAX_ARGS or sum(map(len, argv)) > MAX_FRAME:
            raise ValueError('Unbounded Redis request')
        try:
            cmd = argv[0].decode('ascii').upper()
        except UnicodeDecodeError as error:
            raise ValueError('Non-ASCII Redis command') from error
        if cmd in SINGLE:
            if len(argv) < 2: raise ValueError('Missing Redis key')
            self.key(argv[1])
            if cmd in ('HSCAN', 'SSCAN', 'ZSCAN'):
                if len(argv) < 3 or not argv[2].isdigit(): raise ValueError('Invalid keyed scan cursor')
                options = argv[3:]
                while options:
                    if len(options) < 2 or options[0].upper() not in (b'MATCH', b'COUNT'):
                        raise ValueError('Unbounded keyed native scan')
                    if options[0].upper() == b'COUNT' and (not options[1].isdigit() or int(options[1]) > 1024):
                        raise ValueError('Unbounded keyed scan COUNT')
                    if options[0].upper() == b'MATCH' and len(options[1]) > 180:
                        raise ValueError('Unbounded keyed scan MATCH')
                    options = options[2:]
        elif cmd in MULTIKEY:
            if cmd in ('RPOPLPUSH', 'BRPOPLPUSH'):
                if len(argv) != (4 if cmd == 'BRPOPLPUSH' else 3):
                    raise ValueError('Invalid two-key queue operation')
                if cmd == 'BRPOPLPUSH' and (not argv[3].replace(b'.', b'', 1).isdigit() or float(argv[3]) > 5):
                    raise ValueError('Blocking queue operation exceeds limit')
                keys = argv[1:3]
            else:
                if len(argv) < 2: raise ValueError('Missing Redis keys')
                keys = argv[1:]
            for value in keys: self.key(value)
        elif cmd in BLOCKING:
            if cmd == 'BLMOVE':
                if (len(argv) != 6 or argv[3].upper() not in (b'LEFT', b'RIGHT') or
                        argv[4].upper() not in (b'LEFT', b'RIGHT')):
                    raise ValueError('Invalid native blocking move')
                keys = argv[1:3]
            else:
                if len(argv) < 3: raise ValueError('Invalid blocking queue operation')
                keys = argv[1:-1]
            if not argv[-1].replace(b'.', b'', 1).isdigit() or float(argv[-1]) > 5:
                raise ValueError('Blocking queue operation exceeds limit')
            for value in keys: self.key(value)
        elif cmd == 'MSET':
            if len(argv) < 3 or len(argv) % 2 != 1: raise ValueError('Invalid MSET')
            for key in argv[1::2]: self.key(key)
        elif cmd == 'PUBLISH':
            if len(argv) != 3: raise ValueError('Invalid PUBLISH')
            self.channel(argv[1])
        elif cmd in ('SUBSCRIBE', 'UNSUBSCRIBE'):
            if len(argv) < 2 and cmd != 'UNSUBSCRIBE': raise ValueError('Missing PubSub channel')
            for channel in argv[1:]: self.channel(channel)
        elif cmd in ('SCAN', 'KEYS'):
            # DB1 contains ONLY Mastodon data. Still ban unbounded wildcard metadata.
            if cmd == 'KEYS' or len(argv) < 4 or argv[2].upper() != b'MATCH' or argv[3] not in (
                b'uniquejobs:*', b'queue:*', b'p0v3-mastodon-' + self.generation + b':*'):
                raise ValueError('Unbounded or foreign native Redis key scan')
            if not argv[1].isdigit(): raise ValueError('Invalid SCAN cursor')
            if len(argv) > 4 and (len(argv) != 6 or argv[4].upper() != b'COUNT' or
                    not argv[5].isdigit() or int(argv[5]) > 1024):
                raise ValueError('Unbounded SCAN COUNT')
        elif cmd == 'SCRIPT':
            if len(argv) != 3 or argv[1].upper() != b'LOAD':
                raise ValueError('Unapproved Redis scripting action')
            sha = hashlib.sha1(argv[2]).hexdigest().encode()
            digest = hashlib.sha256(argv[2]).hexdigest()
            if sha not in self.scripts or self.scripts[sha] != digest:
                raise ValueError('Unattested rendered SUJ 8.1.0 Lua source')
        elif cmd == 'EVALSHA':
            if len(argv) < 3 or argv[1].lower() not in self.scripts or not argv[2].isdigit():
                raise ValueError('Unattested native EVALSHA')
            keys = int(argv[2])
            if keys > 64 or len(argv) < 3 + keys: raise ValueError('Unbounded EVALSHA KEYS')
            for key in argv[3:3 + keys]: self.key(key)
        elif cmd == 'INFO':
            if len(argv) not in (1, 2) or len(argv) == 2 and argv[1].lower() not in (
                    b'server', b'persistence', b'replication', b'default'):
                raise ValueError('Foreign Redis INFO section')
        elif cmd == 'CLIENT':
            if (len(argv) < 2 or len(argv) != (3 if argv[1].upper() == b'SETNAME' else 4) or
                    argv[1].upper() not in (b'SETNAME', b'SETINFO') or
                    len(argv) == 4 and argv[2].upper() not in (b'LIB-NAME', b'LIB-VER') or
                    any(len(field) > 96 for field in argv[2:])):
                raise ValueError('Redis client metadata access forbidden')
        elif cmd in NO_KEYS:
            if cmd in ('MULTI', 'EXEC', 'DISCARD', 'UNWATCH', 'QUIT') and len(argv) != 1:
                raise ValueError('Invalid no-key Redis command')
            if cmd == 'ECHO' and len(argv) != 2: raise ValueError('Invalid ECHO')
        else:
            raise ValueError('Redis command outside fixed Mastodon 4.7.4 native profile')
        return cmd


def read_line(sock, limit=256):
    result = bytearray()
    while len(result) <= limit:
        value = sock.recv(1)
        if not value: raise EOFError('Redis peer closed')
        result += value
        if result.endswith(b'\r\n'): return bytes(result[:-2])
    raise ValueError('Unbounded RESP line')


def read_frame(sock, depth=0, budget=None):
    if budget is None: budget = [MAX_FRAME]
    if depth > 12 or budget[0] < 1: raise ValueError('RESP nesting/budget exceeded')
    head = read_line(sock)
    budget[0] -= len(head) + 2
    if not head: raise ValueError('Empty RESP frame')
    marker, value = head[:1], head[1:]
    if marker in (b'+', b'-', b':', b',', b'(', b'#', b'_'):
        return marker, value, marker + head[1:] + b'\r\n'
    if marker in (b'$', b'!', b'='):
        length = int(value)
        if length == -1: return marker, None, head + b'\r\n'
        if length < 0 or length > min(MAX_BULK, budget[0] - 2): raise ValueError('RESP bulk exceeds budget')
        chunks = bytearray()
        while len(chunks) < length + 2:
            part = sock.recv(length + 2 - len(chunks))
            if not part: raise EOFError('Short RESP bulk')
            chunks += part
        if chunks[-2:] != b'\r\n': raise ValueError('Invalid RESP bulk trailer')
        budget[0] -= length + 2
        return marker, bytes(chunks[:-2]), head + b'\r\n' + chunks
    if marker in (b'*', b'~', b'>', b'%', b'|'):
        count = int(value)
        if count == -1: return marker, None, head + b'\r\n'
        if count < 0 or count > MAX_ARGS: raise ValueError('RESP array exceeds budget')
        items, raw = [], bytearray(head + b'\r\n')
        for _ in range(count * (2 if marker in (b'%', b'|') else 1)):
            _, data, part = read_frame(sock, depth + 1, budget)
            items.append(data); raw += part
        return marker, items, bytes(raw)
    raise ValueError('Unsupported RESP frame')


def frame(argv):
    return b'*' + str(len(argv)).encode() + b'\r\n' + b''.join(
        b'$' + str(len(part)).encode() + b'\r\n' + part + b'\r\n' for part in argv)


def public_hello(marker, values, protocol, version):
    if marker != (b'%' if protocol == b'3' else b'*') or not isinstance(values, list) or len(values) != 14:
        raise ValueError('Unexpected provider HELLO native shape')
    observed = dict(zip(values[::2], values[1::2]))
    if (set(observed) != {b'server', b'version', b'proto', b'id', b'mode', b'role', b'modules'} or
            observed[b'version'] != version or observed[b'proto'] != protocol or
            observed[b'mode'] != b'standalone' or observed[b'role'] != b'master' or
            observed[b'modules'] != [] or observed[b'server'] not in (b'valkey', b'redis')):
        raise ValueError('Unreviewed provider native version/role/modules')
    safe = ((b'server', b'redis'), (b'version', version), (b'proto', protocol),
            (b'id', b'0'), (b'mode', b'standalone'), (b'role', b'master'))
    result = bytearray((b'%7' if protocol == b'3' else b'*14') + b'\r\n')
    for key, value in safe:
        result += b'$' + str(len(key)).encode() + b'\r\n' + key + b'\r\n'
        if key in (b'proto', b'id'):
            result += b':' + value + b'\r\n'
        else:
            result += b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n'
    result += b'$7\r\nmodules\r\n*0\r\n'
    return bytes(result)


def reply(sock, text):
    sock.sendall(b'-ERR ' + text + b'\r\n')


def bounded_info(upstream, version):
    """ioredis ready-check needs loading:0. Read native state but never expose
    provider-wide key counts, client IDs, source addresses or peer databases.
    """
    upstream.sendall(frame((b'INFO',)))
    marker, value, _ = read_frame(upstream)
    if marker != b'$' or not isinstance(value, bytes) or len(value) > 262144:
        raise ValueError('Unreviewed provider INFO frame')
    lines = value.split(b'\r\n')
    def exactly(field, expected):
        observations = [line.partition(b':')[2] for line in lines if line.startswith(field + b':')]
        if observations != [expected]: raise ValueError('Provider INFO state changed')
    exactly(b'redis_version', version)
    exactly(b'loading', b'0')
    exactly(b'role', b'master')
    safe = b'# Server\r\nredis_version:' + version + b'\r\n# Persistence\r\nloading:0\r\n# Replication\r\nrole:master\r\n'
    return b'$' + str(len(safe)).encode() + b'\r\n' + safe + b'\r\n'


def virtual_select(argv):
    if argv and argv[0].upper() == b'SELECT':
        if len(argv) != 2 or argv[1] != b'0':
            raise ValueError('Only pinned client virtual DB0 is allowed')
        return True
    return False


class Bridge:
    def __init__(self, config):
        exact(config, ('schemaVersion', 'generation', 'versions', 'providerAddress', 'providerPort',
                       'backendCredentialFile', 'frontendCredentialFile',
                       'imageManifestSha256', 'providerVersion', 'renderedScriptsFile',
                       'renderedScriptsFileSha256', 'scriptJournalDirectory'))
        if config['schemaVersion'] != 1 or tuple(config['versions']) != VERSION or not GENERATION.fullmatch(config['generation']):
            raise ValueError('Foreign Mastodon image/native library pins')
        if config['providerAddress'] != 'valkey' or config['providerPort'] != 6379:
            raise ValueError('Foreign shared provider network')
        if not SHA256.fullmatch(config['imageManifestSha256']) or not SHA256.fullmatch(config['renderedScriptsFileSha256']):
            raise ValueError('Unbound native source-image/script attestation')
        script_bytes = private(config['renderedScriptsFile'], 65536)
        if hashlib.sha256(script_bytes).hexdigest() != config['renderedScriptsFileSha256']:
            raise ValueError('Native source attestation changed after generation sealing')
        scripts = json.loads(script_bytes)
        exact(scripts, ('schemaVersion', 'generation', 'versions', 'imageManifestSha256', 'renderedSha256'))
        if (scripts['schemaVersion'] != 1 or scripts['generation'] != config['generation'] or
                tuple(scripts['versions']) != VERSION or
                scripts['imageManifestSha256'] != config['imageManifestSha256']):
            raise ValueError('Foreign source-attested native script closure')
        self.profile = Profile(config['generation'], scripts['renderedSha256'])
        if not re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}', config['providerVersion']):
            raise ValueError('Unpinned provider native version')
        self.version = config['providerVersion'].encode()
        self.address = (config['providerAddress'], config['providerPort'])
        self.backendSecret = private(config['backendCredentialFile'], 4096).strip()
        self.frontendSecret = private(config['frontendCredentialFile'], 4096).strip()
        if (any(not TOKEN.fullmatch(x.decode('ascii')) for x in (self.backendSecret, self.frontendSecret)) or
                self.backendSecret == self.frontendSecret):
            raise ValueError('Missing/disclosed or reused broker credentials')
        if config['scriptJournalDirectory'] != '/var/lib/mastodon-redis-bridge':
            raise ValueError('Foreign native script intent ledger')
        self.journal = config['scriptJournalDirectory']
        journal_stat = os.stat(self.journal, follow_symlinks=False)
        if (not stat.S_ISDIR(journal_stat.st_mode) or os.path.islink(self.journal) or
                journal_stat.st_uid != os.getuid() or stat.S_IMODE(journal_stat.st_mode) != 0o700):
            raise ValueError('Unprotected native script intent ledger')
        self.active = threading.BoundedSemaphore(MAX_CLIENTS)
        self.scriptLock = threading.Lock()

    def script_load(self, upstream, argv):
        sha = hashlib.sha1(argv[2]).hexdigest()
        # The script cache is provider-global, but only this one APPROVED SHA may
        # be queried. Lost ACK is reconciled by read-only SCRIPT EXISTS; never
        # repeat a possibly attempted SCRIPT LOAD into the shared provider.
        with self.scriptLock:
            intent = os.path.join(self.journal, self.profile.generation.decode() + '-' + sha + '.intent')
            if not os.path.exists(intent):
                descriptor = os.open(intent, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(hashlib.sha256(argv[2]).hexdigest().encode() + b'\n')
                    output.flush(); os.fsync(output.fileno())
                parent = os.open(self.journal, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
                upstream.sendall(frame(argv))
                marker, value, _ = read_frame(upstream)
                if marker != b'+' or value.lower() != sha.encode():
                    raise ValueError('Uncertain native SUJ/Sidekiq script load')
            else:
                data = private(intent, 128)
                if data != hashlib.sha256(argv[2]).hexdigest().encode() + b'\n':
                    raise ValueError('Native script intent changed')
            upstream.sendall(frame((b'SCRIPT', b'EXISTS', sha.encode())))
            marker, values, _ = read_frame(upstream)
            if marker != b'*' or values != [b'1']:
                raise ValueError('Native script cache uncertain; no SCRIPT LOAD replay')
            return b'+' + sha.encode() + b'\r\n'

    def backend(self):
        upstream = socket.create_connection(self.address, timeout=5)
        upstream.settimeout(15)
        # Only the bridge-backend ACL may SELECT DB1. ALL other daemon/provider ACLs
        # deny SELECT. Its finite key/channel/script grants never use ~* or &*.
        # The frontend sees virtual DB0, no provider address or backend credential.
        for command in ((b'AUTH', b'mastodon-bridge', self.backendSecret), (b'SELECT', b'1')):
            upstream.sendall(frame(command))
            marker, value, _ = read_frame(upstream)
            if marker != b'+' or value != b'OK':
                upstream.close(); raise ValueError('DB1 broker credential or SELECT refused')
        return upstream

    def session(self, client):
        upstream = None
        authenticated = False
        subscribed = False
        try:
            client.settimeout(15)
            while True:
                if subscribed and upstream is not None and select.select([upstream], [], [], 0.05)[0]:
                    _, _, native = read_frame(upstream); client.sendall(native)
                if not select.select([client], [], [], 0.05)[0]: continue
                marker, argv, _ = read_frame(client)
                if marker != b'*' or not argv or any(not isinstance(arg, bytes) for arg in argv):
                    raise ValueError('Only RESP bulk-array requests accepted')
                cmd = argv[0].upper()
                if cmd == b'AUTH':
                    if (len(argv) not in (2, 3) or not hmac.compare_digest(argv[-1], self.frontendSecret) or
                            (len(argv) == 3 and argv[1] != b'mastodon') or authenticated):
                        raise ValueError('Invalid or replayed bridge AUTH')
                    upstream = self.backend(); authenticated = True; client.sendall(b'+OK\r\n'); continue
                if cmd == b'HELLO':
                    if (len(argv) not in (5, 7) or argv[1] not in (b'2', b'3') or
                            argv[2].upper() != b'AUTH' or argv[3] != b'mastodon' or
                            not hmac.compare_digest(argv[4], self.frontendSecret) or authenticated or
                            (len(argv) == 7 and (argv[5].upper() != b'SETNAME' or
                             not re.fullmatch(rb'[a-zA-Z0-9_.:@-]{1,96}', argv[6])))):
                        raise ValueError('Unauthenticated Redis HELLO')
                    upstream = self.backend(); authenticated = True
                    upstream.sendall(frame((b'HELLO', argv[1])))
                    marker, values, _ = read_frame(upstream)
                    client.sendall(public_hello(marker, values, argv[1], self.version)); continue
                if not authenticated or upstream is None: raise ValueError('Unauthenticated bridge request')
                if virtual_select(argv):
                    # Local virtual DB0; NEVER forward SELECT to the backend DB1.
                    client.sendall(b'+OK\r\n'); continue
                action = self.profile.check(argv)
                if action == 'SCRIPT':
                    client.sendall(self.script_load(upstream, argv)); continue
                if action == 'INFO':
                    client.sendall(bounded_info(upstream, self.version)); continue
                upstream.sendall(frame(argv))
                _, _, native = read_frame(upstream)
                client.sendall(native)
                if action == 'SUBSCRIBE': subscribed = True
                if action == 'UNSUBSCRIBE' and len(argv) == 1: subscribed = False
                if action == 'QUIT': break
        except (ValueError, EOFError, OSError):
            # Never log payloads, token bytes, native key names, Lua or private replies.
            try: reply(client, b'unapproved native Mastodon Redis operation')
            except OSError: pass
        finally:
            if upstream is not None: upstream.close()
            client.close(); self.active.release()

    def serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 6379)); server.listen(MAX_CLIENTS)
        while True:
            client, _ = server.accept()
            if not self.active.acquire(blocking=False):
                client.close(); continue
            threading.Thread(target=self.session, args=(client,), daemon=True).start()


def main():
    if len(sys.argv) != 2 or sys.argv[1] != '/run/secrets/mastodon-redis-bridge.json':
        raise SystemExit('Fixed Mastodon broker configuration required')
    Bridge(json.loads(private(sys.argv[1], 65536))).serve()


if __name__ == '__main__':
    main()
