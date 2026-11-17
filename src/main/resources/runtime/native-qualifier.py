"""One-use A11 unauthorized QClient network probe. Fixed source-only capability,
not a generic nsenter, product request, localhost bridge or arbitrary shell hook.
The controller has already persisted intent and bound original case/target/QClient.
"""
if not __debug__:
    raise SystemExit('Optimized native qualifier refused before imports or effects')
import ctypes
import errno
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time


def require(condition, text):
    if not condition: raise ValueError(text)


def counter(table):
    completed = subprocess.run(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', table],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=6, check=False)
    require(completed.returncode == 0 and len(completed.stdout) in range(1, 262145),
            'Original QClient nft table unavailable')
    records = json.loads(completed.stdout)['nftables']
    chains = [item['chain'] for item in records if 'chain' in item]
    require({chain['name'] for chain in chains} == {'dst', 'out', 'in'} and
            next(chain for chain in chains if chain['name'] == 'out')['policy'] == 'drop',
            'Negative client output network policy changed')
    rules = [item['rule'] for item in records if 'rule' in item and item['rule']['chain'] == 'out']
    require(len(rules) == 7, 'Scoped QClient output rules changed')
    last = rules[-1]['expr']
    require(len(last) == 2 and 'counter' in last[0] and last[1] == {'drop': None},
            'Denied socket must count the exact final provider network drop rule')
    return last[0]['counter']['packets']


def probe(request):
    exact = {'operation', 'operationId', 'invocationId', 'caseClaimSha256',
             'qclientPid', 'qclientContainerId', 'qclientNetnsInode', 'table',
             'targetAddress', 'targetPort', 'targetContainerId', 'targetPid',
             'targetNetnsInode', 'serviceId', 'processId', 'requestSha256'}
    require(set(request) == exact and request['operation'] == 'native-network-denial' and
            re.fullmatch(r'nq-[a-f0-9]{12}', request['operationId']) and
            re.fullmatch(r'[a-z][a-z0-9-]{0,95}', request['invocationId']) and
            request['serviceId'] in ('alloy', 'loki') and request['processId'] == 'loki' and
            request['targetPort'] == 3100 and
            re.fullmatch(r'p0v3_qc_[a-f0-9]{12}', request['table']) and
            type(request['qclientPid']) is int and request['qclientPid'] > 1 and
            type(request['targetPid']) is int and request['targetPid'] > 1 and
            type(request['qclientNetnsInode']) is int and request['qclientNetnsInode'] > 1 and
            type(request['targetNetnsInode']) is int and request['targetNetnsInode'] > 1 and
            all(isinstance(request[key], str) and re.fullmatch(r'[a-f0-9]{64}', request[key])
                for key in ('qclientContainerId', 'targetContainerId',
                            'caseClaimSha256', 'requestSha256')) and
            isinstance(request['targetAddress'], str) and
            re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', request['targetAddress']) and
            ipaddress.IPv4Address(request['targetAddress']).is_private and
            not ipaddress.IPv4Address(request['targetAddress']).is_loopback and
            not ipaddress.IPv4Address(request['targetAddress']).is_link_local,
            'Foreign local native denial protocol')
    require(os.geteuid() == 0, 'Native namespace evidence requires scoped root')
    descriptor = os.open('/proc/%d/ns/net' % request['qclientPid'], os.O_RDONLY | os.O_CLOEXEC)
    try:
        with open('/proc/%d/cgroup' % request['qclientPid'], encoding='ascii') as stream:
            cgroups = stream.read(65537)
        require(len(cgroups) <= 65536 and request['qclientContainerId'] in cgroups and
                os.fstat(descriptor).st_ino == request['qclientNetnsInode'] and
                os.stat('/proc/%d/ns/net' % request['targetPid']).st_ino == request['targetNetnsInode'] and
                request['targetNetnsInode'] != request['qclientNetnsInode'],
                'Original provider and real denied client must occupy different pinned namespaces')
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.setns(descriptor, 0) == 0, 'Could not enter exact pinned unauthorized QClient')
    finally:
        os.close(descriptor)
    require(os.stat('/proc/self/ns/net').st_ino == request['qclientNetnsInode'],
            'Unauthorized client network namespace switched')
    before = counter(request['table'])
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            require(libc.prctl(47, 4, 0, 0, 0) == 0 and
                    libc.prctl(38, 1, 0, 0, 0) == 0,
                    'Unauthorized socket child must discard ambient caps and privilege gain')
            os.setgroups([])
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            try:
                sock.connect((request['targetAddress'], 3100))
                payload = {'connectFailed': False, 'clientPid': os.getpid()}
            except (OSError, socket.timeout) as error:
                payload = {'connectFailed': True, 'clientPid': os.getpid(), 'errorType': type(error).__name__,
                           'errno': getattr(error, 'errno', None)}
            finally: sock.close()
            os.write(write_fd, json.dumps(payload, sort_keys=True).encode())
        except BaseException:
            os.write(write_fd, b'{"connectFailed":false}')
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        child_bytes = os.read(read_fd, 2049)
        status_pid, status = os.waitpid(child, 0)
    finally: os.close(read_fd)
    require(status_pid == child and status == 0 and len(child_bytes) in range(1, 2049),
            'Denied QClient socket observation absent')
    result = json.loads(child_bytes)
    after = counter(request['table'])
    require(result.get('connectFailed') is True and after > before and
            result.get('errno') not in (errno.EINVAL, errno.EBADF),
            'Real unauthorized client connected or no scoped nft drop counter advanced')
    return {'targetContainerId': request['targetContainerId'],
            'targetPid': request['targetPid'], 'targetNetnsInode': request['targetNetnsInode'],
            'qclientContainerId': request['qclientContainerId'],
            'qclientPid': request['qclientPid'], 'qclientNetnsInode': request['qclientNetnsInode'],
            'caseClaimSha256': request['caseClaimSha256'],
            'dropCounterBefore': before, 'dropCounterAfter': after,
            'connectFailed': True, 'clientPid': result['clientPid'], 'errorType': result['errorType'],
            'errno': result['errno'], 'targetPort': 3100,
            'requestSha256': request['requestSha256']}


if __name__ == '__main__':
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('denial deadline')))
    signal.alarm(15)
    try:
        raw = sys.stdin.buffer.read(8193)
        require(len(raw) in range(1, 8193), 'bounded private denial request required')
        result = probe(json.loads(raw))
        sys.stdout.write(json.dumps(result, separators=(',', ':'), sort_keys=True))
        sys.stdout.flush()
    except Exception:
        sys.stderr.write('Native denied-socket proof failed; retain attempted operation\n')
        raise SystemExit(1)
    finally:
        signal.alarm(0)
