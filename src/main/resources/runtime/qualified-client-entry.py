#!/usr/bin/python3
# Fixed image-installed client launcher. This source is never run in the implementation phase.
if not __debug__:
    raise SystemExit("Optimized client refused")
"""One signed/image-pinned browser, Android, or typed native qualification case.

No arbitrary command, host trust-store mutation, network fallback, APK acquisition,
or automatic request replay. Only an audited fresh Android guest receives the selected
private CA through a fenced one-off system/Conscrypt adoption. A generation-owned controller
starts this process BEFORE making the
private Caddy client listener and grants its one-use gate only after native CID/netns/nft readback.
"""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

CASE = Path('/case')
SUITE = Path('/opt/p0v3/acceptance')
HEX = re.compile(r'[a-f0-9]{64}')
HOST = re.compile(r'(?:[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?\.)+datamancy\.net')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def private(path, limit=4194304):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path == path.resolve() and stat.S_ISREG(info.st_mode) and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and
            info.st_nlink == 1 and 0 < info.st_size <= limit, 'unsafe private client input')
    return path.read_bytes()


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate client JSON key')
            result[key] = value
        return result
    return json.loads(private(path), object_pairs_hook=unique)


def saved(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(data) <= 1048576, 'oversized client record')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return digest(data)


def fixed_dns(approved, address, stop):
    """Container-local only; no resolver upstream, wildcard, public DNS or host trust change."""
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(('127.0.0.1', 53)); listener.settimeout(.5)
        while not stop.is_set():
            try: packet, peer = listener.recvfrom(513)
            except socket.timeout: continue
            require(peer[0] == '127.0.0.1' and 12 <= len(packet) <= 512, 'foreign DNS caller')
            offset, labels = 12, []
            for _ in range(8):
                require(offset < len(packet), 'truncated DNS query')
                length = packet[offset]; offset += 1
                require(length <= 63 and offset + length <= len(packet), 'invalid DNS label')
                if length == 0: break
                labels.append(packet[offset:offset + length].decode('ascii').lower()); offset += length
            else: raise ValueError('DNS name too deep')
            end = offset + 4
            require(end <= len(packet) and packet[offset:end] in (b'\x00\x01\x00\x01',
                    b'\x00\x1c\x00\x01') and packet[4:6] == b'\x00\x01' and
                    packet[6:10] == b'\x00\x00\x00\x00', 'only one A/AAAA question is admitted')
            # Android/Chromium may include a bounded EDNS0 OPT; never forward it or answer
            # another question. Return one ordinary DNS answer without an extra section.
            if packet[10:12] == b'\x00\x01':
                require(packet[end:end + 3] == b'\x00\x00\x29' and len(packet) >= end + 11,
                        'unexpected extra DNS record')
            else: require(packet[10:12] == b'\x00\x00' and end == len(packet),
                          'nonexact DNS message')
            name = '.'.join(labels)
            permitted = name in approved and packet[offset:offset + 2] == b'\x00\x01'
            flags = b'\x81\x80' if permitted else b'\x81\x83'  # exact A or NXDOMAIN; no forwarding
            answer = (b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04' +
                      socket.inet_aton(address)) if permitted else b''
            response = (packet[:2] + flags + packet[4:6] + (b'\x00\x01' if permitted else b'\x00\x00') +
                        b'\x00\x00\x00\x00' + packet[12:end] + answer)
            listener.sendto(response, peer)
    except BaseException as error:
        stop.set()
        # Never report the query name or client auth material in a broad process log.
        print('Scoped DNS stopped: ' + type(error).__name__, file=sys.stderr)
    finally:
        try: listener.close()
        except UnboundLocalError: pass


def checked(argv, timeout=30, input_bytes=None):
    require(argv and all(isinstance(x, str) and '\x00' not in x for x in argv), 'invalid fixed tool invocation')
    result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=timeout)
    require(len(result.stdout) <= 1048576, 'oversized native client readback')
    return result.stdout


def ca_adoption(intent, env):
    ca = private('/run/secrets/source-ca.pem', 65536)
    require(digest(ca) == env['P0V3_CLIENT_CERTIFICATE_SHA256'] and HEX.fullmatch(digest(ca)) and
            b'-----BEGIN CERTIFICATE-----' in ca, 'unverified original source CA')
    home = CASE / 'home'; home.mkdir(mode=0o700, exist_ok=True)
    pki = home / '.pki'; pki.mkdir(mode=0o700, exist_ok=True)
    nss = pki / 'nssdb'; nss.mkdir(mode=0o700, exist_ok=True)
    profile = 'sql:' + str(nss)
    certutil = '/opt/qualified-tools/bin/certutil'
    checked([certutil, '-N', '--empty-password', '-d', profile])
    checked([certutil, '-A', '-n', 'p0v3-original-source', '-t', 'C,,', '-i',
             '/run/secrets/source-ca.pem', '-d', profile])
    readback = checked([certutil, '-L', '-n', 'p0v3-original-source', '-a', '-d', profile])
    require(b'-----BEGIN CERTIFICATE-----' in readback, 'NSS did not adopt scoped source CA')
    jks = '/tmp/p0v3-truststore.jks'
    keytool = '/opt/qualified-tools/bin/keytool'
    checked([keytool, '-importcert', '-noprompt', '-alias', 'p0v3-original-source',
             '-file', '/run/secrets/source-ca.pem', '-keystore', jks,
             '-storepass', 'changeit'])  # Truststore password is not a credential or client secret.
    java = checked([keytool, '-list', '-rfc', '-alias', 'p0v3-original-source',
                    '-keystore', jks, '-storepass', 'changeit'])
    require(b'-----BEGIN CERTIFICATE-----' in java, 'Private Java truststore was not adopted')
    def first_der(contents):
        block = re.search(rb'-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)\s+-----END CERTIFICATE-----', contents)
        require(block is not None, 'Native trust readback has no X.509 certificate')
        return base64.b64decode(re.sub(rb'\s+', b'', block.group(1)), validate=True)
    original_der = first_der(ca)
    require(first_der(readback) == original_der and first_der(java) == original_der,
            'NSS or scoped Java trust adopted a different certificate')
    saved(CASE / 'client-ca-adoption.json', {'invocationId': intent['invocationId'],
          'certificateSha256': digest(ca), 'nssReadbackSha256': digest(readback),
          'javaReadbackSha256': digest(java), 'leafSha256': env['P0V3_CLIENT_LEAF_SHA256']})
    return {'NSS_DEFAULT_DB_TYPE': 'sql', 'P0V3_NSS_DB': profile,
            'JAVA_TOOL_OPTIONS': '-Djavax.net.ssl.trustStore=' + jks +
                                 ' -Djavax.net.ssl.trustStorePassword=changeit',
            'SSL_CERT_FILE': '/run/secrets/source-ca.pem',
            'CHROME_USER_DATA_DIR': str(home / '.config/chromium')}


def wait_gate(intent, env):
    deadline = time.monotonic() + 120
    path = CASE / 'qualification-client-gate.json'
    while time.monotonic() < deadline:
        if path.exists():
            gate = load(path)
            base = {'invocationId', 'requestSha256', 'nativeContainerId', 'policySha256'}
            public_native = {'generationId', 'caseIntentSha256', 'nativePid', 'nativeNetnsInode',
                             'imageId', 'imageManifestSha256', 'originalHost', 'originalCaSha256',
                             'originalLeafSha256', 'scopedCaddyIp', 'nativeNftReadbackSha256'}
            seafile_native = (intent['serviceId'] == 'seafile' and
                              intent['surface'] == 'HEADLESS' and intent['variant'] == 'NATIVE')
            a12_hosts = {'homeassistant': 'home.datamancy.net',
                         'jellyfin': 'media.datamancy.net',
                         'qbittorrent': 'torrents.datamancy.net', 'searxng': 'search.datamancy.net'}
            a12_public = (intent['serviceId'] in a12_hosts and
                          intent['surface'] in ('WEB', 'ANDROID', 'HEADLESS'))
            extra = public_native | ({'deviceRoots', 'nativeToolPins'} if seafile_native else set())
            require(set(gate) == (base | extra if seafile_native or a12_public else base) and
                    gate['invocationId'] == intent['invocationId'] and
                    gate['requestSha256'] == env['P0V3_CLIENT_REQUEST_SHA256'] and
                    HEX.fullmatch(gate['nativeContainerId']) and HEX.fullmatch(gate['policySha256']),
                    'foreign or incomplete post-start native client gate')
            if seafile_native or a12_public:
                require(gate['generationId'] == intent['binding']['generationId'] and
                        gate['caseIntentSha256'] == digest(private(CASE / 'intent.json')) and
                        type(gate['nativePid']) is int and gate['nativePid'] > 1 and
                        type(gate['nativeNetnsInode']) is int and gate['nativeNetnsInode'] > 1 and
                        os.stat('/proc/self/ns/net').st_ino == gate['nativeNetnsInode'] and
                        HEX.fullmatch(gate['imageId']) and
                        re.fullmatch(r'sha256:[a-f0-9]{64}', gate['imageManifestSha256']) and
                        gate['originalHost'] == ('files.datamancy.net' if seafile_native else
                                                  a12_hosts[intent['serviceId']]) and
                        gate['originalCaSha256'] == env['P0V3_CLIENT_CERTIFICATE_SHA256'] and
                        gate['originalLeafSha256'] == env['P0V3_CLIENT_LEAF_SHA256'] and
                        gate['scopedCaddyIp'] == env['P0V3_CLIENT_CADDY_IP'] and
                        HEX.fullmatch(gate['nativeNftReadbackSha256']),
                        'real native one-use original-host QClient policy changed')
            return gate
        time.sleep(.1)
    raise TimeoutError('Native client gate absent; no request or app journey started')


def _producer_file(path, expected_sha, maximum):
    require(HEX.fullmatch(expected_sha) and path.is_file() and not path.is_symlink() and
            path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) & 0o022 == 0 and
            0 < path.stat().st_size <= maximum, 'Unowned, mutable or oversized producer tool')
    sha = hashlib.sha256()
    with path.open('rb') as reader:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk: break
            sha.update(chunk)
    require(sha.hexdigest() == expected_sha, 'Changed native tool outside signed image closure')


def seafile_official_tools(invocation, gate, env, address):
    if not (invocation['serviceId'] == 'seafile' and invocation['surface'] == 'HEADLESS' and
            invocation['variant'] == 'NATIVE'): return
    require(invocation['surface'] == 'HEADLESS' and invocation['variant'] == 'NATIVE' and
            gate['generationId'] == invocation['binding']['generationId'] and
            gate['caseIntentSha256'] == digest(private(CASE / 'intent.json')) and
            gate['originalHost'] == 'files.datamancy.net' and
            gate['originalCaSha256'] == env['P0V3_CLIENT_CERTIFICATE_SHA256'] and
            gate['originalLeafSha256'] == env['P0V3_CLIENT_LEAF_SHA256'] and
            gate['scopedCaddyIp'] == address and
            gate['deviceRoots'] == {'owner': '/case/sync-device-a', 'reader': '/case/sync-device-b'} and
            isinstance(gate['nativePid'], int) and gate['nativePid'] > 1 and
            isinstance(gate['nativeNetnsInode'], int) and gate['nativeNetnsInode'] > 1 and
            HEX.fullmatch(gate['imageId']) and
            re.fullmatch(r'sha256:[a-f0-9]{64}', gate['imageManifestSha256']) and
            HEX.fullmatch(gate['nativeNftReadbackSha256']) and
            os.stat('/proc/self/ns/net').st_ino == gate['nativeNetnsInode'] and
            not any((CASE / item).exists() or (CASE / item).is_symlink()
                    for item in ('sync-device-a', 'sync-device-b')),
            'Seafile must start two born-only official client devices inside pinned QClient')
    pins = gate['nativeToolPins']
    base = Path('/opt/qualified-tools/seafile-v9.0.15')
    tools = {'seafCliSha256': base / 'app/seaf-cli',
             'seafDaemonSha256': base / 'bin/seaf-daemon',
             'seafileInitSha256': base / 'python/seafile/__init__.py',
             'seafileRpcSha256': base / 'python/seafile/rpcclient.py',
             'pysearpcInitSha256': base / 'python/pysearpc/__init__.py',
             'signedClosureSha256': base / 'signed-producer-closure.json',
             'producerPublicKeySha256': base / 'signed-producer-key.pem',
             'producerSignatureSha256': base / 'signed-producer-closure.sig',
             'opensslSha256': Path('/usr/bin/openssl')}
    require(set(pins) == set(tools), 'No exact Seafile official tool/ELF closure pin')
    for key, path in tools.items():
        require((path == Path('/usr/bin/openssl') if key == 'opensslSha256' else
                 path.resolve().is_relative_to(base)), 'Foreign Seafile immutable image tool')
        _producer_file(path, pins[key], 1024 * 1024 if key in
            ('signedClosureSha256', 'producerPublicKeySha256', 'producerSignatureSha256')
            else 256 * 1024 * 1024)
    verified = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin',
        '-inkey', str(tools['producerPublicKeySha256']), '-rawin',
        '-in', str(tools['signedClosureSha256']),
        '-sigfile', str(tools['producerSignatureSha256'])],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=10, check=False)
    require(verified.returncode == 0, 'Seafile producer signature did not verify with pinned key')
    receipt = json.loads(tools['signedClosureSha256'].read_bytes())
    closure = {str(path.relative_to(base)): pins[key] for key, path in tools.items()
               if key not in ('signedClosureSha256', 'producerPublicKeySha256',
                              'producerSignatureSha256', 'opensslSha256')}
    require(receipt['upstream'] == 'haiwen/seafile' and receipt['version'] == 'v9.0.15' and
            isinstance(receipt['files'], dict) and 5 <= len(receipt['files']) <= 512 and
            set(closure.items()).issubset(set(receipt['files'].items())) and
            all(isinstance(name, str) and name != '' and isinstance(expected_sha, str) and
                HEX.fullmatch(expected_sha) and (base / name).resolve().is_relative_to(base) and
                (base / name).is_file() and not (base / name).is_symlink()
                for name, expected_sha in receipt['files'].items()),
            'Seafile Python modules and native ELF closure do not match signed producer contents')
    import os as _os
    module_root = base / 'python'
    present_modules = {str(Path(directory, name).relative_to(base))
                       for directory, dirs, files in _os.walk(module_root, followlinks=False)
                       for name in files}
    require(present_modules == {name for name in receipt['files'] if name.startswith('python/')} and
            len(present_modules) <= 512 and
            not any(Path(directory, name).is_symlink()
                    for directory, dirs, files in _os.walk(module_root, followlinks=False)
                    for name in dirs + files),
            'Unlisted Python module could shadow signed original Seafile RPC')
    total = 0
    for name, expected_sha in receipt['files'].items():
        path = base / name
        total += path.stat().st_size
        require(total <= 1024 * 1024 * 1024, 'Unbounded producer image closure')
        _producer_file(path, expected_sha, 256 * 1024 * 1024)
    saved(CASE / 'seafile-client-tools.json', {'invocationId': invocation['invocationId'],
          'nativeContainerId': gate['nativeContainerId'], 'nativePid': gate['nativePid'],
          'nativeNetnsInode': gate['nativeNetnsInode'], 'originalHost': gate['originalHost'],
          'nativeToolPins': pins, 'signedClosureSha256': pins['signedClosureSha256']})


def guest_ca_adoption(invocation, context, clients, gate):
    """One-off system/Conscrypt trust adoption in the already audited isolated AVD.
    The owner independently rereads both actual guest stores before it releases the app.
    Failure after the intent is terminal; no second remount or CA push is attempted.
    """
    ca = private('/run/secrets/source-ca.pem', 65536)
    require(digest(ca) == context['caSha256'], 'Selected original private CA changed before guest admission')
    root = CASE / 'owner-proofs'
    matrix = invocation['serviceId'] in ('element', 'synapse', 'matrix-authentication-service', 'livekit')
    pieces = re.findall(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----', ca)
    require(1 <= len(pieces) <= (5 if matrix else 3 if invocation['serviceId'] == 'onlyoffice' else 2 if invocation['serviceId'] == 'seafile' else 1) and
            all(len(piece) in range(512, 8193) for piece in pieces) and
            len({digest(piece) for piece in pieces}) == len(pieces) and
            not re.sub(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----',
                       b'', ca).strip(), 'Android trust must contain only selected issuer PEM blocks')
    openssl = '/usr/bin/openssl'
    issuers = []
    for index, piece in enumerate(pieces):
        path = root / ('selected-guest-ca-' + str(index) + '.pem')
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output: output.write(piece + b'\n')
        cert_hash = checked([openssl, 'x509', '-in', str(path), '-subject_hash_old', '-noout'])
        require(re.fullmatch(rb'[a-f0-9]{8}\n', cert_hash), 'Selected Android CA has no fixed subject hash')
        issuers.append((cert_hash.decode().strip() + '.0', piece + b'\n', path))
    require(len({name for name, _, _ in issuers}) == len(issuers),
            'Distinct selected issuers collide in Android subject-hash namespace')
    filename = issuers[0][0] if len(issuers) == 1 else None
    for role, client, avd, _ in clients:
        serial = client['serial']; adb = client['adb']
        label = '' if role == 'owner' else '-reader'
        intent_path = root / ('guest-ca-adoption' + label + '.intent.json')
        saved(intent_path, {'invocationId': invocation['invocationId'],
              'generationId': invocation['binding']['generationId'], 'role': role,
              'serial': serial, 'avd': avd, 'caSha256': digest(ca),
              'guestIssuers': [{'guestFilename': name, 'sha256': digest(pem)} for name, pem, _ in issuers],
              'ownerBridgeSha256': gate['ownerBridgeSha256']})
        stores = ['/system/etc/security/cacerts', '/apex/com.android.conscrypt/cacerts']
        for store in stores:
            for name, _, _ in issuers:
                slot = subprocess.run([adb, '-s', serial, 'shell', 'ls', store + '/' + name],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
                require(slot.returncode != 0, 'Selected guest certificate slot is already occupied')
        checked([adb, '-s', serial, 'root'], timeout=20)
        checked([adb, '-s', serial, 'wait-for-device'], timeout=30)
        checked([adb, '-s', serial, 'remount'], timeout=40)
        checked([adb, '-s', serial, 'wait-for-device'], timeout=60)
        boot_deadline = time.monotonic() + 120
        while time.monotonic() < boot_deadline:
            try:
                if checked([adb, '-s', serial, 'shell', 'getprop', 'sys.boot_completed'],
                           timeout=5).strip() == b'1': break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired): pass
            time.sleep(.5)
        else: raise TimeoutError('Original Android guest did not return after CA remount')
        require(checked([adb, '-s', serial, 'shell', 'getprop', 'ro.boot.qemu.avd_name']).strip() ==
                avd.encode() and
                checked([adb, '-s', serial, 'shell', 'getprop', 'ro.build.version.sdk']).strip() ==
                invocation['variant'][3:].encode(), 'Guest changed during native CA remount')
        for index, (name, pem, path) in enumerate(issuers):
            source = '/data/local/tmp/p0v3-qualified-source-ca-' + str(index) + '.pem'
            checked([adb, '-s', serial, 'push', str(path), source], timeout=30)
            for store in stores:
                # Android 14+ uses Conscrypt's APEX store. Neither host NSS nor
                # explicit-cafile curl proves the app-visible original trust.
                checked([adb, '-s', serial, 'shell', 'cp', source, store + '/' + name], timeout=30)
                checked([adb, '-s', serial, 'shell', 'chmod', '644', store + '/' + name])
                observed = checked([adb, '-s', serial, 'exec-out', 'cat', store + '/' + name], timeout=30)
                require(observed == pem, 'Actual Android system/Conscrypt store did not adopt selected issuer')
            checked([adb, '-s', serial, 'shell', 'rm', source])
        receipt = {
            'invocationId': invocation['invocationId'], 'generationId': invocation['binding']['generationId'],
            'role': role, 'serial': serial, 'avd': avd,
            'caSha256': digest(ca), 'systemCaSha256': digest(ca),
            'conscryptCaSha256': digest(ca), 'ownerBridgeSha256': gate['ownerBridgeSha256']}
        if filename: receipt['guestFilename'] = filename
        else: receipt['guestIssuers'] = [
            {'guestFilename': name, 'sha256': digest(pem)} for name, pem, _ in issuers]
        saved(root / ('guest-ca-adoption' + label + '.json'), receipt)
    end = time.monotonic() + 120
    owner_gate = CASE / 'qualification-guest-trust-gate.json'
    while not owner_gate.exists():
        require(time.monotonic() < end, 'Owner native Android guest trust ACK absent')
        time.sleep(.1)
    approved = load(owner_gate)
    if invocation['serviceId'] == 'onlyoffice':
        receipt = root / 'seafile-installed-client.json'
        require('seafileInstalledClientReceiptSha256' in approved and
                approved['seafileInstalledClientReceiptSha256'] == digest(private(receipt, 65536)) and
                json.loads(private(receipt))['guestCaAdoptionSha256'] ==
                    digest(private(root / 'guest-ca-adoption.json')),
                'Owner did not independently audit the SAME guest Seadroid base and CA')
    require(approved['invocationId'] == invocation['invocationId'] and
            approved['generationId'] == invocation['binding']['generationId'] and
            approved['caSha256'] == digest(ca) and
            approved['ownerBridgeSha256'] == gate['ownerBridgeSha256'] and
            approved['ownerAdoptionSha256'] == digest(private(root / 'guest-ca-adoption.json')) and
            (('readerAdoptionSha256' in approved and
              approved['readerAdoptionSha256'] == digest(private(root / 'guest-ca-adoption-reader.json'))) ==
             (len(clients) == 2)), 'Foreign native guest issuer or post-start ACK')
    return digest(private(owner_gate))


def official_emulators(invocation, context, processes):
    if invocation['surface'] != 'ANDROID': return None
    # Only isolated Android TEST guests have the newer explicit user VM exception.
    # This does not authorize VMs for platform infrastructure or managed lanes.
    variant = invocation['variant']; require(variant in ('API34', 'API36'), 'official API required')
    api = variant[3:]
    owner = context['android']
    clients = [('owner', owner, f'p0v3-api{api}', '5564')]
    if invocation['serviceId'] == 'livekit':
        reader = context['peerAndroid']
        clients.append(('reader', reader, f'p0v3-api{api}-reader', '5580'))
    require({client['serial'] for _, client, _, _ in clients} ==
            {'emulator-' + port for _, _, _, port in clients}, 'only dedicated original AVD serials')
    adb = '/opt/android-sdk/platform-tools/adb'
    emulator = '/opt/android-sdk/emulator/emulator'
    apksigner = '/opt/android-sdk/build-tools/36.0.0/apksigner'
    catalog = json.loads((SUITE / 'cases/android-apps.json').read_bytes())
    require(catalog['schemaVersion'] == 1 and isinstance(catalog['apps'], list),
            'candidate-owned official APK catalog required before emulator start')
    selected = [app for app in catalog['apps'] if invocation['serviceId'] in app['serviceIds']]
    require(len(selected) == 1 and HEX.fullmatch(selected[0]['sha256']) and
            HEX.fullmatch(selected[0]['signerSha256']), 'unreviewed official APK pin')
    require(not processes, 'Android launch cannot reuse an original emulator')
    for role, client, avd, port in clients:
        require(client['adb'] == adb and client['apksigner'] == apksigner and
                client['apk'].startswith('/mnt/media/p0-v3/qualified-clients/') and
                HEX.fullmatch(client['adbSha256']) and HEX.fullmatch(client['apksignerSha256']),
                'Android tools/APK do not belong to this qualified image')
        for binary, key in ((adb, 'adbSha256'), (apksigner, 'apksignerSha256')):
            with open(binary, 'rb') as source:
                require(hashlib.file_digest(source, 'sha256').hexdigest() == client[key],
                        'Android native tool differs from pinned context')
        apk = Path(client['apk'])
        require(apk.is_file() and apk.stat().st_size in range(1, 536870913) and
                client['packageName'] == selected[0]['packageName'],
                'Official Android package or APK bytes absent')
        with open(apk, 'rb') as source:
            require(hashlib.file_digest(source, 'sha256').hexdigest() == selected[0]['sha256'],
                    'Candidate official APK differs before guest boot')
        signer = checked([apksigner, 'verify', '--print-certs', str(apk)]).decode('utf-8', 'strict')
        certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)', signer)
        require(len(certs) == 1 and certs[0].lower() == selected[0]['signerSha256'],
                'Official Android signer changed before effects')
        for check_port in (int(port), int(port) + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
                check.settimeout(.1)
                require(check.connect_ex(('127.0.0.1', check_port)) != 0,
                        'Android owned emulator TCP pair already occupied')
        occupied = subprocess.run([adb, '-s', client['serial'], 'get-state'],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
        require(occupied.returncode != 0, 'Foreign Android guest already attached')
    # ALL official pins, both AVD slots and both original client identities were admitted
    # before starting the first guest. Caller owns process cleanup on ANY later failure.
    for role, client, avd, port in clients:
        adopted_guest = invocation['serviceId'] in ('onlyoffice', 'seafile', 'element', 'synapse',
                                                     'matrix-authentication-service', 'livekit',
                                                     'donetick', 'homeassistant', 'jellyfin', 'mastodon', 'ntfy')
        args = [emulator, '-avd', avd, '-no-window', '-no-audio', '-gpu', 'swiftshader_indirect'] + (
                ['-writable-system'] if adopted_guest else []) + [
                '-no-snapshot', '-no-boot-anim', '-wipe-data', '-port', port,
                '-dns-server', '127.0.0.1']
        logfile = CASE / ('emulator-' + role + '.log')
        fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        out = os.fdopen(fd, 'wb', buffering=0)
        try:
            process = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT,
                                       cwd='/tmp', env=dict(os.environ))
            processes.append((process, client, avd, role))
        finally:
            out.close()
    for process, client, avd, role in processes:
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            require(process.poll() is None, 'Owned Android emulator exited before boot')
            try:
                if checked([adb, '-s', client['serial'], 'shell', 'getprop', 'sys.boot_completed'],
                           timeout=4).strip() == b'1': break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired): pass
            time.sleep(.5)
        else: raise TimeoutError('Owned Android guest boot incomplete')
        require(checked([adb, '-s', client['serial'], 'shell', 'getprop', 'ro.build.version.sdk']).strip() ==
                api.encode() and
                checked([adb, '-s', client['serial'], 'shell', 'getprop', 'ro.kernel.qemu']).strip() == b'1' and
                checked([adb, '-s', client['serial'], 'shell', 'getprop', 'ro.boot.qemu.avd_name']).strip() ==
                avd.encode(), 'A different Android emulator or AVD booted')
        if role == 'owner' and invocation['serviceId'] in (
                'onlyoffice', 'seafile', 'element', 'synapse', 'matrix-authentication-service',
                'donetick', 'homeassistant', 'jellyfin', 'mastodon', 'ntfy'):
            # No app installation/login before the retained owner audits this exact booted
            # guest's QEMU parent, CID, namespace and selected native policy.
            saved(CASE / 'android-boot-ready.json', {'invocationId': invocation['invocationId'],
                  'generationId': invocation['binding']['generationId'], 'serial': client['serial'],
                  'api': int(api), 'avd': avd, 'hostEmulatorPid': process.pid})
            end = time.monotonic() + 120
            while not (CASE / 'qualification-guest-gate.json').exists():
                require(process.poll() is None and time.monotonic() < end,
                        'Native owner guest audit absent before official APK installation')
                time.sleep(.1)
            boot_gate = load(CASE / 'qualification-guest-gate.json')
            require(boot_gate['invocationId'] == invocation['invocationId'] and
                    boot_gate['containerId'] == json.loads(private(CASE / 'qualification-client-gate.json'))['nativeContainerId'] and
                    HEX.fullmatch(boot_gate['ownerBridgeSha256']),
                    'Native owner audited a different booted Android guest')
        # Official APK identity remains independently pinned by qualified-runner and adapter
        # before AND after the UI. This install cannot invent a signer or checksum.
        package = client['packageName']
        require(re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+', package),
                'unreviewed official Android package')
        checked([apksigner, 'verify', '--print-certs', client['apk']])
        checked([adb, '-s', client['serial'], 'install', '--no-streaming', client['apk']], timeout=90)
        require(checked([adb, '-s', client['serial'], 'shell', 'pm', 'path', package]).startswith(b'package:'),
                'pinned official UI was not installed on this exact guest')
        if invocation['serviceId'] == 'onlyoffice' and role == 'owner':
            # Exactly one separately catalog-pinned official Seadroid in this SAME
            # newly owned QClient emulator. No caller package, APK path or install argv.
            fixture = [app for app in catalog['apps'] if app['serviceIds'] == ['seafile']]
            require(len(fixture) == 1 and fixture[0]['packageName'] == 'com.seafile.seadroid2',
                    'Missing distinct publisher-pinned original Seadroid fixture')
            fixture = fixture[0]
            target = CASE / 'owner-proofs'
            require(target.is_dir() and target.resolve() == target and
                    stat.S_IMODE(target.stat().st_mode) == 0o700)
            secondary = Path(context['seafileFixtureApkFile'])
            require(secondary.is_absolute() and secondary.resolve() == secondary and
                    str(secondary).startswith('/mnt/media/p0-v3/qualified-clients/') and
                    secondary != apk and secondary.is_file() and
                    context['seafileFixtureApkSha256'] == fixture['sha256'] and
                    context['seafileInstalledClientReceiptFile'] == str(target / 'seafile-installed-client.json'),
                    'Unselected Seadroid fixture path or prestart receipt authority')
            with secondary.open('rb') as stream:
                require(hashlib.file_digest(stream, 'sha256').hexdigest() == fixture['sha256'],
                        'Seadroid fixture bytes differ from reviewed candidate')
            observed_signer = checked([apksigner, 'verify', '--print-certs', str(secondary)]).decode('utf-8', 'strict')
            signer = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)', observed_signer)
            require(len(signer) == 1 and signer[0].lower() == fixture['signerSha256'],
                    'Seadroid fixture signature changed')
            guest_abi = checked([adb, '-s', client['serial'], 'shell', 'getprop', 'ro.product.cpu.abilist']).decode().strip()
            require(guest_abi and 'arm64-v8a' in guest_abi.split(','),
                    'Exact selected Office ARM64 package has no advertised guest ABI')
            saved(target / 'seafile-fixture.install.intent.json', {'invocationId': invocation['invocationId'],
                  'generationId': invocation['binding']['generationId'], 'serial': client['serial'],
                  'apkSha256': fixture['sha256'], 'signerSha256': fixture['signerSha256'],
                  'packageName': fixture['packageName'], 'primaryPackage': package})
            checked([adb, '-s', client['serial'], 'install', '--no-streaming', str(secondary)], timeout=120)
            paths = checked([adb, '-s', client['serial'], 'shell', 'pm', 'path', fixture['packageName']]).decode().splitlines()
            require(len(paths) == 1 and re.fullmatch(r'package:/data/app/[A-Za-z0-9_./=+~-]+/base\.apk', paths[0]),
                    'Seadroid fixture did not install as a single original base APK')
            temporary = CASE / 'tmp'; temporary.mkdir(mode=0o700, exist_ok=True)
            require(temporary.resolve() == temporary and stat.S_IMODE(temporary.stat().st_mode) == 0o700)
            pulled = temporary / 'seafile-fixture-installed.apk'
            require(not pulled.exists())
            checked([adb, '-s', client['serial'], 'pull', paths[0][len('package:'):], str(pulled)], timeout=120)
            try:
                info = pulled.lstat()
                require(pulled.resolve() == pulled and stat.S_ISREG(info.st_mode) and
                        info.st_nlink == 1 and info.st_uid == os.getuid() and
                        0 < info.st_size <= 536870912, 'Foreign guest-installed Seadroid base')
                with pulled.open('rb') as stream:
                    require(hashlib.file_digest(stream, 'sha256').hexdigest() == fixture['sha256'],
                            'Installed guest Seadroid base bytes differ from original APK')
                installed_certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)',
                    checked([apksigner, 'verify', '--print-certs', str(pulled)]).decode('utf-8', 'strict'))
                require(len(installed_certs) == 1 and installed_certs[0].lower() == fixture['signerSha256'],
                        'Installed Seadroid signer changed inside owner guest')
            finally: pulled.unlink(missing_ok=True)
            saved(target / 'seafile-fixture.install-observed.json', {'invocationId': invocation['invocationId'],
                  'generationId': invocation['binding']['generationId'], 'serial': client['serial'],
                  'packageName': fixture['packageName'], 'guestApkPath': paths[0][len('package:'):],
                  'apkSha256': fixture['sha256'], 'signerSha256': fixture['signerSha256'],
                  'guestAbi': guest_abi})
    saved(CASE / 'android-boot.json', {
        'invocationId': invocation['invocationId'],
        'guests': [{'role': role, 'serial': client['serial'], 'avd': avd,
                    'hostEmulatorPid': process.pid} for process, client, avd, role in processes]})
    deadline = time.monotonic() + 120
    guest_gate = CASE / 'qualification-guest-gate.json'
    while time.monotonic() < deadline:
        require(all(process.poll() is None for process, _, _, _ in processes),
                'Owned original guest exited before native parentage adoption')
        if guest_gate.exists():
            gate = load(guest_gate)
            require(gate['invocationId'] == invocation['invocationId'] and
                    HEX.fullmatch(gate['containerId']) and HEX.fullmatch(gate['ownerBridgeSha256']) and
                    (('readerBridgeSha256' in gate and HEX.fullmatch(gate['readerBridgeSha256'])) ==
                     (len(processes) == 2)), 'Guest authority does not bind both native owner/reader peers')
            a12_hosts = {'homeassistant': 'home.datamancy.net', 'jellyfin': 'media.datamancy.net',
                         'qbittorrent': 'torrents.datamancy.net', 'searxng': 'search.datamancy.net',
                         'donetick': 'donetick.datamancy.net', 'mastodon': 'social.datamancy.net',
                         'ntfy': 'ntfy-native.datamancy.net'}
            if invocation['serviceId'] in a12_hosts:
                require(gate['generationId'] == invocation['binding']['generationId'] and
                        gate['nativeContainerPid'] > 1 and gate['nativeContainerNetnsInode'] > 1 and
                        gate['ownerEmulatorHostPid'] == processes[0][0].pid and
                        gate['ownerEmulatorHostNetnsInode'] == os.stat('/proc/self/ns/net').st_ino and
                        gate['originalHost'] == a12_hosts[invocation['serviceId']] and
                        gate['originalCaSha256'] == os.environ['P0V3_CLIENT_CERTIFICATE_SHA256'] and
                        gate['originalLeafSha256'] == os.environ['P0V3_CLIENT_LEAF_SHA256'] and
                        HEX.fullmatch(gate['nftPolicySha256']) and
                        HEX.fullmatch(gate['nativeNftReadbackSha256']),
                        'A12 guest authority does not bind real original-host native parentage')
            break
        time.sleep(.1)
    else: raise TimeoutError('Native owner/reader emulator bridge gate absent')
    if invocation['serviceId'] in ('onlyoffice', 'seafile', 'element', 'synapse',
                                   'matrix-authentication-service', 'livekit',
                                   'donetick', 'homeassistant', 'jellyfin', 'mastodon', 'ntfy'):
        guest_ca_adoption(invocation, context, clients, gate)
    return digest(private(guest_gate))


def runner(invocation, env, ca_env, gate, guest_gate_sha):
    manifest_bytes = (SUITE / 'cases/manifest.json').read_bytes()
    require(digest(manifest_bytes) == invocation['manifestSha256'], 'acceptance manifest changed')
    manifest = json.loads(manifest_bytes)
    matches = [item for item in manifest['cases'] if all(item.get(key) == invocation[key]
               for key in ('serviceId', 'surface', 'journey', 'variant'))]
    require(len(matches) == 1 and matches[0]['runner'] == 'scripts/qualified-runner.py',
            'no exact immutable case runner')
    definition = matches[0]
    adapter = SUITE / definition['adapter']
    require(adapter.is_file() and adapter.resolve().is_relative_to(SUITE) and adapter.stat().st_size <= 16777216 and
            digest(adapter.read_bytes()) == env['P0V3_CASE_ADAPTER_SHA256'], 'foreign adapter source')
    program = SUITE / 'scripts/qualified-runner.py'
    require(program.is_file() and digest(program.read_bytes()) == invocation['runnerSha256'],
            'qualified-runner bytes changed')
    for name in ('home', 'tmp', 'runtime', 'home/.config', 'home/.cache', 'home/.local', 'home/.local/share'):
        (CASE / name).mkdir(mode=0o700, exist_ok=True)
    selection = {'PATH': '/opt/qualified-tools/bin:/opt/android-sdk/platform-tools:/usr/bin:/bin',
                 'HOME': str(CASE / 'home'), 'TMPDIR': str(CASE / 'tmp'),
                 'XDG_RUNTIME_DIR': str(CASE / 'runtime'), 'XDG_CONFIG_HOME': str(CASE / 'home/.config'),
                 'XDG_CACHE_HOME': str(CASE / 'home/.cache'),
                 'XDG_DATA_HOME': str(CASE / 'home/.local/share'),
                 'ANDROID_HOME': '/opt/android-sdk', 'ANDROID_AVD_HOME': '/opt/android-avd',
                 'ANDROID_SDK_ROOT': '/opt/android-sdk', 'JAVA_HOME': '/opt/qualified-tools',
                 'P0V3_CASE_ID': invocation['serviceId'], 'P0V3_CASE_SURFACE': invocation['surface'],
                 'P0V3_CASE_JOURNEY': invocation['journey'], 'P0V3_CASE_VARIANT': invocation['variant'],
                 'P0V3_CASE_INVOCATION_ID': invocation['invocationId'],
                 'P0V3_CASE_GENERATION': invocation['binding']['generationId'],
                 'P0V3_CASE_PHASE': invocation['binding']['phase'],
                 'P0V3_CASE_ARTIFACT_DIR': str(CASE),
                 'P0V3_CASE_NATIVE_RESULT': str(CASE / 'native-result.json'),
                 'P0V3_CASE_CONTEXT': str(CASE / 'context.json'),
                 'P0V3_CASE_GATE_REQUIRED': '1',
                 'P0V3_CASE_ADAPTER': str(adapter),
                 'P0V3_CASE_ADAPTER_SHA256': env['P0V3_CASE_ADAPTER_SHA256'],
                 'P0V3_QCLIENT_INVOCATION_ID': invocation['invocationId'],
                 'P0V3_QCLIENT_GATE_SHA256': digest(private(CASE / 'qualification-client-gate.json')),
                 'P0V3_QCLIENT_CONTAINER_ID': gate['nativeContainerId']}
    selection.update(ca_env)
    if guest_gate_sha is not None:
        require(invocation['surface'] == 'ANDROID' and HEX.fullmatch(guest_gate_sha),
                'Only host-adopted official Android guest may receive a guest gate')
        selection['P0V3_QGUEST_GATE_SHA256'] = guest_gate_sha
    native_claim = env.get('P0V3_NATIVE_CASE_CLAIM_SHA256')
    native_claim_required = (invocation['surface'] == 'HEADLESS' and invocation['variant'] == 'NATIVE'
        and invocation['serviceId'] == 'qbittorrent')
    require((native_claim_required and isinstance(native_claim, str) and HEX.fullmatch(native_claim)) or
            (not native_claim_required and native_claim is None),
            'Only the host-adopted post-intent native case claim may authorize this runner')
    if native_claim_required: selection['P0V3_NATIVE_CASE_CLAIM_SHA256'] = native_claim
    if definition.get('url'): selection['P0V3_CASE_URL'] = definition['url']
    log = os.open(CASE / 'runner.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process = None
    with os.fdopen(log, 'wb') as stream:
        try:
            process = subprocess.Popen([str(program)], cwd=str(SUITE), env=selection,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            deadline = time.monotonic() + 3600
            total = 0
            while True:
                require(time.monotonic() < deadline, 'Native client runner deadline exceeded')
                ready, _, _ = select.select([process.stdout], [], [], .2)
                if not ready:
                    require(process.poll() is None, 'Native client runner output pipe not closed')
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk: break
                total += len(chunk)
                require(total <= 4 * 1024 * 1024, 'Native runner output exceeded private cap')
                stream.write(chunk)
            stream.flush(); os.fsync(stream.fileno())
            require(process.wait(timeout=1) == 0 and (CASE / 'native-result.json').is_file(),
                    'native UI/client journey did not emit independently verified result')
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def allowed_qualified_client(intent, mode):
    """No private HEADLESS runner can enter QClient as a second case executor."""
    if mode == 'NATIVE_NETWORK_DENIAL':
        return (intent.get('surface') == 'HEADLESS' and intent.get('variant') == 'NATIVE'
                and intent.get('serviceId') in ('alloy', 'loki'))
    if mode != 'NORMAL': return False
    if intent.get('surface') == 'HEADLESS':
        return intent.get('variant') == 'NATIVE' and intent.get('serviceId') in (
            'mastodon', 'sogo', 'seafile', 'homeassistant', 'jellyfin', 'qbittorrent', 'searxng',
            'grafana', 'prometheus', 'alertmanager')
    return (intent.get('surface') == 'WEB' and intent.get('variant') == 'BROWSER' or
            intent.get('surface') == 'ANDROID' and intent.get('variant') in ('API34', 'API36'))


def main():
    os.umask(0o077)
    require(sys.argv == [sys.argv[0], '/case', sys.argv[-1]] and
            re.fullmatch(r'[a-z][a-z0-9-]{0,95}', sys.argv[-1]) and
            CASE.is_dir() and stat.S_IMODE(CASE.stat().st_mode) == 0o700 and
            CASE.stat().st_uid == os.getuid(), 'foreign private qualification case')
    env = dict(os.environ)
    host_names = env['P0V3_CLIENT_HOSTS'].split(',')
    require(host_names == sorted(set(host_names)) and 1 <= len(host_names) <= 64 and
            all(HOST.fullmatch(host) for host in host_names), 'nonexact or wildcard client DNS')
    address = ipaddress.IPv4Address(env['P0V3_CLIENT_CADDY_IP'])
    require(address.is_private and not address.is_loopback and not address.is_link_local and
            HEX.fullmatch(env['P0V3_CLIENT_REQUEST_SHA256']) and
            HEX.fullmatch(env['P0V3_CLIENT_CERTIFICATE_SHA256']) and
            HEX.fullmatch(env['P0V3_CLIENT_LEAF_SHA256']) and
            HEX.fullmatch(env['P0V3_CASE_ADAPTER_SHA256']), 'unreviewed native client input')
    intent = load(CASE / 'intent.json')
    context = load(CASE / 'context.json')
    require(intent['invocationId'] == sys.argv[-1] and
            digest(private(CASE / 'context.json')) == intent['contextSha256'] and
            allowed_qualified_client(intent, env.get('P0V3_CLIENT_MODE')) and
            intent['binding']['phase'] in ('INSTALL', 'RESTORE') and
            intent['surface'] in ('WEB', 'ANDROID', 'HEADLESS') and
            env.get('P0V3_CLIENT_MODE') in ('NORMAL', 'NATIVE_NETWORK_DENIAL') and
            (env['P0V3_CLIENT_MODE'] != 'NATIVE_NETWORK_DENIAL' or
             intent['serviceId'] in ('alloy', 'loki') and
             intent['surface'] == 'HEADLESS' and intent['variant'] == 'NATIVE'),
            'foreign scoped case')
    stop = threading.Event()
    thread = threading.Thread(target=fixed_dns, args=(set(host_names), str(address), stop), daemon=True)
    thread.start()
    processes = []
    try:
        gate = wait_gate(intent, env)
        require(not stop.is_set(), 'scoped client DNS failed before native adoption')
        if env['P0V3_CLIENT_MODE'] == 'NATIVE_NETWORK_DENIAL':
            # This is an actual pinned native network negative client, not a stand-in
            # application runner. Controller proves a real denied socket and nft counter,
            # then Podman stop+namespace disappearance is an independent typed fence.
            while True:
                require(not stop.is_set(), 'scoped negative client DNS failed')
                time.sleep(.25)
        seafile_official_tools(intent, gate, env, str(address))
        ca_env = ca_adoption(intent, env)
        guest_gate_sha = official_emulators(intent, context, processes)
        runner(intent, env, ca_env, gate, guest_gate_sha)
    finally:
        for process, _, _, _ in processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=4)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=4)
        stop.set(); thread.join(timeout=2)


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Credentials, URLs and browser/Android outputs belong only in mode-0600 case records.
        print('Owned native client refused: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
