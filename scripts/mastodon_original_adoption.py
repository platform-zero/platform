#!/usr/bin/python3
"""Fixed original Mastodon PostgreSQL export for the canonical shared provider.

COORD passes ONLY a `MastodonRecovery.canonicalSource(RecoveredGeneration)`-bound
source, holds controller exclusion + source isolation + scratch reservation,
materializes original bootstrap/uploads/Valkey with A03's authenticated tar
import, then imports this produced custom-format dump through the declared
`mastodon-sql-adopt` oneShot. An uncertain export/import is never retried.
Read ONLY an independently imported disposable source COPY from authenticated
Kopia volume archives. NEVER start, exec into or mutate the held original source.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports/effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import select
import time

HASH = re.compile(r'[a-f0-9]{64}\Z')
GEN = re.compile(r'q-[a-f0-9]{12}\Z')
PODMAN = ['/usr/bin/sudo', '-n', '/usr/bin/podman', '--remote=false',
          '--root=/mnt/media/p0-v3/release-runtime/graph',
          '--runroot=/run/p0-v3-release-runtime/store',
          '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def need(ok, reason='Original social source cannot be adopted'):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private(path, limit=1048576):
    file = Path(path)
    need(file.is_absolute() and file.resolve() == file)
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_nlink == 1 and info.st_uid == os.getuid() and 0 < info.st_size <= limit)
        content = stream.read(limit + 1)
        need(len(content) == info.st_size)
        return content


def save(path, content):
    file = Path(path)
    data = content if isinstance(content, bytes) else json.dumps(content, sort_keys=True, separators=(',', ':')).encode()
    need(file.is_absolute() and file.parent.is_dir() and
         stat.S_IMODE(file.parent.stat().st_mode) == 0o700 and file.parent.stat().st_uid == os.getuid())
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return sha(data)


def inspected(cid):
    need(HASH.fullmatch(cid))
    result = subprocess.run(PODMAN + ['inspect', cid], capture_output=True, timeout=30)
    need(result.returncode == 0 and len(result.stdout) <= 1048576)
    records = json.loads(result.stdout)
    need(len(records) == 1 and records[0]['Id'] == cid)
    return records[0]


def source(request):
    """No file or process effects before COMPLETE source/target/owner preflight."""
    expected = {'schemaVersion', 'sourceGenerationId', 'targetGenerationId',
                'sourceMember', 'sourceBundleSha256', 'sourceManifestPath',
                'sourceManifestSha256', 'sourceInputDirectory', 'sourceInputHashes',
                'copyPostgresContainerId', 'copyReceiptFile', 'sourceArchiveHashes',
                'originalTokenCustodyFile', 'originalTokenCustodySha256',
                'kopiaSnapshotId', 'kopiaReceiptSha256', 'stagingDirectory',
                'maximumDumpBytes', 'maximumDumpSeconds'}
    need(set(request) == expected and request['schemaVersion'] == 1 and
         GEN.fullmatch(request['sourceGenerationId']) and GEN.fullmatch(request['targetGenerationId']) and
         request['sourceGenerationId'] != request['targetGenerationId'] and
         request['sourceMember'].startswith(request['sourceGenerationId'] + '-') and
         all(HASH.fullmatch(request[key]) for key in ('sourceBundleSha256',
             'sourceManifestSha256', 'kopiaReceiptSha256')) and
         re.fullmatch(r'[a-zA-Z0-9_.:-]{10,200}', request['kopiaSnapshotId']) and
         set(request['sourceArchiveHashes']) == {'postgres', 'valkey', 'uploads', 'bootstrap'} and
         all(HASH.fullmatch(value) for value in request['sourceArchiveHashes'].values()) and
         HASH.fullmatch(request['originalTokenCustodySha256']) and
         isinstance(request['maximumDumpBytes'], int) and
         1048576 <= request['maximumDumpBytes'] <= 64 * 1024 ** 3 and
         isinstance(request['maximumDumpSeconds'], int) and
         60 <= request['maximumDumpSeconds'] <= 3600)
    spec_path = Path(request['sourceManifestPath'])
    need(spec_path.name == 'spec.json' and spec_path.parent.name == request['sourceMember'] and
         sha(private(spec_path)) == request['sourceManifestSha256'])
    spec = json.loads(private(spec_path))
    need(spec['name'] == request['sourceMember'] and spec.get('store', 'LEGACY') == 'LEGACY' and
         {v['id'] for v in spec['volumes']} == set(request['sourceArchiveHashes']) and
         {'mastodon', 'postgres', 'valkey', 'mastodon-rss-accounts'} <=
         {p['id'] for p in spec['processes']})
    source_inputs = Path(request['sourceInputDirectory'])
    need(source_inputs.is_absolute() and source_inputs.resolve() == source_inputs and
         source_inputs.parent == spec_path.parent and source_inputs.name == 'inputs' and
         set(request['sourceInputHashes']) == {p['environmentFile'] for p in spec['processes']
             if p.get('environmentFile')} | {f['file'] for p in spec['processes'] for f in p.get('files', [])})
    for name, digest in request['sourceInputHashes'].items():
        need(re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name) and HASH.fullmatch(digest) and
             sha(private(source_inputs / name)) == digest)
    # COORD creates a disposable isolated COPY via A03 verified import. This
    # receipt binds each exact original archive and native re-export descriptor.
    # It is NOT permission to start/exec into the held source member.
    copy = json.loads(private(request['copyReceiptFile'], 16384))
    need(set(copy) == {'sourceGenerationId', 'targetGenerationId', 'sourceMember',
         'sourceBundleSha256', 'copyDeployment', 'copyFingerprint',
         'copyPostgresContainerId', 'originalArchiveHashes', 'nativeImportedArchiveHashes',
         'sourceKopiaReceiptSha256', 'postImportIsolationSha256',
         'originalTokenCustodySha256'} and
         copy['sourceGenerationId'] == request['sourceGenerationId'] and
         copy['targetGenerationId'] == request['targetGenerationId'] and
         copy['sourceMember'] == request['sourceMember'] and
         copy['sourceBundleSha256'] == request['sourceBundleSha256'] and
         copy['sourceKopiaReceiptSha256'] == request['kopiaReceiptSha256'] and
         copy['originalTokenCustodySha256'] == request['originalTokenCustodySha256'] and
         copy['originalArchiveHashes'] == copy['nativeImportedArchiveHashes'] == request['sourceArchiveHashes'] and
         copy['copyPostgresContainerId'] == request['copyPostgresContainerId'] and
         copy['copyDeployment'].startswith(request['targetGenerationId'] + '-mastodon-source-copy') and
         re.fullmatch(r'[a-z][a-z0-9-]{1,39}', copy['copyDeployment']) and
         HASH.fullmatch(copy['copyFingerprint']) and HASH.fullmatch(copy['postImportIsolationSha256']),
         'Original-source copy/import/target isolation lineage not authenticated')
    source_pg = inspected(request['copyPostgresContainerId'])
    source_image = next(p for p in spec['processes'] if p['id'] == 'postgres')['imageId']
    need(HASH.fullmatch(source_image) and source_pg['Image'].removeprefix('sha256:') == source_image and
         source_pg['Name'].lstrip('/') == 'p0v3-live-' + copy['copyDeployment'] + '-postgres' and
         source_pg['Config']['Labels']['io.p0v3.private-deployment'] == copy['copyDeployment'] and
         source_pg['Config']['Labels']['io.p0v3.runtime-fingerprint'] == copy['copyFingerprint'] and
         source_pg['State']['Running'] is True and source_pg['State']['Pid'] > 1 and
         not source_pg['HostConfig'].get('PortBindings') and
         source_pg['HostConfig']['NetworkMode'] != 'host' and
         set(source_pg['NetworkSettings']['Networks']) ==
             {'p0v3-live-' + copy['copyDeployment'] + '-net'},
         'Imported source COPY is published, unbound or has changed identity')
    stage = Path(request['stagingDirectory'])
    need(stage.is_absolute() and stage.resolve() == stage and stage.is_dir() and
         stat.S_IMODE(stage.stat().st_mode) == 0o700 and stage.stat().st_uid == os.getuid())
    admin = private(source_inputs / 'postgres.env').decode()
    match = re.fullmatch(r'POSTGRES_PASSWORD=([a-f0-9]{64})\n', admin)
    original_env = private(source_inputs / 'mastodon.env').decode()
    need(match is not None and 'LOCAL_DOMAIN=social.datamancy.net\n' in original_env,
         'Source copy lacks original PostgreSQL credential or APPROVED original actor identity')
    selection = json.loads(private(source_inputs / 'rss-accounts.json'))
    custody = json.loads(private(request['originalTokenCustodyFile'], 65536))
    need(sha(private(request['originalTokenCustodyFile'], 65536)) == request['originalTokenCustodySha256'] and
         Path(request['originalTokenCustodyFile']).name == 'rss-tokens.json' and
         custody['schemaVersion'] == 1 and custody['publicationEnabled'] is False and
         len(selection) == len(custody['accounts']) == 47 and
         len({row['account'] for row in selection}) == 47 and
         {row['account'] for row in selection} == {row['account'] for row in custody['accounts']},
         'Original 47 token custody was not imported from authenticated bootstrap COPY')
    feed = {row['account']: row for row in selection}
    for row in custody['accounts']:
        need(re.fullmatch(r'rss_[a-z0-9_]{1,23}', row['account']) and
             row['feedId'] == feed[row['account']]['feedId'] and
             row['pack'] == feed[row['account']]['pack'] and
             re.fullmatch(r'[0-9]+', row['accountId']) and
             re.fullmatch(r'[a-fA-F0-9]{32,128}', row['token']),
             'Original account/token/feed/pack selection changed')
    return stage, match.group(1), sha(private(request['copyReceiptFile'], 16384)), custody


def sql_readback(container_id, password, custody):
    """Bounded SELECT only inside imported COPY. Never query held source or print tokens."""
    sql = ("SELECT a.username,a.id,u.id,a.bot,u.confirmed_at IS NOT NULL,u.approved,"
           "t.token,t.scopes,t.revoked_at IS NULL FROM accounts a "
           "JOIN users u ON u.account_id=a.id "
           "LEFT JOIN oauth_access_tokens t ON t.resource_owner_id=u.id "
           "WHERE a.domain IS NULL AND (a.bot=TRUE OR a.username IN ('owner','reader')) "
           "ORDER BY a.username,t.id LIMIT 512")
    fixed = ('IFS= read -r original_password; export PGPASSWORD="$original_password"; '
             'exec /usr/lib/postgresql/17/bin/psql -X -q -t -A -F "\t" '
             '-h 127.0.0.1 -U postgres -d mastodon -c "$1"')
    result = subprocess.run(PODMAN + ['exec', '-i', '--user=999:999', container_id,
        '/bin/sh', '-ec', fixed, 'p0v3-copy-sql', sql], input=(password + '\n').encode(),
        capture_output=True, timeout=60, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    need(result.returncode == 0 and len(result.stdout) < 131072 and len(result.stderr) < 4096,
         'Imported source COPY SQL readback failed; never query held original')
    indexed = {}
    originals = {row['account']: row for row in custody['accounts']}
    owners = {}
    for line in result.stdout.decode('utf-8', 'strict').splitlines():
        fields = line.split('\t')
        need(len(fields) == 9 and re.fullmatch(r'[0-9]+', fields[1]) and
             re.fullmatch(r'[0-9]+', fields[2]))
        name, account_id, user_id, bot, confirmed, approved, token, scopes, active = fields
        if name in ('owner', 'reader'):
            need(bot == 'f' and confirmed == approved == 't' and
                 (name not in owners or owners[name] == account_id),
                 'Original owner/reader SQL identity was recreated')
            owners[name] = account_id
        elif name in originals:
            expected = originals[name]
            if token == expected['token']:
                need(bot == confirmed == approved == active == 't' and
                     account_id == expected['accountId'] and
                     scopes == 'read:accounts write:statuses' and name not in indexed,
                     'Original 47 SQL ID, token bytes or productive scopes changed')
                indexed[name] = {'accountId': account_id, 'userId': user_id,
                                 'tokenSha256': sha(token.encode())}
    need(set(owners) == {'owner', 'reader'} and set(indexed) == set(originals),
         'Original 47 source PostgreSQL principals/tokens missing')
    return {'ownerId': owners['owner'], 'readerId': owners['reader'],
            'original47SqlSha256': sha(json.dumps(indexed, sort_keys=True, separators=(',', ':')).encode())}


def export(request):
    stage, password, imported_copy_sha, custody = source(request)
    intent = stage / 'mastodon-original-export.intent.json'
    save(intent, {'sourceGenerationId': request['sourceGenerationId'],
        'targetGenerationId': request['targetGenerationId'],
        'sourceBundleSha256': request['sourceBundleSha256'],
        'sourceManifestSha256': request['sourceManifestSha256'],
        'kopiaSnapshotId': request['kopiaSnapshotId'],
        'kopiaReceiptSha256': request['kopiaReceiptSha256'],
        'sourceArchiveHashes': request['sourceArchiveHashes'],
        'importedCopyReceiptSha256': imported_copy_sha,
        'copyPostgresContainerId': request['copyPostgresContainerId'],
        'originalTokenCustodySha256': request['originalTokenCustodySha256']})
    original_sql = sql_readback(request['copyPostgresContainerId'], password, custody)
    archive = stage / 'original-mastodon.dump'
    fd = os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    # This fixed script reads the ORIGINAL password only from stdin, never argv,
    # environment, container files, logs or generated status. Source is quiesced.
    fixed = ('IFS= read -r original_password; export PGPASSWORD="$original_password"; '
             'exec /usr/lib/postgresql/17/bin/pg_dump --format=custom --no-owner '
             '--no-acl --dbname=mastodon --host=127.0.0.1 --username=postgres')
    command = PODMAN + ['exec', '-i', '--user=999:999', request['copyPostgresContainerId'],
                        '/bin/sh', '-ec', fixed]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    digest = hashlib.sha256(); count = 0
    deadline = time.monotonic() + request['maximumDumpSeconds']
    try:
        child.stdin.write((password + '\n').encode()); child.stdin.close()
        with os.fdopen(fd, 'wb') as target:
            while True:
                need(time.monotonic() < deadline, 'Original SQL copy export exceeded admitted duration')
                if not select.select([child.stdout], [], [], min(5, deadline - time.monotonic()))[0]:
                    continue
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    break
                count += len(chunk)
                need(count <= request['maximumDumpBytes'], 'Original SQL export exceeded pre-admitted scratch')
                target.write(chunk); digest.update(chunk)
            target.flush(); os.fsync(target.fileno())
        need(child.wait(timeout=max(1, deadline - time.monotonic())) == 0 and count >= 1024,
             'Original SQL export uncertain; retain intent/archive and NEVER retry')
        need(sql_readback(request['copyPostgresContainerId'], password, custody) == original_sql,
             'Imported original COPY SQL changed during export; retain uncertain dump')
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        result = {'schemaVersion': 1, 'sourceGenerationId': request['sourceGenerationId'],
                  'targetGenerationId': request['targetGenerationId'],
                  'sourceBundleSha256': request['sourceBundleSha256'],
                  'copyPostgresContainerId': request['copyPostgresContainerId'],
                  'importedCopyReceiptSha256': imported_copy_sha,
                  'originalTokenCustodySha256': request['originalTokenCustodySha256'],
                  'originalSqlReadback': original_sql,
                  'sourceArchiveHashes': request['sourceArchiveHashes'],
                  'dumpSha256': digest.hexdigest(), 'dumpBytes': count,
                  'dumpPath': str(archive), 'intentSha256': sha(private(intent))}
        save(stage / 'mastodon-original-export.receipt.json', result)
        return result
    except BaseException:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        # Never unlink/truncate/replace unknown source export, original archive or intent.
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True); parser.add_argument('--result', required=True)
    args = parser.parse_args()
    request = json.loads(private(args.request))
    receipt = export(request)
    save(args.result, receipt)


if __name__ == '__main__':
    main()
