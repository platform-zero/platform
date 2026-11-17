#!/usr/bin/env python3
"""One-use r3 read-only copy of r2 normalized OCI; never recover the lost build ACK.

The r2 mode-0600 archive and its index-only normalization receipt stay untouched.
Copying to a distinct mode-0400 inode satisfies managed PREPARE's *first* native
source permission check; no image import, podman, or application start occurs.
"""
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

BASE = Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes')
R2 = BASE/'worklane-platform-r2'
R3 = BASE/'worklane-platform-r3'
TERMINAL = Path('/mnt/media/p0-v3/release-generations/q-dd36ebcf43ef/failed-pre-unit-stage-v1.disposition.json')
EXPECTED_TERMINAL = '1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3'
EXPECTED_R2_RECEIPT = '67bc6a57deb494066ef1d2090a2fcdd03bd707a93c942847ed6b7afedb2145db'
EXPECTED_ARCHIVE = '8c1cc42df10cd5086b33e817012e08a63b3ae6899270b1c76494dd831224e7bd'
ARCHIVE = 'worklane-platform.oci.tar'

def digest(b): return hashlib.sha256(b).hexdigest()
def encode(v): return (json.dumps(v, sort_keys=True, separators=(',', ':'))+'\n').encode()
def filehash(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024), b''): h.update(chunk)
    return h.hexdigest()
def checked(path, mode, size_limit=32768):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=mode or s.st_nlink!=1 or s.st_uid!=os.geteuid() or s.st_size>size_limit:
        raise RuntimeError('Changed/unsafe private source: '+str(path))
    fd=os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
    try:
        with os.fdopen(fd,'rb') as f: return f.read()
    except BaseException:
        os.close(fd)
        raise

def save(path, body):
    fd=os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as f: f.write(body); f.flush(); os.fsync(f.fileno())
    fsync_dir(path.parent)
def fsync_dir(path):
    fd=os.open(path, os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def main():
    if R3.exists() or R3.is_symlink(): raise RuntimeError('r3 already attempted: never replay')
    if R2.lstat().st_mode & 0o777 != 0o700 or R2.is_symlink(): raise RuntimeError('r2 source dir changed')
    r2raw=checked(R2/'normalize.result.json', 0o600)
    r2=json.loads(r2raw)
    r2intent=checked(R2/'normalize.intent.json', 0o600)
    old=checked(BASE/'q-5962a9fda75b'/'worklane-export.result.json', 0o600)
    terminal=checked(TERMINAL,0o600)
    source=R2/ARCHIVE
    s=source.lstat()
    if digest(r2raw)!=EXPECTED_R2_RECEIPT or digest(terminal)!=EXPECTED_TERMINAL or \
        digest(r2intent)!=r2['intentSha256'] or \
        r2['archiveSha256']!=EXPECTED_ARCHIVE or r2['archiveBytes']!=s.st_size or \
        r2['originalBuildAcknowledged'] is not False or r2['separateExportAcknowledged'] is not True or \
        r2['nativeImportOccurred'] is not False or r2['qualificationEvidence'] is not False or \
        json.loads(old)['originalBuildAcknowledged'] is not False or \
        not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=os.geteuid() or s.st_nlink!=1 or \
        filehash(source)!=EXPECTED_ARCHIVE:
        raise RuntimeError('Original export/normalization/mode custody changed')
    mem=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
    if mem<16384+4096 or shutil.disk_usage(BASE).free<r2['archiveBytes']+10240*1048576:
        raise RuntimeError('Native floor and exact copy scratch not available')
    R3.mkdir(mode=0o700);fsync_dir(BASE)
    intent=encode({'schemaVersion':1,'action':'distinct-read-only-copy-of-normalized-oci-not-build-ack',
       'r2NormalizeResultSha256':EXPECTED_R2_RECEIPT,'r2ArchiveSha256':EXPECTED_ARCHIVE,
       'originalArchiveSha256':r2['originalArchiveSha256'],'originalBuildAcknowledged':False,
       'separateExportAcknowledged':True,'failedPreUnitTerminalSha256':EXPECTED_TERMINAL,
       'sourceMode':'0600','outputMode':'0400','nativeImportOccurred':False,'qualificationEvidence':False})
    save(R3/'pin.intent.json',intent)
    fd=os.open(R3/ARCHIVE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    src_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        h=hashlib.sha256();n=0
        with os.fdopen(fd,'wb') as dest,os.fdopen(src_fd,'rb') as src:
            for chunk in iter(lambda:src.read(4*1024*1024),b''):
                n+=len(chunk);h.update(chunk);dest.write(chunk)
            dest.flush()
            os.fchmod(dest.fileno(),0o400)
            os.fsync(dest.fileno())
    except BaseException:
        # Retain partial archive and intent for read-only reconciliation; never replay.
        raise
    fsync_dir(R3)
    out=R3/ARCHIVE
    if n!=r2['archiveBytes'] or h.hexdigest()!=EXPECTED_ARCHIVE or filehash(source)!=EXPECTED_ARCHIVE or \
        filehash(out)!=EXPECTED_ARCHIVE or stat.S_IMODE(out.lstat().st_mode)!=0o400 or out.lstat().st_nlink!=1:
        raise RuntimeError('Read-only copy verification failed: retain intent without result')
    proof=encode({'schemaVersion':1,'intentSha256':digest(intent),'r2NormalizeResultSha256':EXPECTED_R2_RECEIPT,
       'r2ArchiveSha256':EXPECTED_ARCHIVE,'originalArchiveSha256':r2['originalArchiveSha256'],
       'archiveSha256':EXPECTED_ARCHIVE,'archiveBytes':n,'archiveMode':'0400',
       'originalBuildAcknowledged':False,'separateExportAcknowledged':True,
       'nativeImportOccurred':False,'nativeApplicationStarted':False,'qualificationEvidence':False,
       'before':r2['before'],'after':r2['after']})
    save(R3/'pin.result.json',proof)
    print(json.dumps({'readOnlyArchive':str(out),'sha256':EXPECTED_ARCHIVE,'mode':'0400',
      'r2NormalizedArchivePreserved':True,'originalBuildAcknowledged':False,'nativeImportOccurred':False},sort_keys=True))

if __name__=='__main__': main()
