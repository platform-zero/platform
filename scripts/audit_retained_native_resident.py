#!/usr/bin/env python3
"""Point-in-time retained native cgroup observations; never a fresh-r9 working budget.

No env, process argv, volume content or Podman application effects are read.
"""
import datetime
import json
import re
from pathlib import Path
from audit_retained_native_limits import CMD, native

UNIT = {'B': 1, 'kB': 1000, 'KB': 1000, 'KiB': 1024,
        'MB': 1000**2, 'MiB': 1024**2, 'GB': 1000**3, 'GiB': 1024**3}
SIZE = re.compile(r'^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)$')

def size_bytes(value):
    match = SIZE.fullmatch(value.strip())
    if not match or match.group(2) not in UNIT:
        raise ValueError('Unrecognized native resident-memory unit')
    return round(float(match.group(1)) * UNIT[match.group(2)])

def ids(cmd):
    rows = native(cmd + ['ps', '--no-trunc', '--format', '{{.ID}}']).splitlines()
    if len(rows) > 4096 or len(set(rows)) != len(rows) or any(not re.fullmatch('[a-f0-9]{64}', i) for i in rows):
        raise ValueError('Changed or ambiguous native retained CID census')
    return rows

def main():
    observations = []
    for store, cmd in CMD.items():
        before = ids(cmd)
        if not before:
            continue
        stats = native(cmd + ['stats', '--no-stream', '--no-trunc', '--format', '{{.ID}}\t{{.MemUsage}}'] + before)
        readings = {}
        for line in stats.splitlines():
            row = line.split('\t')
            if len(row) != 2 or row[0] in readings or row[0] not in before or ' / ' not in row[1]:
                raise ValueError('Ambiguous native memory usage or CID')
            resident, limit = row[1].split(' / ', 1)
            readings[row[0]] = {'observedUsageBytes': size_bytes(resident),
                                'observedLimitBytes': size_bytes(limit)}
        if len(readings) != len(before) or ids(cmd) != before:
            raise ValueError('Retained native cgroup set changed during measurement')
        observations.extend({'store': store, 'cid': cid, **readings[cid]} for cid in before)
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))) * 1024
    stat = __import__('os').statvfs('/mnt/media/p0-v3')
    print(json.dumps({'schemaVersion': 1, 'scope': 'point-in-time-retained-cgroup-usage-not-r9-resident-budget',
                      'observedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'runningCids': len(observations),
                      'retainedObservedUsageBytes': sum(row['observedUsageBytes'] for row in observations),
                      'hostMemAvailableBytes': available, 'diskAvailableBytes': stat.f_bavail * stat.f_frsize,
                      'containers': observations, 'freshR9Measured': False, 'startupAdmission': False},
                     indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
