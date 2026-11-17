#!/usr/bin/env python3
"""Third explicit Timescale build revision after the recorded r2 terminal failure.

The r1 missing original result remains held with its separate read-only reconciliation;
r2 has a durable exit-100 result. Neither original is replayed, cleaned or overwritten.
"""
import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name('build-timescale-image.py')
spec = importlib.util.spec_from_file_location('timescale_artifact_builder', SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
PARENT = Path('/mnt/media/p0-v3/image-acquisition-receipts')
original = PARENT / 'timescale-pg17-231-r1'
failed = PARENT / 'timescale-pg17-231-r2'
reconciled = json.loads(builder.original(original / 'build.reconciliation-v1.json'))
result = json.loads(builder.original(failed / 'build.result.json'))
if (reconciled.get('status') != 'terminal-build-error-observed-original-result-absent' or
        reconciled.get('originalOperationReplayAuthorized') is not False or
        (original / 'build.result.json').exists() or result.get('exitCode') != 100 or
        builder.sha(builder.original(failed / 'build.intent.json')) != result.get('intentSha256') or
        builder.sha(builder.original(failed / 'build.stdout', 2_000_000)) != result.get('stdoutSha256') or
        builder.sha(builder.original(failed / 'build.stderr', 2_000_000)) != result.get('stderrSha256') or
        b'Pathname to install is not absolute' not in builder.original(failed / 'build.stderr', 2_000_000)):
    raise RuntimeError('Prior build outcomes not reconciled; no revised build')
builder.JOB = 'timescale-pg17-231-r3'
builder.ROOT = PARENT / builder.JOB
builder.NAME = 'p0v3-build-' + builder.JOB
builder.TAG = 'localhost/p0-v3/postgres-timescale:2.31.0-pg17.11-r3'

if __name__ == '__main__':
    builder.main()
