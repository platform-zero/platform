#!/usr/bin/env python3
"""Corrected offline package-order build, only after independent original-failure reconciliation.

Never replaces, resumes, retries or cleans timescale-pg17-231-r1. A different reviewed
recipe revision has a different build namespace, context and image identity.
"""
import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name('build-timescale-image.py')
spec = importlib.util.spec_from_file_location('timescale_artifact_builder', SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

ORIGINAL = Path('/mnt/media/p0-v3/image-acquisition-receipts/timescale-pg17-231-r1')
receipt = json.loads(builder.original(ORIGINAL / 'build.reconciliation-v1.json'))
if (receipt.get('operation') != 'timescale-pg17-231-r1' or
        receipt.get('status') != 'terminal-build-error-observed-original-result-absent' or
        receipt.get('originalResultPresent') is not False or
        receipt.get('builtTaggedImagePresent') is not False or
        receipt.get('matchingBuildahIntermediatesPresent') is not False or
        receipt.get('originalOperationReplayAuthorized') is not False or
        not builder.original(ORIGINAL / 'build.intent.json') or
        (ORIGINAL / 'build.result.json').exists()):
    raise RuntimeError('Original build uncertainty not reconciled; no revised build')
for name, key in (('build.intent.json', 'originalIntentSha256'),
                  ('build.stdout', 'originalStdoutSha256'),
                  ('build.stderr', 'originalStderrSha256')):
    if builder.sha(builder.original(ORIGINAL / name, 2_000_000)) != receipt[key]:
        raise RuntimeError('Reconciled original evidence changed')
builder.JOB = 'timescale-pg17-231-r2'
builder.ROOT = builder.ROOT.parent / builder.JOB
builder.NAME = 'p0v3-build-' + builder.JOB
builder.TAG = 'localhost/p0-v3/postgres-timescale:2.31.0-pg17.11-r2'

if __name__ == '__main__':
    builder.main()
