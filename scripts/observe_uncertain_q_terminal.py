#!/usr/bin/env python3
"""Read-only, NON-terminal safety disposition of the fenced original generation.

Never interprets exited CIDs, missing results or this observation as an ACK.
Writes only a separately named coordination report, not release-generation
files, systemd state, Podman state, ownership or capacity-terminal evidence.
"""
import hashlib
import json
from pathlib import Path
import sys

GEN = 'q-d874eb36057e'
ROOT = Path('/mnt/media/p0-v3/release-generations') / GEN
OUT = Path(__file__).resolve().parents[2] / '.coord/rapid-completion/q-d874-readonly-disposition-100.json'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    if not ROOT.is_dir() or ROOT.is_symlink() or OUT.exists():
        raise ValueError('Original receipt directory missing or observation already exists')
    names = ('bundle.json', 'quadlet-serve-stop.intent.json', 'quadlet-serve-stop.result.json',
             'quadlet-serve.result.json', 'quadlet-capacity.terminal.json',
             'quadlet-stop-' + GEN + '-canonical-shared-core-v3-node-exporter.intent.json',
             'quadlet-stop-' + GEN + '-canonical-shared-core-v3-node-exporter.result.json')
    observed = {}
    for name in names:
        path = ROOT / name
        if path.is_symlink():
            raise ValueError('Symlinked original receipt')
        observed[name] = {'present': path.is_file()}
        if path.is_file():
            observed[name].update(size=path.stat().st_size, sha256=sha(path))
    missing = [name for name, state in observed.items() if name != 'bundle.json' and not state['present']]
    stop_intents = sorted(path for path in ROOT.glob('quadlet-stop-*.intent.json') if path.is_file())
    stopped = {path.name.removesuffix('.intent.json'): {
        'originalIntentSha256': sha(path),
        'originalResultPresent': path.with_name(path.name.replace('.intent.json', '.result.json')).is_file(),
        'delegateAckPresent': (ROOT / path.name.replace('quadlet-stop-', 'quadlet-delegate-')
                               .replace('.intent.json', '-stop.ack.json')).is_file(),
    } for path in stop_intents}
    report = {'schemaVersion': 1, 'generation': GEN, 'disposition': 'UNRECONCILED_NONTERMINAL',
              'observationOnly': True, 'originalStopAcknowledged': False,
              'capacityReleased': False, 'nativeReplayAuthorized': False,
              'evidence': observed, 'missingOriginalReceipts': missing,
              'individualOriginalStopIntents': stopped,
              'caveat': 'Read-only observations, including exited CIDs, are not original stop/serve/capacity ACKs.'}
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open('x', encoding='utf-8') as target:
        json.dump(report, target, indent=2, sort_keys=True)
        target.write('\n')
    OUT.chmod(0o600)
    print(f'{GEN}: {report["disposition"]}; missing original receipts={len(missing)}; '
          f'original stop intents={len(stopped)}')

if __name__ == '__main__':
    main()
