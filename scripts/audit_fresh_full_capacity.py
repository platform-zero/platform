#!/usr/bin/env python3
"""Read-only capacity/provenance audit for the unactivated fresh r9 graph.

Source declarations are not native running memory measurements. Follow the
exact selected index, check its SHA pins, account each selected process once,
and show one-shot/daemon, restore, default limit and application heap clues.
No native command, secret input, account, application or OCI effect is used.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import yaml
from refetch_pinned_old_references import (
    ROOT as OLD_CACHE, OLD_COMMIT, GENERATOR_COMMIT, MODULES, GENERATOR,
    MAIN, verified_reference_file,
)

OLD_DESCRIPTORS = OLD_CACHE / ('p0-modules-' + OLD_COMMIT) / 'modules'
OLD_QUADLETS = Path('/home/gerald/huly-oidc-20260923/quadlet')  # secondary rendering reference only
OLD_GENERATOR = OLD_CACHE / ('sso-stack-generator-' + GENERATOR_COMMIT) / MAIN
BASE = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments'
V3 = BASE / 'v3'
SHA = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    if path.is_symlink():
        raise ValueError('Symlinked source is forbidden')
    return yaml.safe_load(path.read_bytes())

def old_service_inventory():
    """Both OLD source descriptors and actual historical Quadlet caps; never imply RSS."""
    verified_reference_file('sso-stack-generator-' + GENERATOR_COMMIT,
                            GENERATOR_COMMIT, GENERATOR, MAIN)
    generator = OLD_GENERATOR.read_text()
    if 'if (!limits.has("memory")) policy.defaultMemory?.let { limits.put("memory", it) }' not in generator:
        raise ValueError('OLD generator default policy changed')
    quadlets = {}
    for path in OLD_QUADLETS.rglob('*.container'):
        if path.is_symlink(): raise ValueError('OLD Quadlet symlink')
        text = path.read_text()
        name = path.stem.removeprefix('webservices-')
        caps = re.findall(r'--memory=([^\s]+)', text)
        if name in quadlets or len(caps) > 1: raise ValueError('Ambiguous OLD Quadlet ' + name)
        quadlets[name] = {'source': str(path), 'sourceSha256': SHA(path),
                          'hardCap': caps[0] if caps else None,
                          'workerHeapSettings': sorted(set(re.findall(
                              r'(?:-Xm[sx][^\s"\n]+|(?:JAVA_OPTS|NODE_OPTIONS|workers?|MAX_MEMORY)[^\n]{0,90})',text,re.I)))}
    rows = []
    if not OLD_DESCRIPTORS.is_dir() or OLD_DESCRIPTORS.is_symlink():
        raise FileNotFoundError('Pinned OLD descriptors absent from verified durable cache; this audit has no authority from /tmp')
    for path in sorted(OLD_DESCRIPTORS.glob('*/legacy/stack.runtime.yaml')):
        verified_reference_file('p0-modules-' + OLD_COMMIT, OLD_COMMIT, MODULES,
                                path.relative_to(OLD_DESCRIPTORS.parent).as_posix())
        data = load(path)
        for service, config in data.get('services', {}).items():
            cap = config.get('resources', {}).get('limits', {}).get('memory')
            # No generator-wide default is proved merely by a missing service limit.
            env = config.get('environment') or {}
            if not isinstance(env, dict): env = {}
            command = str(config.get('command', ''))
            clues = {k: str(v) for k,v in env.items() if re.search(r'HEAP|WORKER|MEMORY|JAVA_OPTS|NODE_OPTIONS',k,re.I)}
            rows.append({'module': data['module'], 'service': service,
                         'descriptor': str(path), 'descriptorSha256': SHA(path),
                         'lifecycle': config.get('lifecycle'), 'descriptorHardCap': cap,
                         'quadlet': quadlets.get(service), 'memoryProvenance':
                             'descriptor-explicit' if cap else 'descriptor-unspecified-generator-policy-unknown',
                         'workerHeapEnvironment': clues, 'workerHeapCommand':
                             re.findall(r'-Xm[sx][^\s"\']+|--workers?(?:=|\s+)\d+',command)})
    return rows, quadlets

def audit(*, require_old=True):
    try:
        old_inventory, old_quadlets = old_service_inventory()
        old_verified = True
    except FileNotFoundError:
        if require_old:
            raise
        # Cache loss cannot erase selected r9 closure; do not fabricate OLD bytes.
        old_inventory, old_quadlets, old_verified = [], {}, False
    by_old = {(r['module'],r['service']):r for r in old_inventory}
    index_path = V3 / 'canonical/r9/index.yaml'
    index = load(index_path)
    manifest_path = V3 / index['manifestResource']
    if SHA(manifest_path) != index['manifestSha256']:
        raise ValueError('r9 manifest pin differs')
    manifest = load(manifest_path)
    if (manifest['revision'], manifest['scope'], len(index['entries'])) != (9, 'full-private', 39):
        raise ValueError('Not the 39-product fresh full stack')
    sources = [('v2/postgres/r1/fragment.yaml', load(BASE / 'v2/postgres/r1/fragment.yaml')),
               ('v2/forgejo/r5/fragment.yaml', load(BASE / 'v2/forgejo/r5/fragment.yaml'))]
    for entry in index['entries']:
        path = V3 / entry['resource']
        if SHA(path) != entry['sha256']:
            raise ValueError('Changed indexed fragment: ' + entry['id'])
        fragment = load(path)
        if (fragment['id'], fragment['revision']) != (entry['id'], entry['revision']):
            raise ValueError('Changed fragment identity: ' + entry['id'])
        sources.append(('v3/' + entry['resource'], fragment))
    old_modules = {m['id']: m for m in manifest['integratedReference']['modules']}
    rows = []
    for path, frag in sources:
        installing = set(frag['install']['processes'])
        restoring = set(frag['restore']['processes'])
        original = old_modules.get(frag['product'] if frag['product'] != 'postgres' else 'postgres-ssd')
        for proc in frag['processes']:
            if proc['id'] not in installing:
                continue
            # FragmentProcess.memoryMiB defaults to 512. A requested rootless
            # runner/managed-lane reservation belongs to a separate source plan.
            memory = proc.get('memoryMiB', 512)
            if not isinstance(memory, int) or memory < 1:
                raise ValueError('Invalid declared memory')
            command = ' '.join(str(item) for item in proc.get('command', []))
            clues = re.findall(r'(?:-Xm[sx]\S+|--max-old-space-size(?:=|\s)\d+|ES_JAVA_OPTS|NODE_OPTIONS|JAVA_OPTS|--memory(?:=|\s)\S+)', command)
            old = by_old.get((original['id'],proc['id'])) if original else None
            rows.append({'product': frag['product'], 'process': proc['id'], 'fragment': path,
                         'oldDirectMatch': old, 'oldMatchStatus': ('old-reference-cache-unavailable' if not old_verified else
                             'same-module-service' if old else 'unmatched-needs-dedicated-recipe-review'),
                         'fragmentSha256': SHA(BASE / path),
                         'oldModuleId': original['id'] if original else None,
                         'oldRuntimeDescriptorSha256': original['runtimeSha256'] if original else None,
                         'oldReferenceServices': [{'id': s['id'], 'lifecycle': s['lifecycle']}
                                                  for s in original['services']] if original else [],
                         'artifact': proc['artifact'], 'memoryMiB': memory,
                         'oneShot': proc.get('oneShot', False), 'onDemand': False,
                         'restored': proc['id'] in restoring,
                         'limitProvenance': 'explicit' if 'memoryMiB' in proc else 'FragmentProcess default 512 MiB',
                         'heapClues': clues, 'providers': frag.get('providers', [])})
    names = [row['process'] for row in rows]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate selected native process: ' + str(len(names) - len(set(names))))
    steady = sum(r['memoryMiB'] for r in rows if not r['oneShot'])
    shots = [r for r in rows if r['oneShot']]
    max_shot = max((r['memoryMiB'] for r in shots), default=0)
    all_shots = sum(r['memoryMiB'] for r in shots)
    providers = {p: [r['process'] for r in rows if r['process'] == p] for p in
                 ('postgres', 'forgejo', 'mariadb', 'valkey', 'memcached', 'caddy', 'keycloak', 'bao')}
    duplicated = {k: v for k, v in providers.items() if len(v) != 1}
    # Forgejo, Bao, etc are not "shared" providers for every product, but
    # they still require one actual process in this one-cohort closure.
    if duplicated:
        raise ValueError('Missing/duplicate graph service: ' + repr(duplicated))
    by_product = []
    for product in dict.fromkeys(row['product'] for row in rows):
        cohort = [row for row in rows if row['product'] == product]
        by_product.append({'product': product, 'steadyMiB': sum(r['memoryMiB'] for r in cohort if not r['oneShot']),
                           'oneShotMaxMiB': max([r['memoryMiB'] for r in cohort if r['oneShot']] or [0]),
                           'installProcesses': len(cohort), 'steadyProcesses': sum(not r['oneShot'] for r in cohort),
                           'oneShots': sum(r['oneShot'] for r in cohort)})
    mem_kib = int(re.search(r'^MemAvailable:\s+(\d+) kB$',
        Path('/proc/meminfo').read_text(), re.M).group(1))
    disk = os.statvfs('/mnt/media/p0-v3')
    return {'schemaVersion': 2, 'scope': 'offline-source-audit-not-native-admission',
            'observedHostMemAvailableMiB': mem_kib // 1024,
            'observedMediaDiskAvailableMiB': disk.f_bavail * disk.f_frsize // 1048576,
            'capacityInterpretation': 'sum of per-process hard ceilings is not measured RSS or a required simultaneous reservation; headroom is checked against measured/proposed admitted workload',
            'indexSha256': SHA(index_path), 'manifestSha256': SHA(manifest_path),
            'sourceFragments': len(sources), 'selectedProducts': len(index['entries']),
            'selectedProcessCount': len(rows), 'steadyProcesses': sum(not r['oneShot'] for r in rows),
            'oneShotProcesses': len(shots), 'steadyMemoryMiB': steady,
            'maxSingleOneShotMiB': max_shot,
            'steadyPlusLargestOneShotUpperBoundMiB': steady + max_shot,
            'oneShotSumMiBNotConcurrent': all_shots,
            'requiredMemoryHeadroomMiB': 16384,
            'steadyPlusHeadroomMiB': steady + 16384,
            'installUpperBoundPlusHeadroomMiB': steady + max_shot + 16384,
            'sharedProcessMultiplicity': {k: len(v) for k,v in providers.items()},
            'oldOnDemandReferences': [f"{m['id']}/{s['id']}" for m in old_modules.values()
                for s in m['services'] if s['lifecycle'] == 'on-demand'],
            'byProduct': by_product, 'processes': rows,
            'oldServiceInventory': old_inventory if old_verified else None,
            'oldReferenceBytesVerified': old_verified,
            'oldQuadletCount': len(old_quadlets) if old_verified else None,
            'oldQuadletsWithoutDescriptor': {name: record for name,record in old_quadlets.items()
                if name not in {r['service'] for r in old_inventory}},
            'measurement': {'freshStackRssMiB': None,
                            'reason': 'r9 never started; configured limits are ceilings, not measured RSS'},
            'oldGeneratorDefaultRule': 'resource_defaults.memory is optional; only explicit policy or descriptor gives a limit',
            'oldReferenceProvenance': {
                'cache': str(OLD_CACHE), 'modulesRepository': MODULES,
                'modulesCommit': OLD_COMMIT, 'generatorRepository': GENERATOR,
                'generatorCommit': GENERATOR_COMMIT,
                'sourceRole': 'read-only-topology-and-caps-not-state-or-native-measurement'},
            'oldGeneratorSourceSha256': SHA(OLD_GENERATOR) if old_verified else None,
            'oldGeneratorExpectedSha256FromPinnedManifest': manifest['integratedReference']['generatorSha256'],
            'oldUnspecifiedLimitsNotAssumedSafeToLower': (
                sum(r['descriptorHardCap'] is None for r in old_inventory) if old_verified else None),
            'exclusions': ['CI rootless runner/transport/job', 'managed broker/workers',
                           'backup worker', 'other retained generations', 'kernel/host memory',
                           'image/volume disk reservation']}

def markdown(data):
    lines = [
        '# Fresh r9 / pinned OLD service memory and lifecycle inventory',
        '',
        'This is a source comparison, **not** a capacity admission or native RSS.',
        f"Pinned generator `{data['oldGeneratorSourceSha256']}`: missing descriptor limits",
        'receive a limit only if the active OLD policy supplied `resource_defaults.memory`;',
        'a supporting OLD Quadlet `--memory` is separately observed, not an RSS sample.',
        f"Current fresh process ceilings: {data['steadyMemoryMiB']} MiB steady; "
        f"{data['maxSingleOneShotMiB']} MiB largest serial one-shot; "
        f"observed host MemAvailable at audit: {data['observedHostMemAvailableMiB']} MiB. "
        'No r9 process RSS exists because no full stack has been started.',
        '', f'# Current selected processes ({len(data["processes"])} rows)', '',
        '| Product | Current process | Lifecycle | Cap MiB | Current heap/worker command clues | OLD direct descriptor cap | OLD Quadlet cap | OLD lifecycle | Mapping |',
        '|---|---|---|---:|---|---|---|---|---|',
    ]
    for r in data['processes']:
        old = r['oldDirectMatch'] or {}
        lines.append('| ' + ' | '.join(str(v) for v in (
            r['product'],r['process'],'oneshot' if r['oneShot'] else 'selected steady',r['memoryMiB'],
            ', '.join(r['heapClues']) or 'not in command',old.get('descriptorHardCap') or 'unspecified',
            (old.get('quadlet') or {}).get('hardCap') or 'no matched Quadlet',
            old.get('lifecycle') or 'unmatched',r['oldMatchStatus'])) + ' |')
    lines += ['', '# Every pinned OLD descriptor service (94 rows)', '',
        '| OLD module/service | Lifecycle | Descriptor hard cap | Supporting Quadlet hard cap | Worker/heap descriptor settings | Descriptor source |',
        '|---|---|---|---|---|---|']
    for old in data['oldServiceInventory']:
        quad = old.get('quadlet') or {}
        lines.append('| ' + ' | '.join((old['module']+'/'+old['service'], str(old['lifecycle']),
            old.get('descriptorHardCap') or 'unspecified',quad.get('hardCap') or 'unmatched/none',
            ', '.join(f'{k}={v}' for k,v in sorted(old['workerHeapEnvironment'].items())) or
              ', '.join(old['workerHeapCommand']) or 'not explicit',old['descriptor'])) + ' |')
    lines += ['', '# Supporting OLD Quadlets without an exact descriptor service name', '',
        '| Quadlet name | Cap | Source |', '|---|---|---|']
    for name,record in sorted(data['oldQuadletsWithoutDescriptor'].items()):
        lines.append(f"| {name} | {record['hardCap'] or 'unspecified'} | {record['source']} |")
    lines += ['', '## Admission implications', '',
        '- A container `--memory` is an upper ceiling, not reserved resident memory. Do not infer hardware shortage from a sum of maxima.',
        '- OLD missing service limits are not evidence that lowering an explicitly bounded fresh process is safe.',
        '- The r9 `alice`/`bob` notebook agents are currently selected steady, whereas OLD test runtimes are on-demand; redesign and native readback are required before reclassifying them.',
        '- Native broker/CI guard, retained generations, backup scratch, workers, image staging and disk must be measured/qualified separately while retaining 16384 MiB available memory and 10240 MiB disk.',
        '- Provider consolidation and serial one-shots avoid multiplying OLD provider caps. No cap is lowered solely to force admission.', '']
    return '\n'.join(lines)

def main():
    data = audit()
    if len(sys.argv) == 2 and sys.argv[1] == '--markdown': print(markdown(data))
    elif len(sys.argv) == 1: print(json.dumps(data, indent=2, sort_keys=True))
    else: raise SystemExit('Usage: audit_fresh_full_capacity.py [--markdown]')

if __name__ == '__main__':
    main()
