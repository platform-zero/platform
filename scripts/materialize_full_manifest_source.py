#!/usr/bin/env python3
"""Offline, unindexed r8 source construction from pinned r7 OLD reference.

Never touches the active index, reads private inputs, executes an OLD script,
loads an image, or interprets an historical support descriptor as a product.
The output is a candidate for subsequent whole-graph closure, not admission.
"""
import json
from pathlib import Path
import yaml

BASE = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments'
old = yaml.safe_load((BASE / 'v3/canonical/r7/manifest.yaml').read_bytes())
assert old['revision'] == 7 and old['scope'] == 'development-core'
assert [x['id'] for x in old['fragments'][:2]] == ['postgres-timescale', 'forgejo-postgres']
selected = {m['id'] for m in old['integratedReference']['modules'] if m['role'] == 'selected'}
assert len(selected) == 39
controls = {'kopia': 'kopia-generation-store', 'mastodon-rss-publisher': 'rss-scheduled-controller'}
external = {'keykeeper', 'openbao', 'keycloak-auth-gateway', 'portal'}
latest = {}
for file in (BASE / 'v3').glob('*/r*/fragment.yaml'):
    document = yaml.safe_load(file.read_bytes())
    product = document['product']
    if product not in (selected - controls.keys() - {'postgres', 'forgejo'}) | external:
        continue
    value = latest.get(product)
    if value is None or document['revision'] > value[0]['revision']:
        latest[product] = (document, file)
assert set(latest) == (selected - controls.keys() - {'postgres', 'forgejo'}) | external
refs = [{'id': 'postgres-timescale', 'revision': 1},
        {'id': 'forgejo-postgres', 'revision': 5}]
old_index = yaml.safe_load((BASE / 'v3/canonical/r7/index.yaml').read_bytes())
old_entries = {(entry['id'], entry['revision']): entry['resource'] for entry in old_index['entries']}
for original in old['fragments'][2:]:
    resource = old_entries[(original['id'], original['revision'])]
    product = yaml.safe_load((BASE / 'v3' / resource).read_bytes())['product']
    doc, _ = latest.pop(product)
    refs.append({'id': doc['id'], 'revision': doc['revision']})
for product in sorted(latest):
    doc, _ = latest[product]
    refs.append({'id': doc['id'], 'revision': doc['revision']})
all_fragments = {}
for ref in refs[2:]:
    matches = [yaml.safe_load(file.read_bytes()) for file in (BASE / 'v3').glob('*/r*/fragment.yaml')
               if file.parent.name == 'r' + str(ref['revision'])]
    fragment = next(f for f in matches if f['id'] == ref['id'])
    assert fragment['product'] not in all_fragments
    all_fragments[fragment['product']] = fragment
for module in old['integratedReference']['modules']:
    if module['role'] != 'selected':
        continue
    product = module['id']
    if product in controls:
        assert not module.get('nativeDaemons') and not module.get('nativeControl')
        module['nativeControl'] = controls[product]
    elif product not in {'postgres', 'forgejo'}:
        daemons = [process['id'] for process in all_fragments[product]['processes']
                   if not process.get('oneShot', False)]
        assert daemons and (not module.get('nativeDaemons') or module['nativeDaemons'] == daemons)
        module['nativeDaemons'] = daemons
old['revision'] = 8
old['scope'] = 'full-private'
old['fragments'] = refs
old['extraBindings'] = [
    {'id': 'keykeeper', 'nativeDaemons': ['keeper']},
    {'id': 'openbao', 'nativeDaemons': ['bao']},
    *({'id': id_, 'nativeControl': 'managed-lane-targets'} for id_ in ('worklane', 'tuios', 'pi')),
    {'id': 'forgejo-runner', 'nativeControl': 'forgejo-ephemeral-rootless-runner',
     'historicalDisposition': 'ROOTLESS_CI_CONTROL'},
    {'id': 'keycloak-auth-gateway', 'nativeDaemons': ['auth-gateway'],
     'historicalDisposition': 'EXECUTABLE_SUPPORT'},
    {'id': 'portal', 'nativeDaemons': ['portal'],
     'historicalDisposition': 'EXECUTABLE_SUPPORT'},
]
assert len(refs) <= 64 and len({(r['id'], r['revision']) for r in refs}) == len(refs)
assert {m['id'] for m in old['integratedReference']['modules'] if m.get('nativeDaemons') or m.get('nativeControl')} == selected
assert not any(x['id'] == 'legal-research-mcp' for x in old['extraBindings'])
target = BASE / 'v3/canonical/r8/manifest.yaml'
content = (json.dumps(old, indent=2, ensure_ascii=True) + '\n').encode()
target.parent.mkdir(parents=True, exist_ok=True)
if target.exists():
    assert target.read_bytes() == content, 'Existing r8 draft differs: review rather than overwriting'
else:
    target.write_bytes(content)
print(f'Unindexed source-only r8: {len(refs)} refs, {len(selected)} selected, {len(content)} bytes')
