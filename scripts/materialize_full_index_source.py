#!/usr/bin/env python3
"""Produce an immutable *unactivated* r8 source index from its exact packaged bytes.

This never rewrites v3/index.yaml or any archived manifest, calls native Podman,
consumes site credentials, or claims full-stack graph admission. Do not select
this index until all support/native owners and acquired artifacts are closed.
"""
import hashlib
from pathlib import Path
import yaml

base = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments/v3'
manifest = base / 'canonical/r8/manifest.yaml'
r7_index = base / 'canonical/r7/index.yaml'
r7_manifest = base / 'canonical/r7/manifest.yaml'
active_index = base / 'index.yaml'
assert active_index.read_bytes() == r7_index.read_bytes()
old = yaml.safe_load(r7_index.read_bytes())
full = yaml.safe_load(manifest.read_bytes())
assert full['scope'] == 'full-private' and full['revision'] == 8
assert len(full['fragments']) == 41 and len({(r['id'], r['revision']) for r in full['fragments']}) == 41
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(r7_manifest) == old['manifestSha256']
assert sha(base / 'provenance.json') == old['provenanceSha256']
entries = []
for ref in full['fragments'][2:]:
    matches = []
    for path in base.glob('*/r*/fragment.yaml'):
        doc = yaml.safe_load(path.read_bytes())
        if (doc['id'], doc['revision']) == (ref['id'], ref['revision']):
            matches.append((doc, path))
    assert len(matches) == 1, ref
    doc, path = matches[0]
    assert path.parent.name == 'r' + str(ref['revision'])
    entry = {'id': ref['id'], 'revision': ref['revision'],
             'resource': str(path.relative_to(base)), 'sha256': sha(path)}
    templates = doc.get('templates', [])
    if templates:
        assert len({item['resource'] for item in templates}) == len(templates)
        entry['templates'] = {item['resource']: sha(path.parent / item['resource']) for item in templates}
    entries.append(entry)
assert len(entries) == 39
index = {'schemaVersion': 2, 'provenanceSha256': old['provenanceSha256'],
         'manifestResource': 'canonical/r8/manifest.yaml', 'manifestSha256': sha(manifest),
         'recentManifestSha256': sha(r7_manifest)}
for field in ('previousManifestSha256', 'intermediateManifestSha256', 'priorManifestSha256',
              'latestPriorManifestSha256', 'penultimateManifestSha256', 'lastManifestSha256'):
    index[field] = old[field]
index['entries'] = entries
output = (yaml.safe_dump(index, sort_keys=False, width=1024, allow_unicode=False)).encode()
target = base / 'canonical/r8/index.yaml'
if target.exists():
    assert target.read_bytes() == output, 'Existing r8 source differs; review rather than overwrite'
else:
    target.write_bytes(output)
print(f'Unactivated r8 source index: {len(entries)} packaged V3 fragments, sha256={sha(target)}')
