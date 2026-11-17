#!/usr/bin/env python3
"""Offline r9 fresh-only source from immutable r8; never select the active index."""
import hashlib, json
from pathlib import Path
import yaml
base = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments/v3'
r8 = base / 'canonical/r8/manifest.yaml'
active = base / 'index.yaml'
assert active.read_bytes() == (base / 'canonical/r7/index.yaml').read_bytes()
manifest = json.loads(r8.read_text())
assert manifest['revision'] == 8 and manifest['scope'] == 'full-private'
manifest['revision'] = 9
refs = [r for r in manifest['fragments'] if r['id'] == 'private-mastodon-shared-redis-bridge']
assert len(refs) == 1 and refs[0]['revision'] == 2
refs[0]['revision'] = 4
for selected in ('private-bookstack', 'private-element', 'private-matrix-authentication-service'):
    item, = [r for r in manifest['fragments'] if r['id'] == selected]
    assert item['revision'] == 1
    item['revision'] = 2
sogo = [r for r in manifest['fragments'] if r['id'] == 'private-sogo-mail-groupware']
assert len(sogo) == 1 and sogo[0]['revision'] == 1
sogo[0]['revision'] = 2
replacements = {
 'kopia container and all original state': 'Kopia container and newly initialized stack state',
 'stopped consistent per-app data, isolated restore, original custody, no raw live database copy': 'stopped consistent new-stack data, isolated cold restore and authenticated backup custody; no raw live database copy',
 'OIDC client, original account ownership, Git/issues and SSH isolation': 'OIDC client, fresh private account ownership, Git/issues and SSH isolation',
 'separate original-account tokens and idempotent reconciliation': '47 freshly minted feed-bot tokens, one distinct new observer and idempotent reconciliation',
}
def rewrite(node):
    if isinstance(node, dict): return {k: rewrite(v) for k,v in node.items()}
    if isinstance(node, list): return [rewrite(v) for v in node]
    return replacements.get(node, node) if isinstance(node, str) else node
manifest = rewrite(manifest)
out = base / 'canonical/r9/manifest.yaml'
out.parent.mkdir(parents=True, exist_ok=True)
body = (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode()
if out.exists(): assert out.read_bytes() == body, 'Existing r9 manifest differs'
else:
    with out.open('xb') as fd: fd.write(body)
old = yaml.safe_load((base / 'canonical/r8/index.yaml').read_bytes())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
old['manifestResource'] = 'canonical/r9/manifest.yaml'
old['manifestSha256'] = sha(out)
old['recentManifestSha256'] = sha(r8)
for entry in old['entries']:
    if entry['id'] == 'private-mastodon-shared-redis-bridge':
        assert entry['revision'] == 2
        entry['revision'] = 4
        entry['resource'] = 'mastodon/r4/fragment.yaml'
        entry['sha256'] = sha(base / entry['resource'])
    if entry['id'] in ('private-bookstack', 'private-element', 'private-matrix-authentication-service'):
        assert entry['revision'] == 1
        name = entry['resource'].split('/')[0]
        entry['revision'] = 2
        entry['resource'] = f'{name}/r2/fragment.yaml'
        entry['sha256'] = sha(base / entry['resource'])
    if entry['id'] == 'private-sogo-mail-groupware':
        assert entry['revision'] == 1
        entry['revision'] = 2
        entry['resource'] = 'sogo/r2/fragment.yaml'
        entry['sha256'] = sha(base / entry['resource'])
index = base / 'canonical/r9/index.yaml'
body = yaml.safe_dump(old, sort_keys=False, width=1024).encode()
if index.exists(): assert index.read_bytes() == body, 'Existing r9 index differs'
else:
    with index.open('xb') as fd: fd.write(body)
print('Unactivated fresh r9', sha(out), sha(index))
