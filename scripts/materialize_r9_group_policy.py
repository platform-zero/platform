#!/usr/bin/env python3
"""Attach pinned OLD explicit group policies to r9 module-owned route declarations."""
import hashlib,json,re,yaml
from pathlib import Path
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3/canonical/r9'
M=R/'manifest.yaml';I=R/'index.yaml';OLD=Path('/tmp/p0-old-full-36b6b7/modules/caddy/legacy/stack.config/caddy/Caddyfile')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads(M.read_bytes());i=yaml.safe_load(I.read_bytes());assert i['manifestSha256']==sha(M) and sha(OLD)==m['integratedReference']['routeSourceSha256']
text=OLD.read_text()
for mod in m['integratedReference']['modules']:
 for route in mod.get('privateRoutes',[]):
  if route['policy']!='GROUP':continue
  label=route['label']
  pattern=r'import keycloak_group_allow '+re.escape(label)+r' ([a-z|]+)'
  match=re.findall(pattern,text)
  if label in ('home','files','search.datamancy.net','portal.datamancy.net','datamancy.net'):
   original={'home':'homeassistant','files':'seafile','search.datamancy.net':'search',
     'portal.datamancy.net':'portal','datamancy.net':'portal'}[label]
   match=re.findall(r'import keycloak_group_allow '+original+r' ([a-z|]+)',text)
  if label=='firefly':match=['admins|operators'] # Browser protection replaces absent selected OLD SSO support; no bearer bypass.
  if label=='firefly-importer':raise RuntimeError('Importer must never inherit grouped browser proxy')
  if label=='ntfy':match=['admins|operators']
  if label=='qbittorrent' and not match:
   route['policy']='AUTH';continue
  assert len(set(match))==1,(label,match)
  route['groups']=match[0]
M.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
