#!/usr/bin/env python3
"""One-time OLD-reference -> fresh module-owned ingress declarations for unactivated r9.

The resulting hash-bound MANIFEST, not this materializer or OLD's Caddyfile,
is the sole ingress graph authority. Refuse changed OLD provenance or unknown
selected processes/networks; never modify r7 or r8.
"""
import hashlib,json,re,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
OLD=Path('/tmp/p0-old-full-36b6b7/modules/caddy/legacy/stack.config/caddy/Caddyfile')
M=ROOT/'canonical/r9/manifest.yaml';I=ROOT/'canonical/r9/index.yaml'
sha=lambda b:hashlib.sha256(b).hexdigest()
manifest=json.loads(M.read_bytes());index=yaml.safe_load(I.read_bytes())
assert sha(OLD.read_bytes())==manifest['integratedReference']['routeSourceSha256']
assert sha(M.read_bytes())==index['manifestSha256']
# OLD label -> selected fresh owner/process/port/policy/special. These values are
# copied once into each module's own sealed graph entry; compilation never reads
# this table or the historical deployment. Explicit protocol changes remain
# separately reviewed at source and in native admission.
D={
 'keycloak':('keycloak','keycloak',8443,'OPEN','identity'),
 'keycloak-auth':('keycloak-auth-gateway','auth-gateway',4180,'CONTROL','auth-gateway'),
 'onboarding':('onboarding',None,None,'FOLDED','onboarding'),
 'kopia':('kopia',None,None,'FOLDED','kopia'),
 'prometheus':('prometheus','prometheus',9090,'GROUP',''),
 'alerts':('alertmanager','alertmanager',9093,'GROUP',''),
 'grafana':('grafana','grafana',3000,'GROUP','grafana'),
 'planka':('planka','planka',1337,'APP',''),
 'huly':('huly','huly',8443,'GROUP','huly'),
 'bookstack':('bookstack','bookstack',8080,'APP',''),
 'sogo':('sogo','groupware',8443,'APP','sogo'),
 'jellyfin':('jellyfin','jellyfin',8096,'APP','jellyfin'),
 'firefly':('firefly-iii','firefly',8080,'GROUP','finance'),
 'firefly-importer':('firefly-iii',None,None,'FOLDED','finance-importer'),
 'donetick':('donetick','donetick',2021,'GROUP','donetick'),
 'donetick-native':('donetick','donetick',2021,'NATIVE','donetick-native'),
 'erpnext':('erpnext','erp',8443,'GROUP','erpnext'),
 'qbittorrent':('qbittorrent','qbittorrent',8080,'GROUP','qbittorrent'),
 'qbittorrent-native':('qbittorrent','qbittorrent',8080,'NATIVE','qbittorrent-native'),
 'api.bookstack':('bookstack','bookstack',8080,'NATIVE','bookstack-api'),
 'seafile':('seafile','seafile-files',8443,'GROUP','seafile'),
 'files':('seafile','seafile-files',8443,'GROUP','seafile'),
 'files-native':('seafile','seafile-files',8443,'NATIVE','seafile-native'),
 'onlyoffice':('onlyoffice','onlyoffice-front',8443,'APP','onlyoffice'),
 'matrix':('synapse','synapse',8008,'NATIVE','matrix'),
 'matrix-auth':('matrix-authentication-service','mas',8080,'APP',''),
 'api.matrix':('synapse','synapse',8008,'NATIVE','matrix-api'),
 'element':('element','element-web',8080,'APP',''),
 'chat':('element','element-web',8080,'APP',''),
 'matrix-rtc':('livekit','rtc-web',8080,'NATIVE','matrix-rtc'),
 'mastodon':('mastodon','social',8443,'APP','social'),
 'social':('mastodon','social',8443,'APP','social'),
 'jupyterhub':('jupyterhub','hub',8443,'GROUP','jupyterhub'),
 'homeassistant':('homeassistant','homeassistant',8123,'GROUP','homeassistant'),
 'home':('homeassistant','homeassistant',8123,'GROUP','homeassistant'),
 'home-native':('homeassistant','homeassistant',8123,'NATIVE','home-native'),
 'ntfy':('ntfy','ntfy',8080,'GROUP','ntfy'),
 'ntfy-native':('ntfy','ntfy',8080,'NATIVE','ntfy-native'),
 'forgejo':('forgejo','forgejo',3000,'APP','forgejo'),
 'websearch':('searxng','searxng-web',8080,'GROUP','websearch'),
}
oldLabels={r['label'] for r in manifest['integratedReference']['routes']}
assert set(D)==oldLabels and len(D)==40
P={};owners={}
for e in index['entries']:
 d=yaml.safe_load((ROOT/e['resource']).read_bytes())
 for p in d['processes']:
  if not p.get('oneShot'):
   assert p['id'] not in P
   P[p['id']]=p;owners[p['id']]=d['product']
# V2 Forgejo is part of the same selected runtime graph, not a copied OLD daemon.
forgejo=yaml.safe_load((ROOT.parent/'v2/forgejo/r5/fragment.yaml').read_bytes())
for p in forgejo['processes']:
 if p['id']=='forgejo':P[p['id']]=p;owners[p['id']]='forgejo'
# Explicit published canonical hosts: old names remain labels for audited aliases.
HOST={'keycloak':'auth','keycloak-auth':'keycloak-auth','huly':'work',
 'sogo':'groupware','erpnext':'erp','seafile':'files','onlyoffice':'office',
 'jupyterhub':'notebooks','mastodon':'social','homeassistant':'home'}
TLS={'keycloak':('keycloak','identity-ca.pem'), 'huly':('huly','huly-ca.pem'),
 'sogo':('groupware','sogo-ca.pem'),'erpnext':('erp','erp-ca.pem'),
 'seafile':('seafile-files','seafile-ca.pem'),
 'onlyoffice':('onlyoffice-front','onlyoffice-ca.pem'),
 'mastodon':('social','mastodon-ca.pem'), 'jupyterhub':('hub','hub-ca.pem')}
mods={m['id']:m for m in manifest['integratedReference']['modules']}
for m in mods.values():m.pop('privateRoutes',None)
for label,(owner,proc,port,policy,special) in D.items():
 assert owner in mods and (mods[owner]['role']=='selected' or owner in ('onboarding','keycloak-auth-gateway'))
 host=HOST.get(label,label)+'.datamancy.net'
 route={'label':label,'host':host,'policy':policy}
 if proc:
  assert proc in P and owners[proc]==owner,(label,proc,owners.get(proc))
  nets=P[proc]['networks']
  net=next((n for n in nets if n.endswith('-web') and n not in ('identity-web',)),None)
  if not net: net='identity-web' if 'identity-web' in nets else ('ingress-control' if 'ingress-control' in nets else nets[-1])
  assert net in nets,(label,proc,nets)
  route.update(process=proc,network=net,port=port)
 if special:route['special']=special
 if port==8443:
  assert owner in TLS,(label,owner)
  route.update(tlsName=TLS[owner][0],caInput=TLS[owner][1])
 # Alias has an exact designated canonical host, not a duplicate Caddy site.
 if label in ('files','chat','social','home','mastodon','homeassistant','seafile'):
  route['aliasOf']={'files':'seafile','chat':'element','social':'mastodon',
    'home':'homeassistant','mastodon':'social','homeassistant':'home',
    'seafile':'files'}[label] if label not in ('mastodon','homeassistant','seafile') else None
  if route['aliasOf'] is None:route.pop('aliasOf')
 mods[owner].setdefault('privateRoutes',[]).append(route)
# OLD reference contains only 40 hosts. These are selected v3 executable
# support hosts; add them to their owning module, not a second route table.
for owner,host,proc,port,policy,special in [
 ('portal','portal.datamancy.net','portal',3000,'GROUP','portal'),
 ('portal','datamancy.net','portal',3000,'GROUP','portal-apex'),
 ('portal','homepage.datamancy.net',None,None,'REDIRECT','portal-redirect'),
 ('caddy','www.datamancy.net',None,None,'REDIRECT','apex-redirect'),
 ('mailserver','mail.datamancy.net',None,None,'CONTROL','mail-tls'),
 ('caddy','control.datamancy.net',None,None,'CONTROL','controller'),
 ('caddy','api.datamancy.net',None,None,'CONTROL','agent-api'),
 ('opensearch','search.datamancy.net','opensearch',9200,'GROUP','search')]:
 route={'label':host,'host':host,'policy':policy,'special':special}
 if proc:
  if proc not in P and proc=='portal':
   # Portal is an r9 support fragment and must be selected in the same index.
   raise RuntimeError('Portal must be in selected graph')
  assert proc in P and owners[proc]==owner,(proc,owner)
  nets=P[proc]['networks'];net=next((n for n in nets if n.endswith('-web')),None)
  if not net:net=nets[-1]
  assert net,(host,proc,nets)
  route.update(process=proc,network=net,port=port)
 mods[owner].setdefault('privateRoutes',[]).append(route)
# Route IDs, hosts and effective selected frontends must be unique. Any
# unresolved ROOTLESS/HOST control is represented as a non-proxy policy.
routes=[r for m in mods.values() for r in m.get('privateRoutes',[])]
assert len({r['label'] for r in routes})==len(routes)
# Alias labels can have the same host, but not divergent upstream or policy.
for host in {r['host'] for r in routes}:
 same=[r for r in routes if r['host']==host]
 assert len({(r.get('process'),r.get('port'),r['policy'],r.get('special')) for r in same})==1,(host,same)
M.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
# The index is a source hash lock, not the live r7 selection.
body=I.read_text();body=re.sub(r'(?m)^manifestSha256: [a-f0-9]{64}$','manifestSha256: '+sha(M.read_bytes()),body)
I.write_text(body)
print('r9 manifest',sha(M.read_bytes()),'index',sha(I.read_bytes()),'declarations',len(routes))
