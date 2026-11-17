#!/usr/bin/env python3
"""Bind r9 Caddy auth host to the same fresh Keycloak PKI consumed by SSO."""
import pathlib,json,hashlib,yaml
r=pathlib.Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
s=r/'caddy/r2/fragment.yaml';dest=r/'caddy/r3/fragment.yaml';m=r/'canonical/r9/manifest.yaml';i=r/'canonical/r9/index.yaml'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(s.read_bytes())=='f147cddcc748481cd89d3f567552cd7ac61966da42cb339413565d426b3db425' and not dest.exists()
x=json.loads(s.read_bytes());x['revision']=3;x['providers'].append('keycloak')
x['networks'].append('identity-web');x['providerNetworks']={'keycloak':['identity-web']}
x['providerProcesses']={'keycloak':['keycloak']}
for name in ('identity-web.pem','identity-web-key.pem'):
 x['inputs'].append({'name':name,'owner':'keycloak','purpose':'RUNTIME','consumers':['caddy']})
 x['processes'][0]['files'].append({'file':name,'target':'/run/secrets/'+name})
x['processes'][0]['networks'].append('identity-web')
x['processes'][0]['networkAliases']=[{'network':'identity-web','host':'auth.datamancy.net'}]
x['install']['dependencies']['caddy']=['keycloak']
x['restore']['dependencies']['caddy']=['keycloak']
dest.parent.mkdir(exist_ok=True);dest.write_text(json.dumps(x,indent=2)+'\n')
manifest=json.loads(m.read_bytes());entry=next(v for v in manifest['fragments'] if v['id']=='private-caddy');assert entry['revision']==2;entry['revision']=3
m.write_text(json.dumps(manifest,indent=2)+'\n')
index=yaml.safe_load(i.read_bytes());part=next(e for e in index['entries'] if e['id']=='private-caddy');assert part['revision']==2
part.update(revision=3,resource='caddy/r3/fragment.yaml',sha256=sha(dest.read_bytes()))
index['manifestSha256']=sha(m.read_bytes());i.write_text(yaml.safe_dump(index,sort_keys=False))
print(part['sha256'])
