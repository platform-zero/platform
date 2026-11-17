#!/usr/bin/env python3
"""Refine unactivated monitor-web into single-product ingress-only networks."""
import hashlib,json,yaml
from pathlib import Path
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes())
assert i['manifestSha256']==sha(M)
for product,network in {'prometheus':'prometheus-web','alertmanager':'alerts-web','grafana':'grafana-web'}.items():
 f=R/product/'r2/fragment.yaml';e,=[x for x in i['entries'] if x['resource']==f'{product}/r2/fragment.yaml']
 assert e['sha256']==sha(f)
 d=json.loads(f.read_bytes());assert d['networks'][-1]=='monitor-web' and d['webNetworks']==['monitor-web']
 d['networks'][-1]=network;d['webNetworks']=[network]
 p,=[x for x in d['processes'] if x['id']==product];assert p['networks'][-1]=='monitor-web';p['networks'][-1]=network
 f.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n');e['sha256']=sha(f)
 mod,=[x for x in m['integratedReference']['modules'] if x['id']==product]
 for route in mod['privateRoutes']:
  assert route['network']=='monitor-web';route['network']=network
M.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
