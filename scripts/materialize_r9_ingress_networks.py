#!/usr/bin/env python3
"""Fresh r9-only frontend revisions. Never mutate active/historical fragments.

An ingress peer receives only a dedicated app HTTP frontend, not shared
metrics, ntfy credential or OpenSearch data networks.
"""
from pathlib import Path
import hashlib,json,shutil,yaml
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes())
assert sha(M)==i['manifestSha256'] and m['revision']==9
mapping={'prometheus':'prometheus-web','alertmanager':'alerts-web','grafana':'grafana-web',
 'ntfy':'ntfy-web','opensearch':'search-web'}
for product,network in mapping.items():
 source=R/product/'r1';dest=R/product/'r2'
 if dest.exists():raise RuntimeError('Existing new revision: '+str(dest))
 shutil.copytree(source,dest)
 d=yaml.safe_load((dest/'fragment.yaml').read_bytes())
 assert d['product']==product and d['revision']==1 and network not in d['networks']
 d['revision']=2;d['networks'].append(network);d['webNetworks']=[network]
 front=[p for p in d['processes'] if not p.get('oneShot') and p['id'] in
        ({'prometheus','alertmanager','grafana','ntfy','opensearch'} & {product})]
 assert len(front)==1,(product,[p['id'] for p in d['processes']])
 front[0]['networks'].append(network)
 (dest/'fragment.yaml').write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
 ref,=[x for x in m['fragments'] if x['id']==d['id'] and x['revision']==1]
 ref['revision']=2
 entry,=[x for x in i['entries'] if x['id']==d['id'] and x['revision']==1]
 entry['revision']=2;entry['resource']=product+'/r2/fragment.yaml';entry['sha256']=sha(dest/'fragment.yaml')
 for r in entry.get('templates',{}):
  assert sha(dest/r)==entry['templates'][r]
 for mod in m['integratedReference']['modules']:
  if mod['id']==product:
   for route in mod.get('privateRoutes',[]):
    if route.get('process')==product:route['network']=network
M.write_text(json.dumps(m,indent=2,ensure_ascii=False)+'\n')
i['manifestSha256']=sha(M)
I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
