#!/usr/bin/env python3
"""Keep OpenSearch's HTTP frontend separate from SearxNG's search-web."""
import json,yaml,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3';I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes());assert i['manifestSha256']==sha(M)
f=R/'opensearch/r2/fragment.yaml';e,=[x for x in i['entries'] if x['resource']=='opensearch/r2/fragment.yaml'];assert e['sha256']==sha(f)
d=json.loads(f.read_bytes());assert d['networks'][-1]=='search-web' and d['webNetworks']==['search-web'];d['networks'][-1]='opensearch-web';d['webNetworks']=['opensearch-web']
p,=[x for x in d['processes'] if x['id']=='opensearch'];assert p['networks'][-1]=='search-web';p['networks'][-1]='opensearch-web'
f.write_text(json.dumps(d,indent=2)+'\n');e['sha256']=sha(f)
mod,=[x for x in m['integratedReference']['modules'] if x['id']=='opensearch'];r,=mod['privateRoutes'];assert r['network']=='search-web';r['network']='opensearch-web'
M.write_text(json.dumps(m,indent=2)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9',sha(M),sha(I))
