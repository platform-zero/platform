#!/usr/bin/env python3
"""Fresh r9-only OpenSearch least-privileged mTLS browser role and Caddy mount."""
from pathlib import Path
import hashlib,json,yaml,shutil
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3';I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes());assert i['manifestSha256']==sha(M)
ops=R/'opensearch/r2/fragment.yaml';e,=[x for x in i['entries'] if x['resource']=='opensearch/r2/fragment.yaml'];assert sha(ops)==e['sha256']
d=json.loads(ops.read_bytes());assert d['product']=='opensearch' and d['revision']==2 and 'exportedInputs' not in d
for name,target in [('opensearch-reader.pem','/config/reader.pem'),('opensearch-reader-key.pem','/config/reader-key.pem')]:
 d['inputs'].append({'name':name,'owner':'opensearch','purpose':'RUNTIME','consumers':['opensearch']})
 front,=[p for p in d['processes'] if p['id']=='opensearch'];front['files'].append({'file':name,'target':target})
d['exportedInputs']=['opensearch-ca.pem','opensearch-reader.pem','opensearch-reader-key.pem']
ops.write_text(json.dumps(d,indent=2)+'\n');e['sha256']=sha(ops)
caddy=R/'caddy/r2';assert not caddy.exists();shutil.copytree(R/'caddy/r1',caddy)
cad=caddy/'fragment.yaml';c=yaml.safe_load(cad.read_bytes());assert c['revision']==1 and c['product']=='caddy'
c['revision']=2;c['providers']=['opensearch']
for name,target in [('opensearch-reader.pem','/run/secrets/opensearch-reader.pem'),
 ('opensearch-reader-key.pem','/run/secrets/opensearch-reader-key.pem')]:
 c['inputs'].append({'name':name,'owner':'opensearch','purpose':'RUNTIME','consumers':['caddy']})
 c['processes'][0]['files'].append({'file':name,'target':target})
cad.write_text(json.dumps(c,indent=2)+'\n')
e,=[x for x in i['entries'] if x['id']=='private-caddy' and x['revision']==1]
e.update(revision=2,resource='caddy/r2/fragment.yaml',sha256=sha(cad))
ref,=[x for x in m['fragments'] if x['id']=='private-caddy' and x['revision']==1];ref['revision']=2
mod,=[x for x in m['integratedReference']['modules'] if x['id']=='opensearch'];r,=mod['privateRoutes']
assert r['port']==9200 and r['policy']=='GROUP' and r['special']=='search'
r.update(tlsName='opensearch',caInput='opensearch-ca.pem')
M.write_text(json.dumps(m,indent=2)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
