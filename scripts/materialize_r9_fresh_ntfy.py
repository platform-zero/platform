#!/usr/bin/env python3
"""Add v2.15 declarative fresh users/tokens to r9 only; preserve r2 historical."""
import hashlib,json,yaml
from pathlib import Path
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3';I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes());assert i['manifestSha256']==sha(M)
src=R/'ntfy/r2/fragment.yaml';e,=[x for x in i['entries'] if x['resource']=='ntfy/r2/fragment.yaml'];assert e['sha256']==sha(src)
d=json.loads(src.read_bytes());assert d['revision']==2 and d['product']=='ntfy' and d['inputs']==[]
d['revision']=3;d['inputs']=[{'name':'ntfy-config.yml','owner':'ntfy','purpose':'RUNTIME','consumers':['ntfy']}]
p,=[x for x in d['processes'] if x['id']=='ntfy']
assert '--auth-default-access=deny-all' in p['command'] and '--listen-http=:8080' in p['command']
p['command']=['serve','--config=/run/secrets/ntfy.yml']
p['files']=[{'file':'ntfy-config.yml','target':'/run/secrets/ntfy.yml'}]
dest=R/'ntfy/r3';dest.mkdir(exist_ok=False)
out=dest/'fragment.yaml';out.write_text(json.dumps(d,indent=2)+'\n')
e.update(revision=3,resource='ntfy/r3/fragment.yaml',sha256=sha(out))
ref,=[r for r in m['fragments'] if r['id']==d['id'] and r['revision']==2];ref['revision']=3
M.write_text(json.dumps(m,indent=2)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
