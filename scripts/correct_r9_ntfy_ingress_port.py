#!/usr/bin/env python3
"""Correct manifest ntfy HTTP port from OLD 80 to selected r9 --listen-http=8080."""
import json,yaml,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
I=R/'canonical/r9/index.yaml';M=R/'canonical/r9/manifest.yaml'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes());assert i['manifestSha256']==sha(M)
fragment=json.loads((R/'ntfy/r2/fragment.yaml').read_bytes());p,=[p for p in fragment['processes'] if p['id']=='ntfy']
assert '--listen-http=:8080' in p['command'] and '--auth-default-access=deny-all' in p['command']
mod,=[x for x in m['integratedReference']['modules'] if x['id']=='ntfy'];routes=mod['privateRoutes'];assert len(routes)==2
for route in routes:
 assert route['port']==80;route['port']=8080
M.write_text(json.dumps(m,indent=2)+'\n');i['manifestSha256']=sha(M);I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'index',sha(I))
