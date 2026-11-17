#!/usr/bin/env python3
"""Fork fresh r3 into r4 with a uniquely owned Mastodon uploads volume.

Only the unactivated r9 candidate may select r4. Historical r7/r8/r3
resources and old restore state stay byte-for-byte intact.
"""
import hashlib,json
from pathlib import Path
base=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3/mastodon'
source=base/'r3/fragment.yaml';out=base/'r4/fragment.yaml'
raw=source.read_bytes()
if hashlib.sha256(raw).hexdigest()!='65ae8f195f456760d02c58eb27b2c1cbc00cdcc2fbf9973b50eb15d3027a5289':
 raise RuntimeError('Fresh r3 source changed')
data=json.loads(raw)
assert data['revision']==3 and sum(x['id']=='uploads' for x in data['volumes'])==1
data['revision']=4
for vol in data['volumes']:
 if vol['id']=='uploads':vol['id']='mastodon-uploads'
changed=0
for proc in data['processes']:
 for mount in proc.get('volumes',[]):
  if mount['volume']=='uploads':mount['volume']='mastodon-uploads';changed+=1
assert changed==5
body=(json.dumps(data,separators=(',',':'),ensure_ascii=False)+'\n').encode()
out.parent.mkdir(parents=True,exist_ok=True)
if out.exists():assert out.read_bytes()==body,'Already-materialized source differs'
else:out.write_bytes(body)
print('mastodon fresh r4 source',hashlib.sha256(body).hexdigest())
