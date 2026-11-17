#!/usr/bin/env python3
"""Bind pinned OLD Firefly6.7.9 Passport/session/API policy to r9-only PHP processes."""
import hashlib,json,pathlib,yaml
root=pathlib.Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
old=pathlib.Path('/tmp/p0-old-full-36b6b7/modules/firefly-iii/legacy/stack.config/firefly-iii')
r3=root/'firefly-iii/r3';index=root/'canonical/r9/index.yaml'
sha=lambda b:hashlib.sha256(b).hexdigest()
d=json.loads((r3/'fragment.yaml').read_bytes()); assert d['revision']==3
names={'ApiSubjectBoundary.php':'/opt/firefly/ApiSubjectBoundary.php',
       'AuthServiceProvider.php':'/var/www/html/app/Providers/AuthServiceProvider.php',
       'session.php':'/var/www/html/config/session.php'}
consumers=['firefly-migrate','firefly-php','firefly-users-init','firefly-runtime-config']
for name,target in names.items():
    source=old/name;data=source.read_bytes();assert source.is_file() and not source.is_symlink()
    assert b'webservices' not in data and b'{{' not in data
    (r3/name.lower()).write_bytes(data)
    output='finance-core-'+name.lower()
    d['inputs'].append({'name':output,'owner':'firefly-iii','purpose':'RUNTIME','consumers':consumers})
    d['templates'].append({'output':output,'resource':name.lower(),'format':'LITERAL','parameters':{}})
    for p in d['processes']:
        if p['id'] in consumers: p['files'].append({'file':output,'target':target})
(r3/'fragment.yaml').write_text(json.dumps(d,indent=2)+'\n')
i=yaml.safe_load(index.read_bytes()); e=next(e for e in i['entries'] if e['id']=='private-firefly-iii')
assert e['revision']==3
e['sha256']=sha((r3/'fragment.yaml').read_bytes())
for name in names:e['templates'][name.lower()]=sha((r3/name.lower()).read_bytes())
index.write_text(yaml.safe_dump(i,sort_keys=False))
print('firefly r3 policy',e['sha256'])
