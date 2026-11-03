#!/usr/bin/env python3
"""Native account and scoped-token checks. No RSS posts, checkpoint changes or review bypass."""
import argparse
import hashlib
import html
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import ssl
import uuid
from probe_receipt import private_receipt


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='mastodon-r4');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    module_spec=importlib.util.spec_from_file_location('social',Path(__file__).with_name('test-private-mastodon.py'))
    m=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(m)
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-social-rss-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'passed':False,'fullStackAcceptance':False,'publicationEnabled':False}
    token_dir=directory/'tokens';token_dir.mkdir(mode=0o700)
    spec_path=m.BASE/(name+'.json');spec=json.loads(spec_path.read_text())
    packs=m.ROOT/'platform/src/main/resources/rss-packs/v1'
    def hashes(path):return {str(p.relative_to(path)):hashlib.sha256(p.read_bytes()).hexdigest() for p in path.rglob('*') if p.is_file()}
    state=Path('/mnt/media/p0-v3/rss-staging-state');before_state=hashes(state);before_packs=hashes(packs)
    with private_receipt(receipt,lambda r:m.write(directory/'receipt.json',json.dumps(r,indent=2))):
        r=subprocess.run([str(m.CLI),'runtime','status-private',str(spec_path)],capture_output=True,env=m.ENV,timeout=180)
        assert r.returncode==0
        assert all(p['state']=='running' for p in json.loads(r.stdout.splitlines()[0]) if not next(q.get('oneShot',False) for q in spec['processes'] if q['id']==p['id']))
        process='p0v3-live-'+name+'-social';d=json.loads(subprocess.check_output(m.P+['inspect',process]))[0]
        assert d['Config']['Labels']['io.p0v3.private-deployment']==name and not d['HostConfig']['PortBindings']
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        address=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress']
        network=json.loads(subprocess.check_output(m.P+['network','inspect','p0v3-live-'+name+'-net']))[0];assert network['internal']
        image=next(p['image'] for p in spec['processes'] if p['id']=='mastodon')
        r=subprocess.run(m.P+['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges',
            '--security-opt=apparmor=p0v3-private-v1','--user=991:991','--memory=128m','--pids-limit=64','--image-volume=ignore',
            '--volume','p0v3-live-'+name+'-volume-bootstrap:/bootstrap:ro','--entrypoint=/usr/local/bin/ruby',image,
            '-e','print File.read(ARGV[0])','/bootstrap/rss-tokens.json'],capture_output=True,text=True,timeout=60)
        assert r.returncode==0;tokens=json.loads(r.stdout);assert tokens['publicationEnabled'] is False and tokens['schemaVersion']==1
        expected={f['account']:{**f,'pack':p.stem} for p in packs.glob('*.json') if p.name!='manifest.json' for f in json.loads(p.read_text())['feeds']}
        assert len(tokens['accounts'])==47 and set(expected)=={f['account'] for f in tokens['accounts']}
        assert len({f['accountId'] for f in tokens['accounts']})==47
        ca=ssl.create_default_context(cafile=str(m.BASE/name/'ca.pem'))
        def api(path,token,method='GET',data=None):
            payload=json.dumps(data).encode() if data is not None else b''
            with socket.create_connection((address,8443),timeout=20) as raw,ca.wrap_socket(raw,server_hostname='social') as tls:
                assert tls.getpeercert(binary_form=True)==ssl.PEM_cert_to_DER_cert((m.BASE/name/'web.pem').read_text())
                tls.sendall((method+' '+path+' HTTP/1.1\r\nHost: social:8443\r\nAuthorization: Bearer '+token+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\nConnection: close\r\n\r\n').encode()+payload)
                response=http.client.HTTPResponse(tls);response.begin();return response.status,json.loads(response.read(1048576))
        for item in tokens['accounts']:
            account=item['account'];token=item['token'];assert re.fullmatch(r'[A-Za-z0-9_.-]{20,256}',token)
            assert item['feedId']==expected[account]['id'] and item['pack']==expected[account]['pack'];m.write(token_dir/(account+'.token'),token+'\n')
            status,body=api('/api/v1/accounts/verify_credentials',token)
            assert status==200 and body['acct']==account and body['id']==item['accountId'] and body['bot'] and body['locked'] and body['statuses_count']==0
            assert body['display_name']==expected[account]['display_name'] and expected[account]['url'] in html.unescape(body['note'])
        assert len({f['pack'] for f in tokens['accounts']})==9
        first=tokens['accounts'][0]['token']
        status,instance=api('/api/v2/instance',first);assert status==200 and instance['registrations']['enabled'] is False
        assert instance['configuration']['statuses']['max_characters']>=500
        assert api('/api/v1/admin/accounts',first)[0]==403
        assert api('/api/v1/accounts/update_credentials',first,'PATCH',{'display_name':'Must not change'})[0]==403
        assert api('/api/v1/statuses',first,'POST',{})[0]==422  # Native authorization succeeds, empty content validation fails; no status created.
        status,unchanged=api('/api/v1/accounts/verify_credentials',first)
        assert status==200 and unchanged['statuses_count']==0 and unchanged['display_name']==expected[tokens['accounts'][0]['account']]['display_name']
        logs=subprocess.run(m.P+['logs','p0v3-live-'+name+'-mastodon-rss-accounts'],capture_output=True,text=True,check=True)
        assert 'New password:' not in logs.stdout+logs.stderr
        assert all(item['token'] not in logs.stdout+logs.stderr for item in tokens['accounts'])
        m.write(directory/'hosts',address+' social\n')
        jars=sorted((m.ROOT/'platform/build/install/p0-v3-platform/lib').glob('*.jar'));assert jars
        r=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djdk.net.hosts.file='+str(directory/'hosts'),'--class-path',':'.join(map(str,jars)),
            str(m.ROOT/'acceptance/scripts/RssAccountProbe.java'),str(token_dir),str(m.BASE/name/'ca.pem')],capture_output=True,text=True,timeout=240)
        # JVM diagnostics are retained privately, never token-bearing request/response dumps.
        safe=r.stderr
        for item in tokens['accounts']:safe=safe.replace(item['token'],'[redacted]')
        m.write(directory/'transport.log',safe);assert r.returncode==0,'Native publisher transport preflight failed; private diagnostics retained'
        receipt.update(json.loads(r.stdout))
        assert hashes(state)==before_state and hashes(packs)==before_packs
        receipt.update(passed=True,accounts=47,packs=9,zeroFeedStatuses=True,adminAccessDenied=True,profileMutationDenied=True,
            scopeAllowsStatusValidation=True,nativeRegistrationClosed=True,packBytesUnchanged=True,existingCheckpointsUnchanged=True,initializerLogsExcludeCredentials=True,
            manifestSha256=hashlib.sha256(spec_path.read_bytes()).hexdigest())
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
