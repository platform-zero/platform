#!/usr/bin/env python3
"""Source-only full r9 Caddy adapt/validate with the extracted exact CLI.

No server starts. Validation substitutes *only* private upstream CA file paths
with a disposable offline CA; the production config retains sealed-generation
CA paths and needs independent native readback before admission.
"""
from pathlib import Path
import hashlib,json,os,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[2]
REV=os.environ.get('P0V3_R9_CADDY_REVISION','')
assert REV in ('','control-v3'), 'Only the original or corrected typed-control validation revision is selectable'
OUT=ROOT/'.coord/rapid-completion'
SRC=OUT/('fresh-r9-full-caddyfile-control-v2' if REV else 'fresh-r9-full-caddyfile-388')
MAN=ROOT/'platform/src/main/resources/fragments/v3/canonical/r9/manifest.yaml'
BIN=OUT/'caddy-config-check-bin-142'
assert BIN.is_file() and hashlib.sha256(BIN.read_bytes()).hexdigest()=='678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9'
manifest=json.loads(MAN.read_bytes())
routes=[r for module in manifest['integratedReference']['modules'] for r in module.get('privateRoutes',[])]
assert len(routes)==48 and {r['label'] for r in routes}>={r['label'] for r in manifest['integratedReference']['routes']}
assert len({r['label'] for r in routes})==len(routes)
selected_tls={
 'identity-web': 'auth.datamancy.net',
 'office-web': 'office.datamancy.net',
 'files-web': 'files.datamancy.net',
 'work-web': 'work.datamancy.net',
 'groupware-web': 'groupware.datamancy.net',
 'finance-ingress-web': 'firefly.datamancy.net',
}
assert SRC.is_file() and SRC.read_text().count('tls internal')==len({r['host'] for r in routes})-len(selected_tls)
assert all(f'https://{host} {{\n    tls /run/secrets/{stem}.pem /run/secrets/{stem}-key.pem' in SRC.read_text()
 for stem,host in selected_tls.items())
adapt=subprocess.run([str(BIN),'adapt','--config',str(SRC),'--adapter','caddyfile'],capture_output=True,check=True)
config=json.loads(adapt.stdout)
http=config['apps']['http']['servers']
hosts=set()
for server in http.values():
 for r in server['routes']:
  for match in r.get('match',[]):hosts.update(match.get('host',[]))
expected={r['host'] for r in routes}
assert hosts==expected,(sorted(expected-hosts),sorted(hosts-expected))
assert config['admin']['listen']=='127.0.0.1:2019'
if REV:
 text=SRC.read_text()
 control=text.split('https://control.datamancy.net {',1)[1].split('\nhttps://',1)[0]
 api=text.split('https://api.datamancy.net {',1)[1].split('\nhttps://',1)[0]
 assert '@typed_control path /ops/status /ops/lane/start /ops/lane/stop /ops/device-tokens /ops/device-tokens/*' in control
 assert 'reverse_proxy unix//run/p0-control/http.sock' in control and 'respond 404' in control
 assert '@device_api path /v1/models /v1/chat/completions' in api and 'request_header -Cookie' in api
 assert 'reverse_proxy unix//run/p0-control/http.sock' in api and '/ops/device-tokens' not in api
# Inspect the ADAPTED handler graph: a Caddyfile line/host count alone cannot
# establish auth ordering, denial, special native routes or header provenance.
all_routes=[r for server in http.values() for r in server['routes']]
def descendants(value):
 if isinstance(value,dict):
  yield value
  for item in value.values():yield from descendants(item)
 elif isinstance(value,list):
  for item in value:yield from descendants(item)

def host_route(name):
 matched=[route for route in all_routes if any(name in m.get('host',[]) for m in route.get('match',[]))]
 assert len(matched)==1,name
 return matched[0]
required_strip={'Remote-User','Remote_User','X-Remote-User','X_Remote_User',
 'Remote-Groups','Remote_Groups','X-Webservices-SSO-Subject','X_Webservices_SSO_Subject',
 'X-Trusted-Proxy-Secret','X_Trusted_Proxy_Secret'}
for declared in routes:
 host=declared['host'];nodes=list(descendants(host_route(host)))
 pending=declared.get('special') in ('qbittorrent-native','bookstack-api')
 if declared.get('process') and not pending:
  dial=f"{declared['process']}:{declared['port']}"
  assert any(dial==u['dial'] for x in nodes if x.get('handler')=='reverse_proxy' for u in x.get('upstreams',[])),(host,dial)
  deleted={h for x in nodes if x.get('handler')=='headers' for h in x.get('request',{}).get('delete',[])}
  assert required_strip<=deleted,(host,required_strip-deleted)
 if pending:
  assert any(x.get('handler')=='static_response' and x.get('status_code')==503 for x in nodes),host
  assert not any(x.get('handler')=='reverse_proxy' for x in nodes),host
 if declared['policy']=='GROUP' and not pending:
  assert declared['groups']
  assert any('Remote-Groups' in x.get('header_regexp',{}) and
    'X-Webservices-SSO-Subject' in x.get('header_regexp',{})
    for x in nodes),host
  assert any(x.get('handler')=='reverse_proxy' and any(
     u['dial']=='auth-gateway:4180' for u in x.get('upstreams',[])) for x in nodes),host
  assert any(x.get('handler')=='static_response' and x.get('status_code')==403 for x in nodes),host
def path_branch(host_name,selected):
 branches=[node for node in descendants(host_route(host_name if host_name=='datamancy.net' else host_name+'.datamancy.net')) if
  isinstance(node.get('match'),list) and any(selected in m.get('path',[]) for m in node['match'])]
 assert branches,(host_name,selected)
 return branches[0]
for host_name,path in [('work','/_accounts'),('files','/seafhttp/*'),
 ('notebooks','/hub/api/*'),('home','/api/webhook/*'),('api.matrix','/_matrix/federation/*')]:
 branch=path_branch(host_name,path)
 nodes=list(descendants(branch.get('handle',[])))
 assert any(x.get('handler')=='reverse_proxy' for x in nodes),(host_name,path)
 assert not any(x.get('handler')=='reverse_proxy' and any(u['dial']=='auth-gateway:4180'
   for u in x.get('upstreams',[])) for x in nodes),(host_name,path)
 assert required_strip<={h for x in nodes if x.get('handler')=='headers' for h in
  x.get('request',{}).get('delete',[])},(host_name,path)
assert any(x.get('status_code')==404 for x in descendants(path_branch('api.matrix','/_synapse/admin')))
for host_name in ('portal','datamancy.net'):
 for path in ('/.well-known/matrix/client','/.well-known/matrix/server'):
  nodes=list(descendants(path_branch(host_name,path)))
  assert any(x.get('handler')=='static_response' and x.get('status_code')==200 for x in nodes)
assert any(x.get('handler')=='static_response' and x.get('status_code')==403
   for x in descendants(path_branch('firefly','/login')))
finance_native=list(descendants(path_branch('firefly','/oauth/token')))
assert any(x.get('handler')=='reverse_proxy' and any(u['dial']=='firefly-native-api:8081'
   for u in x.get('upstreams',[])) for x in finance_native)
assert required_strip<={h for x in finance_native if x.get('handler')=='headers' for h in
  x.get('request',{}).get('delete',[])}
for ntfy_host in ('ntfy.datamancy.net','ntfy-native.datamancy.net'):
 nodes=list(descendants(host_route(ntfy_host)))
 assert any('Authorization' in x.get('header_regexp',{}) and 'tk_' in
  x['header_regexp']['Authorization'].get('pattern','') for x in nodes),ntfy_host
 assert any(x.get('handler')=='reverse_proxy' and any(u['dial']=='ntfy:8080'
  for u in x.get('upstreams',[])) for x in nodes),ntfy_host
for name,required in {'work':['/_accounts','/auth/openid/callback'],
 'files':['/seafhttp/*','/onlyoffice/editor-callback'],
 'notebooks':['/hub/api/*','/user/*'],
 'home':['/api/webhook/*'],
 'api.matrix':['/_matrix/federation/*','/_matrix/client/*'],
 'files-native':['/api2/*','/seafhttp/*']}.items():
 matchers={p for x in descendants(host_route(name+'.datamancy.net')) for p in x.get('path',[])}
 assert set(required)<=matchers,(name,matchers)
# Explicit unavailable dispositions remain visible; they are NOT resolved
# application integrations merely because Caddy can parse their 503/404.
unavailable=sorted(r['label'] for r in routes if r['policy']=='FOLDED' or
 r.get('special') in (('ntfy-native','qbittorrent-native','bookstack-api','onboarding') if REV else
  ('ntfy-native','qbittorrent-native','bookstack-api','controller','agent-api','onboarding')))
with tempfile.TemporaryDirectory(prefix='p0-r9-caddy-validate-') as folder:
 scratch=Path(folder);env=os.environ.copy();env.update(XDG_DATA_HOME=str(scratch),XDG_CONFIG_HOME=str(scratch))
 ca=scratch/'offline-CA.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1',
     '-subj','/CN=auth.datamancy.net','-addext','subjectAltName=DNS:auth.datamancy.net',
     '-keyout',str(scratch/'offline-key.pem'),
     '-out',str(ca)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
 generated=set()
 def rewrite(value):
  if isinstance(value,dict):
   for key,v in value.items():
    if key=='certificate' and v in {'/run/secrets/'+stem+'.pem' for stem in selected_tls}:
     value[key]=str(ca)
    elif key=='key' and v in {'/run/secrets/'+stem+'-key.pem' for stem in selected_tls}:
     value[key]=str(scratch/'offline-key.pem')
    elif key=='root_ca_pem_files':
     assert len(v)==1 and v[0].startswith('/run/secrets/') and v[0].endswith('-ca.pem')
     generated.add(v[0]);value[key]=[str(ca)]
    elif key=='client_certificate_file':
     assert v=='/run/secrets/opensearch-reader.pem';value[key]=str(ca)
    elif key=='client_certificate_key_file':
     assert v=='/run/secrets/opensearch-reader-key.pem';value[key]=str(scratch/'offline-key.pem')
    else:rewrite(v)
  elif isinstance(value,list):
   for row in value:rewrite(row)
 rewrite(config)
 declared={'/run/secrets/'+r['caInput'] for r in routes if r.get('caInput')}
 assert generated==declared,(generated,declared)
 fixture=scratch/'caddy.json';fixture.write_text(json.dumps(config))
 result=subprocess.run([str(BIN),'validate','--config',str(fixture)],env=env,capture_output=True,text=True)
 if result.returncode:raise RuntimeError('Exact CLI rejected full adapted configuration: '+result.stderr[:1200])
 receipt={'schemaVersion':1,'sourceManifestSha256':hashlib.sha256(MAN.read_bytes()).hexdigest(),
  'generatedCaddyfileSha256':hashlib.sha256(SRC.read_bytes()).hexdigest(),
  'fullAdaptedSourceSha256':hashlib.sha256(adapt.stdout).hexdigest(),
  'exactCaddyCliSha256':hashlib.sha256(BIN.read_bytes()).hexdigest(),
  'oldRouteLabelsClassified':40,'moduleOwnedRoutes':len(routes),'uniqueApprovedPrivateHosts':len(hosts),
  'referencedPrivateBackendCaInputs':sorted(declared),
  'intentionallyUnavailableOrPendingNativePolicies':unavailable,
  'allSelectedApplicationRoutesFunctional':False,
  'adaptedHandlerPolicyAndHeaderChecksPassed':True,
  'cliValidateFixtureOnly':True,'applicationStarted':False,'nativeTrustVerified':False,
  'limitation':'Offline CA paths substituted for missing per-generation secret mounts. Full source JSON is adapted; native production CA and peer reachability are not validated.'}
 # Retain the original 165 evidence byte-for-byte; this is a distinct audit.
 (OUT/('fresh-r9-full-caddy-validation-control-v3.json' if REV else 'fresh-r9-full-caddy-validation-388.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 (OUT/('fresh-r9-full-caddy-adapt-control-v3.json' if REV else 'fresh-r9-full-caddy-adapt-388.json')).write_bytes(adapt.stdout)
 print(json.dumps(receipt,indent=2))
