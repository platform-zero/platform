#!/usr/bin/env python3
"""Offline native policy fixture: never use its known test credentials in a release."""
import json,hashlib,tempfile,subprocess,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];BASE=ROOT/'.coord/rapid-completion'
B=BASE/'caddy-config-check-bin-142';source=BASE/'fresh-r9-caddy-native-fixture-391'
assert hashlib.sha256(B.read_bytes()).hexdigest()=='678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9'
assert b'e'*64 in source.read_bytes()
# Re-adapt the current graph-rendered fixture with the exact pinned binary;
# a stale saved JSON must never pass the structural routing assertions.
adapted=subprocess.run([str(B),'adapt','--config',str(source),'--adapter','caddyfile'],
    capture_output=True,timeout=30,check=True)
assert len(adapted.stdout)<1_048_576
config=json.loads(adapted.stdout)
pinned=BASE/'fresh-r9-native-adapt-391.json'
if pinned.exists():assert pinned.read_bytes()==adapted.stdout
else:pinned.write_bytes(adapted.stdout)
site={m['host'][0]:r for server in config['apps']['http']['servers'].values() for r in server['routes'] for m in r.get('match',[]) if len(m.get('host',[]))==1}
def allnodes(v):
 if isinstance(v,dict):
  yield v
  for k in v.values():yield from allnodes(k)
 elif isinstance(v,list):
  for k in v:yield from allnodes(k)
book=list(allnodes(site['api.bookstack.datamancy.net']))
qb=list(allnodes(site['qbittorrent-native.datamancy.net']))
assert any('X-Internal-Token' in x.get('header',{}) and 'e'*64 in str(x) for x in book)
assert any(x.get('handler')=='reverse_proxy' and any(u['dial']=='bookstack:8080' for u in x['upstreams']) and
    x.get('headers',{}).get('request',{}).get('set',{}).get('Authorization')==
    ['Token p0v3-'+'b'*32+':'+'c'*64] for x in book)
assert any(x.get('handler')=='static_response' and x.get('status_code')==403 for x in book)
assert any(x.get('handler')=='authentication' and any(a['password'].startswith('$2a$12$') for a in
 x['providers']['http_basic']['accounts']) for x in qb)
assert any(x.get('handler')=='reverse_proxy' and any(u['dial']=='qbittorrent:8080' for u in x['upstreams']) for x in qb)
assert not any('Authorization' in x.get('request',{}).get('delete',[]) for x in qb),\
    'Native API Basic authorization cannot be erased before qBittorrent authenticates it'
assert any(x.get('handler')=='static_response' and x.get('status_code')==404 for x in qb)
finance=list(allnodes(site['firefly.datamancy.net']))
assert any(x.get('handler')=='reverse_proxy' and any(u.get('dial')=='firefly-native-api:8081'
    for u in x.get('upstreams',[])) for x in finance)
assert not any(x.get('handler')=='static_response' and x.get('status_code')==503 for x in finance)
ntfy=list(allnodes(site['ntfy.datamancy.net']))
ntfy_native=list(allnodes(site['ntfy-native.datamancy.net']))
assert any(x.get('handler')=='reverse_proxy' and x.get('headers',{}).get('request',{}).get('set',{}).get('Authorization')==
    ['Bearer tk_'+'a'*32] for x in ntfy)
assert any(x.get('handler')=='reverse_proxy' and any(u['dial']=='ntfy:8080' for u in x['upstreams'])
    and 'Authorization' not in x.get('headers',{}).get('request',{}).get('set',{}) for x in ntfy_native)
assert any('Authorization' in x.get('header_regexp',{}) and 'Basic' in
    x['header_regexp']['Authorization'].get('pattern','') for x in ntfy_native)
# Inspect the actual adapted Caddy subroute sequence, not only host names or
# an unordered search for proxy handlers. These expectations come from the
# reviewed OLD callback/native policy; the module graph remains the only
# executable routing source. Caddy's adapter may reorder directives.
def selected_routes(host):
 r=site[host]
 assert len(r['handle'])==1 and r['handle'][0]['handler']=='subroute'
 outer=r['handle'][0]['routes']
 assert len(outer)==1 and len(outer[0]['handle'])==1
 sub=outer[0]['handle'][0]
 assert sub['handler']=='subroute'
 return sub['routes']
def nodes(route):return list(allnodes(route))
def proxy(route,dial,uri=None):
 return any(n.get('handler')=='reverse_proxy' and
    any(u.get('dial')==dial for u in n.get('upstreams',[])) and
    (uri is None or n.get('rewrite',{}).get('uri')==uri) for n in nodes(route))
def paths(route):
 return {p for m in route.get('match',[]) for p in m.get('path',[])}
def gate(route):return proxy(route,'auth-gateway:4180','/oauth2/auth')
def guarded(host,bypass,dial):
 routes=selected_routes(host)
 assert len(routes)==len(bypass)+3,host
 for i,required in enumerate(bypass):
  assert required<=paths(routes[i]) and proxy(routes[i],dial) and not gate(routes[i]),(host,i)
  deleted={v for n in nodes(routes[i]) for v in n.get('request',{}).get('delete',[])}
  assert {'Remote-User','Remote_User','Remote-Groups','Remote_Groups',
      'X-Webservices-SSO-Subject','X_Webservices_SSO_Subject'}<=deleted,(host,i)
 auth,allowed,denied=routes[len(bypass):]
 assert gate(auth) and not auth.get('match'),host
 g=next(n for n in nodes(auth) if n.get('rewrite',{}).get('uri')=='/oauth2/auth')
 responses=g['handle_response']
 assert [401,403] in [r['match'].get('status_code') for r in responses],host
 redirect=next(r for r in responses if r['match'].get('status_code')==[401,403])
 assert any(n.get('handler')=='rewrite' and n.get('uri')=='/oauth2/start' for n in nodes(redirect))
 assert any(n.get('handler')=='reverse_proxy' and
     n.get('headers',{}).get('request',{}).get('set',{}).get('X-Auth-Request-Redirect')==
     ['{http.request.scheme}://{http.request.host}{http.request.orig_uri}'] for n in nodes(redirect))
 assert any('Remote-Groups' in m.get('header_regexp',{}) and
     'X-Webservices-SSO-Subject' in m.get('header_regexp',{}) for m in allowed.get('match',[])),host
 assert proxy(allowed,dial) and any(n.get('handler')=='static_response' and
     n.get('status_code')==403 for n in nodes(denied)),host
 return routes
control=selected_routes('control.datamancy.net')
assert len(control)==3 and gate(control[0])
assert any('Remote-Groups' in m.get('header_regexp',{}) and
    'X-Webservices-SSO-Subject' in m.get('header_regexp',{}) for m in control[1].get('match',[]))
assert proxy(control[1],'unix//run/p0-control/http.sock') and not proxy(control[0],'unix//run/p0-control/http.sock')
assert any(x.get('status_code')==403 for x in nodes(control[2]))
device=selected_routes('api.datamancy.net')
assert len(device)==2 and paths(device[0])=={'/v1/models','/v1/chat/completions'}
assert proxy(device[0],'unix//run/p0-control/http.sock') and not any(gate(x) for x in device)
assert {'Cookie','Remote-User','X-Webservices-SSO-Subject'}<={h for n in nodes(device[0]) for h in
    n.get('request',{}).get('delete',[])}
assert any(n.get('status_code')==404 for n in nodes(device[1]))
guarded('work.datamancy.net',[{'/_accounts','/auth/openid/callback'}],'huly:8443')
guarded('files.datamancy.net',[{'/seafhttp/*','/onlyoffice/editor-callback'}],'seafile-files:8443')
guarded('notebooks.datamancy.net',[{'/hub/api/*','/user/*'}],'hub:8443')
home_routes=guarded('home.datamancy.net',[{'/api/webhook/*'},set(),set()],'homeassistant:8123')
assert any('User-Agent' in m.get('header_regexp',{}) for m in home_routes[1]['match'])
assert any(m.get('query',{}).get('external_auth')==['1'] for m in home_routes[2]['match'])
ntfy_routes=guarded('ntfy.datamancy.net',[set()],'ntfy:8080')
assert any('Authorization' in m.get('header_regexp',{}) and
    'tk_' in m['header_regexp']['Authorization']['pattern'] for m in ntfy_routes[0]['match'])
assert not any(n.get('headers',{}).get('request',{}).get('set',{}).get('Authorization')
    for n in nodes(ntfy_routes[0]) if n.get('handler')=='reverse_proxy')
assert any(n.get('headers',{}).get('request',{}).get('set',{}).get('Authorization')==
    ['Bearer tk_'+'a'*32] for n in nodes(ntfy_routes[-2]) if n.get('handler')=='reverse_proxy')
# A misordered bypass must fail even though every host and upstream still exists.
first=home_routes.pop(0)
try:
 try:guarded('home.datamancy.net',[{'/api/webhook/*'},set(),set()],'homeassistant:8123')
 except AssertionError:pass
 else:raise AssertionError('A removed native callback bypass escaped adapted-order verification')
finally:home_routes.insert(0,first)
# The selected OIDC start route initiates Keycloak's native required-action
# journey. A post-login session is NOT completion/readback of those actions.
onboard=list(allnodes(site['onboarding.datamancy.net']))
assert any(n.get('handler')=='static_response' and n.get('status_code')==302 and
    '/oauth2/start?rd=' in str(n.get('headers',{}).get('Location',[])) for n in onboard)
assert any(n.get('handler')=='reverse_proxy' and any(u['dial']=='auth-gateway:4180'
    for u in n.get('upstreams',[])) for n in onboard)
assert any(n.get('handler')=='static_response' and 'native-readback-pending' in str(n.get('body',''))
    for n in onboard)
with tempfile.TemporaryDirectory(prefix='p0-native-caddy-') as folder:
 root=Path(folder);ca=root/'fixture-ca.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1',
  '-subj','/CN=TEST-ONLY','-keyout',str(root/'key.pem'),'-out',str(ca)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
 count=0
 for node in allnodes(config):
  if 'root_ca_pem_files' in node:
   assert all(x.startswith('/run/secrets/') and x.endswith('-ca.pem') for x in node['root_ca_pem_files'])
   node['root_ca_pem_files']=[str(ca)];count+=1
  if 'client_certificate_file' in node:
   assert node['client_certificate_file']=='/run/secrets/opensearch-reader.pem'
   assert node['client_certificate_key_file']=='/run/secrets/opensearch-reader-key.pem'
   node['client_certificate_file']=str(ca)
   node['client_certificate_key_file']=str(root/'key.pem')
 assert count>=7
 selected_tls={'identity-web','office-web','files-web','work-web','groupware-web','finance-ingress-web'}
 observed_cert=set();observed_key=set()
 for node in allnodes(config):
  if node.get('certificate') in {'/run/secrets/'+stem+'.pem' for stem in selected_tls}:
   observed_cert.add(node['certificate']);node['certificate']=str(ca)
  if node.get('key') in {'/run/secrets/'+stem+'-key.pem' for stem in selected_tls}:
   observed_key.add(node['key']);node['key']=str(root/'key.pem')
 assert observed_cert=={'/run/secrets/'+stem+'.pem' for stem in selected_tls}
 assert observed_key=={'/run/secrets/'+stem+'-key.pem' for stem in selected_tls}
 file=root/'adapted-fixture.json';file.write_text(json.dumps(config))
 env=os.environ.copy();env.update(XDG_DATA_HOME=str(root),XDG_CONFIG_HOME=str(root))
 validation=subprocess.run([str(B),'validate','--config',str(file)],env=env,capture_output=True,text=True)
 assert validation.returncode==0,validation.stderr[:800]
print(json.dumps({'schemaVersion':1,'kind':'test-only-known-credentials-never-deploy',
 'generatedSourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
 'exactCaddyCliSha256':hashlib.sha256(B.read_bytes()).hexdigest(),
 'nativeBookstackTokenAndQbittorrentBcryptPolicyValidated':True,
 'bookstackEnrollmentScriptRan':False,
 'adaptedCallbackAndSsoOrderChecked':True,'managedControlOwnerAndDeviceSocketOrderChecked':True,
 'onboardingOIDCSourceAuthAndNoActionCompletionChecked':True,'mutatedBypassRejected':True,
 'nativeCredentialsIssuedOrEnrolled':False,'fullSourceReleaseAdmission':False},indent=2))
