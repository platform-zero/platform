#!/usr/bin/env python3
"""One-time, pinned OLD importer integration into unactivated r9 (never r7/r8).
Copies only reviewed OLD source files and binds two SSO peers and native importer
under the module graph. Manifest remains the sole executable ingress authority.
"""
import hashlib, json, pathlib, re, yaml
ROOT=pathlib.Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
OLD=pathlib.Path('/tmp/p0-old-full-36b6b7/modules/firefly-iii/legacy/stack.config/firefly-importer')
SOURCE=ROOT/'firefly-iii/r2/fragment.yaml'
DEST=ROOT/'firefly-iii/r3'
INDEX=ROOT/'canonical/r9/index.yaml'; MANIFEST=ROOT/'canonical/r9/manifest.yaml'
sha=lambda b: hashlib.sha256(b).hexdigest()
assert sha(SOURCE.read_bytes())=='124af01ad0d92f88eb0a7d6b1a542551d3cc974a3c3606994cef713d97756957'
assert not DEST.exists(), 'r3 is source-only one-time materialization'
assert sha(MANIFEST.read_bytes())==yaml.safe_load(INDEX.read_bytes())['manifestSha256']
DEST.mkdir(mode=0o755)
copy=['bootstrap-app.php','ImporterSubjects.php','ManualFilePolicy.php','SubjectBoundary.php',
      'ImportJobRepository.php','WebIndexController.php','ApiImportJobsController.php','importer.php',
      'initialize-policy.php','bootstrap-hook.sh']
for name in copy:
    source=OLD/name; data=source.read_bytes()
    assert source.is_file() and not source.is_symlink() and len(data) in range(100,40000)
    if name in ('ImporterSubjects.php','SubjectBoundary.php'):
        assert data.count(b'keycloak\\.') == 1 and data.count(b'/realms/webservices') == 1
        data=data.replace(b'keycloak\\.',b'auth\\.').replace(b'/realms/webservices',b'/realms/p0v3')
    if name=='SubjectBoundary.php':
        # Bearer transport is the isolated native Caddy peer, not an unverified
        # public Caddy internal-CA chain. Same native policy and Passport owner API.
        before=b"'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'cafile' => '/ca/caddy-ca.crt'],"
        assert data.count(before)==1
        data=data.replace(before,b"'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],")
        before=b"@file_get_contents((string) config('importer.url').'/api/v1/about/user'"
        assert data.count(before)==1
        data=data.replace(before,b"@file_get_contents('http://firefly-native-api:8081/api/v1/about/user'")
    (DEST/name.lower()).write_bytes(data)
# Native upstream source stays verbatim; this does NOT add a second ingress graph.
(DEST/'native-api.caddyfile').write_bytes((SOURCE.parent/'native-api.caddyfile').read_bytes())
d=json.loads(SOURCE.read_bytes()); d['revision']=3
for artifact in ('firefly-importer','firefly-sso'):
    d['artifacts'].append(artifact)
d['networks']+=['firefly-importer-web','finance-api','identity-web']
d['providers'].append('keycloak')
d['providerNetworks']['keycloak']=['identity-web']
d['providerProcesses']['keycloak']=['keycloak']
d['webNetworks'].append('firefly-importer-web')
d['volumes'].append({'id':'firefly-importer-storage','userId':33})
def file(name, target): return {'file':name,'target':target}
def inp(name, consumers, purpose='RUNTIME'):
    d['inputs'].append({'name':name,'owner':'firefly-iii','purpose':purpose,'consumers':consumers})
# Distinct secret files for the two confidential browser clients; Keycloak CA is
# generation-matched. Runtime image source is sealed and never read from OLD.
inp('firefly-sso.env',['firefly-sso']);inp('firefly-importer-sso.env',['firefly-importer-sso'])
d['inputs'].append({'name':'identity-ca.pem','owner':'keycloak','purpose':'RUNTIME',
                    'consumers':['firefly-sso','firefly-importer-sso']})
inp('firefly-importer.env',['firefly-importer','firefly-importer-files-init'])
for name in copy:
    file_name='finance-'+name.lower()
    if name=='bootstrap-hook.sh': consumers=['firefly-importer']
    elif name in ('initialize-policy.php','ImporterSubjects.php','ManualFilePolicy.php','SubjectBoundary.php'):
        consumers=['firefly-importer']
    else: consumers=['firefly-importer']
    inp(file_name,consumers)
    d['templates'].append({'output':file_name,'resource':name.lower(),'format':'LITERAL','parameters':{}})
# The v2 native transport file is unchanged, but its module revision is bound
# to the r3 resource hash, not a second handwritten host declaration.
proc=d['processes']; native=next(p for p in proc if p['id']=='firefly-native-api')
native['networks'].append('finance-api')
proc.append({'id':'firefly-importer-files-init','artifact':'firefly-importer','userId':33,'oneShot':True,
    'entrypoint':'/bin/sh','command':['-ec','cp -R /var/www/html/storage/. /seed/storage/'],
    'environmentFile':'firefly-importer.env','volumes':[{'volume':'firefly-importer-storage','target':'/seed/storage'}],
    'memoryMiB':512,'networks':['firefly-importer-web']})
patches={
 'bootstrap-app.php':'/var/www/html/bootstrap/app.php',
 'ImporterSubjects.php':'/opt/firefly-importer/ImporterSubjects.php',
 'ManualFilePolicy.php':'/opt/firefly-importer/ManualFilePolicy.php',
 'SubjectBoundary.php':'/opt/firefly-importer/SubjectBoundary.php',
 'ImportJobRepository.php':'/var/www/html/app/Repository/ImportJob/ImportJobRepository.php',
 'WebIndexController.php':'/var/www/html/app/Http/Controllers/IndexController.php',
 'ApiImportJobsController.php':'/var/www/html/app/Api/Controllers/ImportJob/IndexController.php',
 'importer.php':'/var/www/html/config/importer.php',
 'initialize-policy.php':'/opt/firefly-importer/initialize-policy.php',
 'bootstrap-hook.sh':'/etc/entrypoint.d/11-execute-things.sh'}
proc.append({'id':'firefly-importer','artifact':'firefly-importer','userId':33,
    'entrypoint':'/usr/local/bin/docker-php-serversideup-entrypoint','command':['/init'],
    'environmentFile':'firefly-importer.env','volumes':[{'volume':'firefly-importer-storage','target':'/var/www/html/storage'}],
    'files':[file('finance-'+name.lower(), target) for name,target in patches.items()],
    'memoryMiB':1024,'readinessHttpPort':8080,'readinessHttpPath':'/health',
    'networks':['firefly-importer-web','finance-api']})
for suffix,network in [('', 'firefly-web'),('-importer','firefly-importer-web')]:
    pid='firefly'+suffix+'-sso'
    proc.append({'id':pid,'artifact':'firefly-sso','userId':65532,'groupId':65532,
        'entrypoint':'/bin/oauth2-proxy','command':[],
        'environmentFile':pid+'.env','files':[file('identity-ca.pem','/run/secrets/identity-ca.pem')],
        'memoryMiB':256,'readinessHttpPort':4180,'readinessHttpPath':'/ready',
        'networks':[network,'identity-web']})
for phase in ('install','restore'):
    graph=d[phase]
    if phase=='install':
        graph['processes']+=['firefly-importer-files-init','firefly-importer','firefly-sso','firefly-importer-sso']
        graph['dependencies']['firefly-importer-files-init']=[]
        graph['dependencies']['firefly-importer']=['firefly-importer-files-init','firefly-native-api']
    else:
        graph['processes']+=['firefly-importer','firefly-sso','firefly-importer-sso']
        graph['dependencies']['firefly-importer']=['firefly-native-api']
    graph['dependencies']['firefly-sso']=['firefly','keycloak']
    graph['dependencies']['firefly-importer-sso']=['firefly-importer','keycloak']
# Input ownership accepts provider keycloak, provider export supplies identity-ca.
(DEST/'fragment.yaml').write_text(json.dumps(d,indent=2)+'\n')
index=yaml.safe_load(INDEX.read_bytes())
entry=next(e for e in index['entries'] if e['id']=='private-firefly-iii')
assert entry['revision']==2
entry['revision']=3;entry['resource']='firefly-iii/r3/fragment.yaml'
entry['sha256']=sha((DEST/'fragment.yaml').read_bytes())
entry['templates']={name.lower():sha((DEST/name.lower()).read_bytes()) for name in copy}
entry['templates']['native-api.caddyfile']=sha((DEST/'native-api.caddyfile').read_bytes())
# manifest revision and graph route owner remain the same pending r9 release.
manifest=json.loads(MANIFEST.read_bytes())
ref=next(f for f in manifest['fragments'] if f['id']=='private-firefly-iii')
assert ref['revision']==2;ref['revision']=3
finance=next(m for m in manifest['integratedReference']['modules'] if m['id']=='firefly-iii')
for route in finance['privateRoutes']:
    if route['label']=='firefly':
        assert route['process']=='firefly' and route['policy']=='GROUP'
        route.update(process='firefly-sso',port=4180,policy='APP')
        route.pop('groups',None)
    if route['label']=='firefly-importer':
        assert route['policy']=='FOLDED'
        route.update(process='firefly-importer-sso',network='firefly-importer-web',port=4180,policy='APP')
        route['special']='finance-importer'
assert finance['nativeDaemons']==['firefly-php','firefly','firefly-native-api']
finance['nativeDaemons']+=['firefly-sso','firefly-importer','firefly-importer-sso']
MANIFEST.write_text(json.dumps(manifest,indent=2)+'\n')
index['manifestSha256']=sha(MANIFEST.read_bytes())
INDEX.write_text(yaml.safe_dump(index,sort_keys=False))
print('r3 fragment',sha((DEST/'fragment.yaml').read_bytes()),'manifest',sha(MANIFEST.read_bytes()))
