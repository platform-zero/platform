#!/usr/bin/env python3
"""Read-only r9 module ingress reconciliation. Not a second route registry.

The OWNED manifest route declarations produce Caddyfile and graph networks.
Report explicit missing features separately from intentional no-HTTP controls.
No syntax/host count is treated as authorization to start applications.
"""
import hashlib,json,yaml
from pathlib import Path
from refetch_pinned_old_references import (ROOT as OLD_CACHE, OLD_COMMIT, MODULES, CADDY,
    verified_reference_file)
R=Path(__file__).resolve().parents[1]/'src/main/resources/fragments/v3'
M=R/'canonical/r9/manifest.yaml';I=R/'canonical/r9/index.yaml'
OLD=OLD_CACHE/('p0-modules-'+OLD_COMMIT)/CADDY
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads(M.read_bytes());i=yaml.safe_load(I.read_bytes())
 verified_reference_file('p0-modules-'+OLD_COMMIT,OLD_COMMIT,MODULES,CADDY,
     m['integratedReference']['routeSourceSha256'])
 if sha(M)!=i['manifestSha256'] or sha(OLD)!=m['integratedReference']['routeSourceSha256']:
  raise RuntimeError('Unpinned r9 module ingress or OLD route source')
 procs={};source={}
 for ref in i['entries']:
  f=R/ref['resource'];d=yaml.safe_load(f.read_bytes())
  if sha(f)!=ref['sha256']:raise RuntimeError('Mutated selected fragment')
  for p in d['processes']:
   if not p.get('oneShot'):
    if p['id'] in procs:raise RuntimeError('Duplicate process')
    procs[p['id']]=p;source[p['id']]=d['product']
 routes=[(module['id'],route) for module in m['integratedReference']['modules'] for route in module.get('privateRoutes',[])]
 old={r['label'] for r in m['integratedReference']['routes']}
 if len(old)!=40 or len(routes)!=48 or len({r['label'] for _,r in routes})!=48 or not old<={r['label'] for _,r in routes}:
  raise RuntimeError('Not every OLD label and r9 support route is classified')
 disposition={}
 for module,r in routes:
  selected=r.get('process');policy=r['policy'];special=r.get('special','')
  if selected and selected in procs:
   p=procs[selected]
   if source[selected]!=module or r['network'] not in p['networks']:
    raise RuntimeError('Module route is not the selected process network')
  elif selected=='forgejo' and module=='forgejo':pass # selected V2 provider, bound by Kotlin full projection
  elif selected:raise RuntimeError('Non-executable declared route')
  if special=='kopia':s='INTENTIONAL_NATIVE_BACKUP_CONTROL_NO_HTTP_DAEMON'
  elif special in ('mail-tls','portal-redirect','apex-redirect'):s='INTENTIONAL_NON_APPLICATION_TLS_OR_REDIRECT'
  elif special=='onboarding':
   if selected is not None or policy!='CONTROL':raise RuntimeError('Onboarding must use only the selected identity gateway')
   s='DECLARED_NATIVE_OIDC_REQUIRED_ACTION_START_POST_LOGIN_READBACK_PENDING'
  elif special in ('controller','agent-api'):
   if selected is not None or policy!='CONTROL':raise RuntimeError('Control must use only the selected managed native socket')
   s=('OWNED_BROKER_READ_ONLY_STATUS_TYPED_START_STOP_NOT_IMPLEMENTED' if special=='controller' else
      'OWNED_BROKER_HTTP_SOCKET_FRESH_DEVICE_GRANT_SOURCE_CHAT_LANE_TRANSPORT_MISSING')
  elif special in ('finance','finance-importer'):
   if selected not in ('firefly-sso','firefly-importer-sso'):
    raise RuntimeError('Financial browser route is not the acquired module SSO peer')
   s='DECLARED_OLD_PINNED_SSO_AND_NATIVE_BACKENDS_NATIVE_NOT_VALIDATED'
  elif special in ('qbittorrent-native','bookstack-api'):s='FRESH_GRANT_SOURCE_EXISTS_ENROLLMENT_AND_NATIVE_BEHAVIOR_UNVERIFIED'
  elif special in ('ntfy','ntfy-native'):s='DECLARED_FRESH_NTFY_USER_TOKEN_SOURCE_NATIVE_NOT_VALIDATED'
  elif special=='search':s='DECLARED_SCOPED_MTLS_READER_NATIVE_NOT_VALIDATED'
  else:s='DECLARED_GRAPH_UPSTREAM_NATIVE_NOT_VALIDATED'
  disposition[r['label']]={'module':module,'host':r['host'],'process':selected,'network':r.get('network'),
      'port':r.get('port'),'policy':policy,'special':special,'sourceStatus':s}
 unresolved=sorted(label for label in disposition if disposition[label]['sourceStatus'] in
     ('FEATURE_SOURCE_GAP','FRESH_GRANT_SOURCE_EXISTS_ENROLLMENT_AND_NATIVE_BEHAVIOR_UNVERIFIED',
      'OWNED_BROKER_READ_ONLY_STATUS_TYPED_START_STOP_NOT_IMPLEMENTED',
      'OWNED_BROKER_HTTP_SOCKET_FRESH_DEVICE_GRANT_SOURCE_CHAT_LANE_TRANSPORT_MISSING'))
 report={'schemaVersion':2,'scope':'r9-module-owned-private-ingress-not-release-admission',
  'indexSha256':sha(I),'manifestSha256':sha(M),'oldCaddyfileSha256':sha(OLD),
  'oldReferenceProvenance':{'repository':MODULES,'commit':OLD_COMMIT,'cache':str(OLD_CACHE),
      'role':'topology-reference-only-not-runtime-authority'},
  'oldRouteLabelsAccounted':len(old),'totalModuleDeclarations':len(routes),
  'uniquePrivateHosts':len({r['host'] for _,r in routes}),
  'routeDisposition':disposition,'unresolvedSelectedReferenceLabels':unresolved,
  'fullFeatureClosure':False,'nativeValidation':False,'noApplicationStartup':True,
  'note':'Credential-fed fixture policies and syntax are source checks; no 503/404 or account redirect proves native feature completion.'}
 print(json.dumps(report,indent=2,sort_keys=True))
if __name__=='__main__':main()
