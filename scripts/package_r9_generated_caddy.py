#!/usr/bin/env python3
"""Package exact Caddy CLI derivative of graph-generated Caddyfile into r9 index.

This is NOT a handwritten second route inventory. Any graph change requires
re-rendering, adapting and re-validating with the pinned binary before repackaging.
"""
from pathlib import Path
import hashlib,json,os,shutil,yaml
ROOT=Path(__file__).resolve().parents[2]
REV=os.environ.get('P0V3_R9_CADDY_REVISION','')
assert REV in ('','control-v3')
R=ROOT/'platform/src/main/resources/fragments/v3/canonical/r9'
I=R/'index.yaml';M=R/'manifest.yaml'
OUT=ROOT/'.coord/rapid-completion'
SRC=OUT/('fresh-r9-full-caddyfile-control-v2' if REV else 'fresh-r9-full-caddyfile-388')
JSON=OUT/('fresh-r9-full-caddy-adapt-control-v3.json' if REV else 'fresh-r9-full-caddy-adapt-388.json')
RECEIPT=OUT/('fresh-r9-full-caddy-validation-control-v3.json' if REV else 'fresh-r9-full-caddy-validation-388.json')
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
i=yaml.safe_load(I.read_bytes());m=json.loads(M.read_bytes());a=json.loads(RECEIPT.read_bytes())
assert i['manifestSha256']==sha(M)==a['sourceManifestSha256']
assert sha(SRC)==a['generatedCaddyfileSha256'] and sha(JSON)==a['fullAdaptedSourceSha256']
assert a['exactCaddyCliSha256']=='678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9'
assert a['oldRouteLabelsClassified']==40 and a['moduleOwnedRoutes']==48
TARGET=R/'generated-caddy.json'
if TARGET.exists():
 assert i.get('adaptedCaddyJsonSha256')==sha(TARGET) and len(i.get('generatedCaddyfileSha256',''))==64
shutil.copyfile(JSON,TARGET)
i['generatedCaddyfileSha256']=sha(SRC)
i['adaptedCaddyJsonSha256']=sha(TARGET)
i['caddyResource']='canonical/r9/generated-caddy.json'
I.write_text(yaml.safe_dump(i,sort_keys=False))
print('r9 manifest',sha(M),'adapted JSON',sha(TARGET),'index',sha(I))
