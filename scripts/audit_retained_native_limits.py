#!/usr/bin/env python3
"""Read-only native retained-container hard-cap census; never RSS/admission.

No inspect Env, tokens, volumes or commands are serialized. Two rootful stores
are observed; absent rootless/host services require separate frozen accounting.
"""
import hashlib,json,subprocess
from pathlib import Path
CMD={
 'legacy':['sudo','-n','/usr/bin/podman','--remote=false','--root=/mnt/media/p0-v3/release-runtime/graph','--runroot=/run/p0-v3-release-runtime/store','--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config'],
 'canonical-v2':['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']}
def native(args,max_bytes=3000000):
 r=subprocess.run(args,capture_output=True,timeout=90,check=True)
 if len(r.stdout)>max_bytes:raise RuntimeError('Unbounded native readback')
 return r.stdout.decode('utf-8','strict')
def main():
 result=[]
 for store,cmd in CMD.items():
  ids=[line for line in native(cmd+['ps','--no-trunc','--format','{{.ID}}']).splitlines() if line]
  if len(ids)>4096 or any(len(x)!=64 for x in ids):raise RuntimeError('Invalid native running-CID census')
  if not ids:continue
  text=native(cmd+['inspect','--type','container','--format',
     '{{.Id}}\t{{.Name}}\t{{.HostConfig.Memory}}\t{{.HostConfig.MemorySwap}}\t{{.State.Status}}']+ids)
  records=[]
  for line in text.splitlines():
   cols=line.split('\t')
   if len(cols)!=5 or cols[-1]!='running' or cols[0] not in ids:raise RuntimeError('Running store changed or ambiguous')
   cid,name,mem,swap,state=cols
   if int(mem)<0 or int(swap)<-1:raise RuntimeError('Invalid memory policy')
   records.append({'cid':cid,'name':name.removeprefix('/'),'memoryHardCapBytes':int(mem),
      'memorySwapLimitBytes':int(swap),'memoryMiB':(int(mem)+1048575)//1048576 if int(mem) else None})
  if len(records)!=len(ids) or {x['cid'] for x in records}!=set(ids):raise RuntimeError('Changed native CID set')
  result+=list(dict(store=store,**row) for row in records)
 known=[x['memoryMiB'] for x in result if x['memoryMiB'] is not None]
 print(json.dumps({'schemaVersion':1,'scope':'point-in-time-running-container-cap-census-not-RSS-or-capacity-release',
    'runningContainerCount':len(result),'configuredHardCapsSumMiB':sum(known),
    'unboundedContainerCount':len(result)-len(known),
    'stores':{store:sum(x['store']==store for x in result) for store in CMD},
    'containers':result,'applicationStarted':False,'effectReplayAuthorized':False},indent=2,sort_keys=True))
if __name__=='__main__':main()
