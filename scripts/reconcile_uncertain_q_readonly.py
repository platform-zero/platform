#!/usr/bin/env python3
"""Independent *physical* terminal observation for q-d874; never an original ACK.

Reads original pins, maintenance fence, exact canonical-store CIDs/labels,
all generated systemd units, and process/owner identities twice. No locks,
Podman mutations, unit transitions, result backfills or reservation release.
A time-bounded observation cannot authorize a later restart or replacement.
"""
import hashlib,json,os,re,subprocess,time
from pathlib import Path
GEN='q-d874eb36057e'
ROOT=Path('/mnt/media/p0-v3/release-generations')/GEN
OUT=Path(__file__).resolve().parents[2]/'.coord/rapid-completion/q-d874-physical-terminal-readonly-126.json'
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
def digest(x):return hashlib.sha256(x).hexdigest()
def original(name,limit=2_000_000):
 p=ROOT/name
 if p.is_symlink() or not p.is_file() or p.stat().st_size>limit:raise RuntimeError('Missing/foreign original proof: '+name)
 return p.read_bytes()
def native(args,maxsize=3_000_000):
 r=subprocess.run(args,capture_output=True,timeout=50,check=True)
 if len(r.stdout)>maxsize or len(r.stderr)>8192:raise RuntimeError('Oversized read-only native census')
 return r.stdout.decode('utf-8','strict')
def process_scan():
 # This script's argv does not contain the generation ID. A separate owner
 # could use another executable name; match either ID or known owner PID/ticks.
 seen=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  try:
   line=(p/'cmdline').read_bytes().replace(b'\x00',b' ').decode('utf-8','replace')
   if GEN in line:seen.append({'pid':int(p.name),'commandSha256':digest(line.encode())})
  except (PermissionError,FileNotFoundError,ProcessLookupError):continue
 return sorted(seen,key=lambda v:v['pid'])
def owner_state(pid,ticks):
 p=Path('/proc')/str(pid)
 try:
  text=(p/'stat').read_text(); fields=text.rsplit(')',1)[1].strip().split()
  return {'pid':pid,'originalStartTicks':ticks,'sameLiveOwner':int(fields[19])==ticks and fields[0] not in ('Z','X')}
 except (FileNotFoundError,ProcessLookupError):return {'pid':pid,'originalStartTicks':ticks,'sameLiveOwner':False}
def census():return json.loads(native(CMD+['ps','-a','--no-trunc','--format','json']))
def main():
 if not ROOT.is_dir() or ROOT.is_symlink() or OUT.exists():raise RuntimeError('Original root or separate output invalid')
 bundle=original('bundle.json',4_194_304);b=json.loads(bundle)
 if digest(bundle)!='fa4906c40932a4f6a7c8d6df1207e437d442d47c8b9981798b7ebd7f3636ddcf':
  raise RuntimeError('Original bundle changed')
 pin,=b['members'];spec=pin['spec'];member=spec['name'];fingerprint=pin['runtimeFingerprint']
 if member!=GEN+'-canonical-shared-core-v3' or len(spec['processes'])!=26:raise RuntimeError('Not original member')
 fence_path=Path('/mnt/media/p0-v3/runtime-deployments')/member/'runtime.maintenance'
 if fence_path.is_symlink() or not fence_path.is_file() or fence_path.with_name('runtime.maintenance.tmp').exists():
  raise RuntimeError('Maintenance fence missing/uncertain')
 fb=fence_path.read_bytes();fence=json.loads(fb)
 unsigned={key:value for key,value in fence.items() if key!='checksum'}
 # Kotlin Json omits default-valued checksum and absent stageTarget when
 # hashing MaintenanceFence.copy(checksum=""). Do not assume blank is encoded.
 fence_valid=(fence['fingerprint']==fingerprint and fence['reason']=='update' and
   fence['checksum']==digest(json.dumps(unsigned,separators=(',',':'),ensure_ascii=False).encode()))
 original_absent=all(not (ROOT/name).exists() for name in ('quadlet-serve-stop.result.json',
     'quadlet-serve.result.json','quadlet-capacity.terminal.json',
     f'quadlet-stop-{member}-node-exporter.result.json',f'quadlet-delegate-{member}-node-exporter-stop.ack.json'))
 launches={};owners={};provenance={}
 for p in spec['processes']:
  key=p['id'];name=f'quadlet-launch-{member}-{key}.result.json';data=original(name)
  j=json.loads(data)
  if not j['nativeAcknowledged'] or j['imageId']!=p['imageId'] or not re.fullmatch('[a-f0-9]{64}',j['containerId']):
   raise RuntimeError('Original CID unbound: '+key)
  launches[key]=j['containerId'];provenance[name]=digest(data)
  start=f'quadlet-delegate-{member}-{key}-start.intent.json';start_bytes=original(start)
  owner=json.loads(start_bytes);provenance[start]=digest(start_bytes)
  if owner['fingerprint']!=fingerprint or owner['process']!=key:raise RuntimeError('Foreign owner intent')
  owners[(owner['ownerPid'],owner['ownerStartTicks'])]=None
  for suffix in ('stop.intent.json',):
   stop=ROOT/f'quadlet-delegate-{member}-{key}-{suffix}'
   if stop.is_file():
    val=original(stop.name);j=json.loads(val)
    if j['fingerprint']!=fingerprint or j['process']!=key:raise RuntimeError('Foreign stop owner')
    owners[(j['ownerPid'],j['ownerStartTicks'])]=None;provenance[stop.name]=digest(val)
 def observe():
  rows=census();matched={};other=[]
  for row in rows:
   names=row.get('Names',[])
   if not isinstance(names,list):raise RuntimeError('Unknown Podman names structure')
   for name in names:
    if name.startswith('p0v3-live-'+member+'-'):
     key=name.removeprefix('p0v3-live-'+member+'-')
     if key in matched:raise RuntimeError('Duplicate native name')
     matched[key]=row
    elif GEN in name:other.append(name)
  status=[]
  for p in spec['processes']:
   key=p['id'];row=matched.get(key)
   status.append({'process':key,'oneShot':p['oneShot'],'originalCid':launches[key],
      'nativeCid':row.get('Id') if row else None,'nativeState':row.get('State') if row else None,
      'exactCidExited':row is not None and row.get('Id')==launches[key] and row.get('State')=='exited'})
  unit=[]
  for p in spec['processes']:
   key=p['id'];name=f'p0v3-{member}-{key}.service'
   text=native(['/usr/bin/systemctl','show','--no-pager',
      '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlPID,UnitFileState',name],32768)
   fields=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
   complete=(fields.get('ActiveState')=='active' and fields.get('SubState')=='exited' and
     fields.get('Result')=='success' and fields.get('ExecMainStatus')=='0' and p['oneShot'])
   inactive=fields.get('ActiveState') in ('failed','inactive')
   unit.append({'process':key,'unit':name,'load':fields.get('LoadState'),
      'active':fields.get('ActiveState'),'sub':fields.get('SubState'),
      'mainPid':fields.get('MainPID'),'controlPid':fields.get('ControlPID'),
      'generated':fields.get('UnitFileState')=='generated',
      'terminal':(inactive or complete) and fields.get('MainPID')=='0' and
         fields.get('ControlPID')=='0' and fields.get('LoadState')=='loaded' and
         fields.get('UnitFileState')=='generated'})
  proc=process_scan();owner=[owner_state(*id) for id in sorted(owners)]
  return {'processes':status,'otherNamedContainers':other,'units':unit,
    'matchingHelperProcesses':proc,'originalOwners':owner,
    'physicallyQuiescent':len(matched)==len(spec['processes']) and
      all(v['exactCidExited'] for v in status) and all(u['terminal'] for u in unit) and
      not other and not proc and not any(v['sameLiveOwner'] for v in owner)}
 first=observe();time.sleep(0.35);second=observe()
 physical=(first['physicallyQuiescent'] and second['physicallyQuiescent'] and
  first['processes']==second['processes'] and first['units']==second['units'])
 report={'schemaVersion':1,'generation':GEN,'bundleSha256':digest(bundle),'member':member,
   'fingerprint':fingerprint,'originalLaunchProofSha256':provenance,
   'maintenanceFenceSha256':digest(fb),'maintenanceFenceValid':fence_valid,
   'missingOriginalResultsRemainMissing':original_absent,
   'physicalTerminalProven':bool(physical and original_absent and fence_valid),
   'observationOnly':True,'originalStopAcknowledged':False,'originalServeAcknowledged':False,
   'capacityReleased':False,'nativeEffectReplayAuthorized':False,
   'snapshots':[first,second],
   'caveat':'Bounded read-only physical quiescence; no original ACK, release reservation, historical success or future-start guarantee.'}
 OUT.parent.mkdir(exist_ok=True)
 with OUT.open('x') as fd:json.dump(report,fd,indent=2,sort_keys=True);fd.write('\n')
 OUT.chmod(0o600)
 print(GEN,'physicalTerminalProven',report['physicalTerminalProven'],'CID count',len(launches))
if __name__=='__main__':main()
