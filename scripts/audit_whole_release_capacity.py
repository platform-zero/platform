#!/usr/bin/env python3
"""Whole-release envelope: exact declared caps plus honest unpinned work.

A hard OCI/cgroup cap is not measured resident memory or a complete release
reservation. Missing planned lane/job/backup numbers remain parameters, never
fabricated minima promoted to admission or reasons to lower a limit.
"""
import hashlib,json
from pathlib import Path
from audit_fresh_full_capacity import audit
BASE=Path(__file__).resolve().parents[2]
CI=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-minimal-bound-r2')
SHA=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 graph=audit(require_old=False);root=Path(__file__).resolve().parents[1]/'src/main/resources/fragments'
 import yaml
 idx=yaml.safe_load((root/'v3/canonical/r9/index.yaml').read_bytes())
 files=[root/'v2/postgres/r1/fragment.yaml',root/'v2/forgejo/r5/fragment.yaml']+[
   root/'v3'/r['resource'] for r in idx['entries']]
 vols=[];nets=[]
 for path in files:
  f=yaml.safe_load(path.read_bytes());vols.extend({'product':f['product'],'volume':v['id'],
   'source':str(path.relative_to(root)),'sourceSha256':SHA(path)} for v in f.get('volumes',[]));nets.extend(f['networks'])
 if len(vols)!=59 or len({v['volume'] for v in vols})!=59 or len(set(nets))!=73:
  raise RuntimeError('Full release volume or network count changed')
 retained_path=BASE/'.coord/rapid-completion/retained-native-hard-caps-readonly-150.json'
 retained=json.loads(retained_path.read_bytes())
 if retained['scope']!='point-in-time-running-container-cap-census-not-RSS-or-capacity-release' or \
    retained['unboundedContainerCount']!=0:
  raise RuntimeError('Retained native hard-cap census absent or incomplete')
 qpath=BASE/'.coord/rapid-completion/q-d874-physical-terminal-readonly-126.json'
 q=json.loads(qpath.read_bytes())
 if not q['physicalTerminalProven'] or q['originalStopAcknowledged'] or q['capacityReleased']:
  raise RuntimeError('Q physical proof is not a separate non-ACK observation')
 qbundle=json.loads(Path('/mnt/media/p0-v3/release-generations/q-d874eb36057e/bundle.json').read_bytes())
 qreserve=qbundle['memoryReservationMiB']
 disposition=Path('/mnt/media/p0-v3/release-generations/q-d874eb36057e/quadlet-terminal-disposition.observation.json')
 qterminal=json.loads(disposition.read_bytes())
 if qterminal['generation']!='q-d874eb36057e' or qterminal['bundleSha256']!=SHA(
    Path('/mnt/media/p0-v3/release-generations/q-d874eb36057e/bundle.json')) or \
    len(qterminal['originalCids'])!=26 or len(qterminal['observedExitCodes'])!=26 or \
    qterminal['overlappingOriginalStopAndGuardian']!=['loki'] or \
    any(qterminal[field] for field in ('originalStopAcknowledged','originalServeAcknowledged',
     'originalIsolationAcknowledged','publicActivation')):
  raise RuntimeError('Separate historical physical capacity receipt absent or misbound; no ACK inference')
 jobs={}
 for kind,hard in [('job',None),('runner',256),('transport',128)]:
  p=CI/(kind+'.normalize.result.json');proof=json.loads(p.read_bytes())
  if proof.get('applicationStarted') or not proof['archiveSha256']==SHA(CI/(kind+'.oci.tar')):
   raise RuntimeError('Unauthenticated CI archive: '+kind)
  jobs[kind]={'hardMemoryCapMiB':hard,'configImageId':proof['imageId'],
    'selectedManifestDigest':proof['ociManifestDigest'],'archiveBytes':proof['archiveBytes'],
    'bindingReceiptSha256':SHA(p),'timing':'concurrent with whole stack' if kind!='job' else 'one job on demand'}
 old=graph['oldOnDemandReferences']
 if len(old)!=4:raise RuntimeError('OLD on-demand references changed')
 host_kib=int(next(row.split()[1] for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemTotal:')))
 steady=graph['steadyMemoryMiB'];shot=graph['maxSingleOneShotMiB']
 result={'schemaVersion':1,'scope':'complete-r9-declared-envelope-not-native-admission',
  'indexSha256':graph['indexSha256'],'manifestSha256':graph['manifestSha256'],
  'physicalHostMemTotalMiB':host_kib//1024,
  'processRows':graph['processes'],'volumeRows':vols,'distinctPrivateNetworks':len(set(nets)),
  'residentHardCapsNotActualRss':{'rootfulSteadyMiB':steady,'rootfulSerializedInstallUpperMiB':steady+shot,
    'rootfulOneShotTotalNeverConcurrentMiB':graph['oneShotSumMiBNotConcurrent'],
    'ciRunnerMiB':256,'ciTransportMiB':128,'ciGuardMiB':256,
    'ciJobBoundMiB':{'min':512,'max':8192,'requiresFrozenEnrollment':True},
    'managedPhysicalWorklaneMiB':{'min':256,'max':65536,'requiresFrozenPlan':True},
    'managedVirtualTuiosPiAdditionalMiB':0,'managedBrokerMiB':256,
    'kopiaBackupWorkReservationMiB':{'min':1024,'exact':None,'requiresFrozenPhase':True}},
  'ciSourceArchiveBindings':jobs,
  'oldOnDemandReferencesNotAlwaysOn':old,
  'oldReferenceBytesVerified':graph['oldReferenceBytesVerified'],
  'oldReferenceAuthority':'pinned-r9-manifest-summary-only' if not graph['oldReferenceBytesVerified'] else 'durable-cache-source-sha-verified',
  'diskEnvelopeMiB':{'rootfulStateMinimumFrom59Volumes':len(vols)*1024,
    'ciJobDiskRange':[1024,32768],'ciRunnerAndTransportArchiveBytes':jobs['runner']['archiveBytes']+jobs['transport']['archiveBytes'],
    'ciJobArchiveBytes':jobs['job']['archiveBytes'],'managedPhysicalLaneDiskRange':[1024,1048576],
    'managedBrokerFixedDisk':128,'managedArchiveAndUnpackedBytes':None,
    'backupScratchAndNewStackCaptureMiB':None,'retainedGenerationsMiB':None,'headroomMiB':10240},
  'memoryEnvelopeMiB':{'headroom':16384,'steadyIncludingFixedCIAndManagedBrokerOnly':steady+256+128+256+256,
    'steadyMinimumOneManagedLaneWithGuardNoJob':steady+256+128+256+256+256,
    'steadyMinimumWithGuardAndOneJob':steady+256+128+256+256+256+512,
    'conservativeInstallWithGuardOneJobAndLargestShot':steady+shot+256+128+256+256+256+512,
    'allBoundedTogetherPlusHeadroom':steady+shot+256+128+256+256+256+512+16384,
    'exactFullReleaseTotal':None},
  'retainedObservedHardCaps':{'censusSha256':SHA(retained_path),
    'pointInTimeRunningContainers':retained['runningContainerCount'],
    'sumMiBNotMeasuredRSS':retained['configuredHardCapsSumMiB'],
    'unboundedContainerCount':retained['unboundedContainerCount'],
    'qD874OriginalReservationMiBSubjectToFreshAdmissionRecheck':qreserve,
    'qD874SeparatePhysicalExitObservationSha256':SHA(qpath),
    'qD874IndependentCapacityDispositionSha256':SHA(disposition),
    'qD874NativeUnitCidRecheckRequiredBeforeAccountingRelease':True,
    'qD874NativeRunningContainerCount':0,
    'caveat':'Historical retained original reservation is not a live RSS claim; admission must re-census under lock.'},
  'conservativeConfiguredCapEnvelopeMiB':{
    'retainedPlusFreshSteadyMinimumPlusHeadroomExcludingQIntent':retained['configuredHardCapsSumMiB']+steady+896+16384,
    'sameIncludingQUntilFreshAdmissionRecheck':retained['configuredHardCapsSumMiB']+qreserve+steady+896+16384,
    'notActualRssOrFrozenFullPeak':True},
  'notHardCaps':['CI guard configured systemd MemoryMax=256M requires effective native readback',
      'worklane managed physical lane not selected in frozen release plan',
      'job enrollment memory/disk not selected in frozen release plan',
      'backup scratch and worker work reservation requires capture plan',
      'retained generations and artifact staging must be included in admission',
      'OCI hard cap is not actual RSS or admission when native memory/swap policies are unknown'],
  'sourceProvenance':{'rootful':'audit_fresh_full_capacity.py + 41 pinned fragments',
    'ci':'ForgejoCiNativeUnits.kt: transport128 runner256 guard256, ForgejoRunnerWorkflowPreview.kt: job512..8192',
    'managed':'ManagedLaneRuntime.kt: physical lane256..65536 + broker256; TUIOS/PI virtual',
    'backup':'GenerationCapacityPlanner.kt: work.memoryMiB>=1024; scratch nonzero',
    'disk':'GenerationCapacityPlanner.kt: 1024MiB per volume minimum'}}
 print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
