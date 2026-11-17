#!/usr/bin/env python3
"""Derive SUJ 8.1.0 rendered Lua from exact selected OCI bytes, offline.

Faithfully implements the pinned Template#render/include_partial expansion only
for verified literal partial calls; rejects any other ERB code. No Ruby execution,
Redis SCRIPT LOAD, app startup, script injection or native RSS acceptance.
"""
import hashlib,json,pathlib,re,tarfile,os,fcntl,stat
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b')
ARCH=ROOT/'mastodon-script-source.oci.tar'
OUT=ROOT/'mastodon-rendered-lua-source.json'
PREFIX='usr/local/bundle/gems/sidekiq-unique-jobs-8.1.0/lib/sidekiq_unique_jobs/lua/'
PART=re.compile(r'<%=\s*include_partial\s+[\'\"](shared/[a-z_]+\.lua)[\'\"]\s*%>')
ANY=re.compile(r'<%.*?%>',re.S)
def sha(value):return hashlib.sha256(value).hexdigest()
def filehash(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
def write(path,value):
 if path.exists() or path.is_symlink():raise RuntimeError('Rendered Lua source already issued; no replacement')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def main():
 with (ROOT/'control.lock').open('a+b') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  if OUT.exists() or OUT.is_symlink():raise RuntimeError('Existing or uncertain rendered source')
  manifest=json.loads((ROOT/'mastodon-script-export-custody.result.json').read_bytes())
  assert manifest['originalExportAcknowledged'] and not manifest['renderedScriptsProven']
  assert manifest['archiveSha256']==filehash(ARCH)
  files={}
  with tarfile.open(ARCH,'r:') as outer:
   index=json.load(outer.extractfile('index.json'))
   source=json.load(outer.extractfile('blobs/sha256/'+index['manifests'][0]['digest'].split(':')[1]))
   assert len(source['layers']) in range(1,128)
   for layer in source['layers']:
    entry=outer.getmember('blobs/sha256/'+layer['digest'].split(':')[1])
    stream=outer.extractfile(entry)
    mode='r|gz' if layer['mediaType'].endswith('gzip') else 'r|'
    with tarfile.open(fileobj=stream,mode=mode) as payload:
     for item in payload:
      if item.name.startswith(PREFIX) and item.name.endswith('.lua') and item.isfile():
       name=item.name.removeprefix(PREFIX)
       if not re.fullmatch(r'(?:shared/)?[a-z_]+\.lua',name) or item.size>8192 or name in files:
        raise RuntimeError('Ambiguous or unbounded pinned Lua source')
       files[name]=payload.extractfile(item).read()
  scripts={name for name in files if not name.startswith('shared/')}
  assert len(scripts) in range(8,33) and len(files)-len(scripts) in range(4,25)
  def render(name,seen):
   if name not in files:raise RuntimeError('Lua template includes missing pinned file')
   text=files[name].decode('utf-8')
   for match in ANY.finditer(text):
    if not PART.fullmatch(match.group()):raise RuntimeError('Unreviewed dynamic ERB in pinned Lua')
   def include(match):
    relative=match.group(1)
    if relative in seen:return '' # pinned Template#@partial_templates memoizes per script
    seen.add(relative)
    return render(relative,seen)
   return PART.sub(include,text)
  rows={}
  for name in sorted(scripts):
   value=render(name,set()).encode('utf-8')
   rows[hashlib.sha1(value).hexdigest()]=sha(value)
  assert len(rows)==len(scripts)
  output={'schemaVersion':1,'generation':'q-5962a9fda75b',
   'scope':'source-only-rendered-suj-lua-from-exact-selected-oci-not-native-script-load',
   'archiveSha256':manifest['archiveSha256'],'exportCustodyResultSha256':sha((ROOT/'mastodon-script-export-custody.result.json').read_bytes()),
   'versions':['mastodon-4.7.4','sidekiq-8.1.6','sidekiq-unique-jobs-8.1.0','sidekiq-scheduler-6.0.2'],
   'imageManifestSha256':manifest['ociManifestDigest'].removeprefix('sha256:'),
   'sourceFiles':{name:sha(value) for name,value in sorted(files.items())},
   'renderedSha256':rows,'nativeScriptLoadObserved':False,'qualificationEvidence':False}
  write(OUT,(json.dumps(output,sort_keys=True,separators=(',',':'))+'\n').encode())
  print('Rendered SUJ scripts source-bound:',len(rows),'no Redis or application started')
if __name__=='__main__':main()
