package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

/** Native rootless VFS contains subuid-owned directories; a host-owner walk
 * cannot establish its size. This is a bounded root-scoped metadata ONLY
 * readback, under the generation native lock and exact selected graph root. */
internal object RootlessVfsGraphCensus {
    fun observe(graph:Path,bound:Long):JsonObject {
        val generation=graph.parent.parent.parent.parent.parent.fileName.toString()
        val isolated=generation==WorklaneFullPrepareReturnProbe.generation
        require(isolated || generation in setOf("q-c3a7a9e29391",
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation))
        val expected=(if(isolated) WorklaneFullPrepareReturnProbe.base else GenerationRuntime.BASE.resolve(generation))
            .resolve("managed/control/data/containers/storage")
        require(graph==expected && bound==34359738368L &&
            Files.isDirectory(graph,NOFOLLOW_LINKS) && graph.toRealPath()==graph)
        val script="""import hashlib,json,os,stat
root='${expected}'
assert os.path.realpath(root)==root and stat.S_ISDIR(os.lstat(root).st_mode)
assert os.lstat(root).st_uid==int(os.environ['SUDO_UID'])
h=hashlib.sha256();n=0;bytes=0;links=0
pending=[(root,'')]
while pending:
 path,rel=pending.pop();s=os.lstat(path);n+=1
 assert n<=4000000 and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode))
 bytes+=s.st_blocks*512
 assert 0<=bytes<=34359738368
 if stat.S_ISLNK(s.st_mode): links+=1
 h.update((rel+'|'+str(s.st_mode)+'|'+str(s.st_uid)+'|'+str(s.st_gid)+'|'+str(s.st_size)+'|'+str(s.st_blocks)+'\n').encode())
 if stat.S_ISDIR(s.st_mode):
  with os.scandir(path) as directory: children=sorted(directory,key=lambda e:e.name,reverse=True)
  for e in children:
   assert e.name not in ('.','..') and '/' not in e.name
   pending.append((e.path,rel+'/'+e.name))
assert n>1
print(json.dumps({'sha256':h.hexdigest(),'allocatedBytes':bytes,'entries':n,'symlinks':links},sort_keys=True))
""".trimIndent()
        val child=ProcessBuilder("/usr/bin/sudo","-n","/usr/bin/python3","-I","-c",script)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val bytes=child.inputStream.readNBytes(8193)
        require(child.waitFor(90,TimeUnit.SECONDS) && child.exitValue()==0 && bytes.size in 64..8192)
        return Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject.also {
            require(it.keys==setOf("sha256","allocatedBytes","entries","symlinks") &&
                it.getValue("sha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
                it.getValue("allocatedBytes").jsonPrimitive.long in 1..bound &&
                it.getValue("entries").jsonPrimitive.long in 2..4000000L &&
                it.getValue("symlinks").jsonPrimitive.long in 0..it.getValue("entries").jsonPrimitive.long)
        }
    }
}
