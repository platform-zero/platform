package net.datamancy.platform

import java.nio.channels.OverlappingFileLockException
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

/** Process-local gate BEFORE opening a POSIX-locked inode. On Linux, closing ANY
 * descriptor for that inode in the SAME process releases all its fcntl record locks,
 * even if another FileChannel/Java FileLock remains "valid". ThreadLocal reentry
 * checks alone do not prevent a second JVM thread opening and closing that inode.
 * This gate is not a substitute for the original OS lock or owner PID/start-tick proof.
 */
internal object JvmNativeLockGate {
    private val gates = ConcurrentHashMap<Path, ReentrantLock>()
    /** Ordinary admission fails immediately. A caller with an explicit short recovery
     * deadline may opt into a bounded wait, WITHOUT opening the competing inode.
     * The default eight-hour operation budget is not a contention wait authorization.
     */
    fun boundedAdmissionMillis(mustBeBound: Boolean): Long {
        if (!mustBeBound) return 0
        val left = RecoveryDeadline.remainingSecondsIfBound() ?: return 0
        return if (left <= 120) left * 1000 else 0
    }
    fun <T> with(path: Path, waitMillis: Long = 0, action: () -> T): T {
        require(path.isAbsolute && path == path.normalize() && waitMillis in 0..120_000)
        val gate = gates.computeIfAbsent(path) { ReentrantLock(true) }
        // Reject BEFORE opening an alias descriptor, even when the OS would accept
        // the open and then silently release the first process-owned POSIX lock.
        val admitted = if (waitMillis == 0L) gate.tryLock()
            else gate.tryLock(waitMillis, TimeUnit.MILLISECONDS)
        if (!admitted) throw OverlappingFileLockException()
        try {
            if (gate.holdCount != 1) throw OverlappingFileLockException()
            return action()
        } finally { gate.unlock() }
    }
}
