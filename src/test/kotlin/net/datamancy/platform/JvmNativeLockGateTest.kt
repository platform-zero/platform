package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JvmNativeLockGateTest {
    @Test fun `second JVM thread fails fast without opening same POSIX locked inode`() {
        val path = Files.createTempFile("native-posix-guard-", ".lock")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val secondFinished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val secondFailure = AtomicReference<Throwable?>()
        val ownerPid = ProcessHandle.current().pid()
        val first = thread(name = "native-lock-original-owner") {
            try {
                JvmNativeLockGate.with(path) {
                    FileChannel.open(path, READ, WRITE).use { channel ->
                        channel.lock().use {
                            held.countDown()
                            assertTrue(release.await(15, TimeUnit.SECONDS))
                        }
                    }
                }
            } catch (e: Throwable) { failure.set(e); held.countDown() }
        }
        val second = thread(start = false, name = "native-lock-competing-thread") {
            try {
                JvmNativeLockGate.with(path) {
                    FileChannel.open(path, READ, WRITE).use { channel ->
                        channel.lock().use { error("Competing thread acquired an overlapping lock") }
                    }
                }
            } catch (e: Throwable) { secondFailure.set(e) }
            finally { secondFinished.countDown() }
        }
        try {
            assertTrue(held.await(10, TimeUnit.SECONDS))
            assertEquals(null, failure.get())
            second.start()
            assertTrue(secondFinished.await(3, TimeUnit.SECONDS))
            assertTrue(secondFailure.get() is OverlappingFileLockException)
            assertTrue(QuadletNativeLockProof.heldBy(path, ownerPid))
            assertEquals(null, failure.get())
            release.countDown()
            first.join(5_000)
            assertFalse(QuadletNativeLockProof.heldBy(path, ownerPid))
            JvmNativeLockGate.with(path) {
                FileChannel.open(path, READ, WRITE).use { channel ->
                    channel.lock().use { assertTrue(QuadletNativeLockProof.heldBy(path, ownerPid)) }
                }
            }
        } finally {
            release.countDown()
            first.join(15_000); if (second.state != Thread.State.NEW) second.join(15_000)
            Files.deleteIfExists(path)
        }
    }
}
