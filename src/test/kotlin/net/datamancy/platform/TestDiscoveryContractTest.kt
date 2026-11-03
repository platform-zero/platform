package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class TestDiscoveryContractTest {
    @Test fun `annotated tests cannot silently disappear through inferred non-void return types`() {
        val classes = Path.of(javaClass.protectionDomain.codeSource.location.toURI())
        val packageRoot = classes.resolve("net/datamancy/platform")
        val invalid = Files.walk(packageRoot).use { paths ->
            paths.filter { it.toString().endsWith(".class") }.toList().flatMap { path ->
                val name = classes.relativize(path).toString().removeSuffix(".class").replace('/', '.')
                // Metadata inspection only: no constructors, initializers, test methods or native
                // integration probes are executed by this check.
                Class.forName(name, false, javaClass.classLoader).declaredMethods.filter { method ->
                    method.annotations.any { it.annotationClass.java.name in setOf("org.junit.jupiter.api.Test", "org.junit.Test") } &&
                        method.returnType != Void.TYPE
                }.map { "$name.${it.name}: ${it.returnType.name}" }
            }.sorted()
        }
        assertTrue(invalid.isEmpty(), "JUnit would silently omit annotated non-void tests:\n" + invalid.joinToString("\n"))
    }
}
