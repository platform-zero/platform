plugins {
    kotlin("jvm") version "2.2.20"
    kotlin("plugin.serialization") version "2.2.20"
    application
    jacoco
}

repositories { mavenCentral() }

kotlin { jvmToolchain(21) }

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}

application { mainClass.set("net.datamancy.platform.MainKt") }
// Keep archive metadata/order from changing the candidate identity on an unchanged rebuild.
tasks.withType<org.gradle.api.tasks.bundling.AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
// Unit imports may create local Python caches; these are not runtime source artifacts.
tasks.processResources { exclude("**/__pycache__/**", "**/*.pyc") }
tasks.test {
    // Unit-only even when an integration opt-in variable leaks from the parent shell.
    exclude("**/*RealIntegrationTest*")
    useJUnitPlatform { excludeTags("native", "integration", "real-domain", "sandbox-web") }
    finalizedBy(tasks.jacocoTestReport)
}

tasks.register<Test>("nativeIntegrationTest") {
    description = "Explicit opt-in native checks; never part of test/check or unit coverage"
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    include("**/*RealIntegrationTest*")
    useJUnitPlatform()
    onlyIf { providers.gradleProperty("nativeIntegration").orNull == "true" }
}

jacoco { toolVersion = "0.8.13" }
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.jacocoTestReport)
    violationRules {
        rule {
            element = "BUNDLE"
            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}
tasks.check { dependsOn(tasks.jacocoTestCoverageVerification) }
