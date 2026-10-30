package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LaneAccountsTest {
    private val issuer = "https://sso.example.test/realms/v3"
    private val humans = listOf(HumanLaneSubject("opaque-human-b", "p0v3_bob"), HumanLaneSubject("opaque-human-a", "p0v3_alice"))
    private fun request() = LaneAccountRequest(1, "scratch", issuer, humans, listOf("opaque-agent-a"))

    @Test fun `plan is stable human-only and never grants or removes app capabilities`() {
        val before = request()
        val plan = LaneAccounts.plan(before, issuer, setOf("root", "gerald", "software_lab"))
        assertEquals(listOf("p0v3_alice", "p0v3_bob"), plan.accounts.map { it.username })
        assertEquals(listOf("opaque-human-a", "opaque-human-b"), plan.accounts.map { it.subject })
        assertTrue(plan.accounts.all { it.issuer == issuer })
        assertFalse(plan.toString().contains("opaque-agent-a"))
        assertEquals(plan, LaneAccounts.plan(before.copy(humans = humans.reversed()), issuer, setOf("root")))
        assertEquals(before, request()) // planner did not mutate source identities
    }

    @Test fun `issuer is independently trusted and exact`() {
        for (bad in listOf("http://sso.example.test/realms/v3", "https://user@sso.example.test/realms/v3", "https://sso.example.test/realms/v3?x=y", "https://sso.example.test/realms/v3/")) {
            assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(issuer = bad), bad, emptySet()) }
        }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(issuer = "https://evil.example.test/realms/v3"), issuer, emptySet()) }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request(), "https://other.example.test", emptySet()) }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request(), "%%%", emptySet()) }
    }

    @Test fun `subjects cannot be reused across humans and agents`() {
        assertFailsWith<IllegalArgumentException> {
            LaneAccounts.plan(request().copy(agentSubjects = listOf("opaque-human-a")), issuer, emptySet())
        }
        assertFailsWith<IllegalArgumentException> {
            LaneAccounts.plan(request().copy(humans = humans + HumanLaneSubject("opaque-human-a", "p0v3_carol")), issuer, emptySet())
        }
        assertFailsWith<IllegalArgumentException> {
            LaneAccounts.plan(request().copy(humans = listOf(humans[0].copy(subject = "bad\nsubject"))), issuer, emptySet())
        }
        assertFailsWith<IllegalArgumentException> {
            LaneAccounts.plan(request().copy(agentSubjects = listOf("bad subject")), issuer, emptySet())
        }
    }

    @Test fun `names are confined and checked against reserved and occupied inventory`() {
        for (name in listOf("gerald", "software_lab", "root", "p0v3_root", "p0v3_agent", "p0v3_gerald", "p0v3_${"x".repeat(25)}", "p0v3_bad;useradd", "p0v3_-bad")) {
            assertFailsWith<IllegalArgumentException> {
                LaneAccounts.plan(request().copy(humans = listOf(HumanLaneSubject("human", name))), issuer, emptySet())
            }
        }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request(), issuer, setOf("p0v3_alice")) }
        assertFailsWith<IllegalArgumentException> {
            LaneAccounts.plan(request().copy(humans = listOf(humans[0], humans[1].copy(username = "p0v3_bob"))), issuer, emptySet())
        }
    }

    @Test fun `invalid scope and empty or unbounded mappings are refused`() {
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(schemaVersion = 2), issuer, emptySet()) }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(siteId = "../host"), issuer, emptySet()) }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(humans = emptyList()), issuer, emptySet()) }
        assertFailsWith<IllegalArgumentException> { LaneAccounts.plan(request().copy(agentSubjects = List(129) { "agent-$it" }), issuer, emptySet()) }
    }

    @Test fun `strict offline file inputs feed CLI plan without looking at host accounts`() {
        val config = Files.createTempFile("p0v3-lane-", ".json")
        val occupied = Files.createTempFile("p0v3-occupied-", ".json")
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        try {
            Files.writeString(config, """{"schemaVersion":1,"siteId":"scratch","issuer":"$issuer","humans":[{"subject":"opaque-human-a","username":"p0v3_alice"}],"agentSubjects":["opaque-agent-a"]}""")
            Files.writeString(occupied, """["root","gerald","software_lab"]""")
            assertEquals(setOf("root", "gerald", "software_lab"), LaneAccounts.occupiedFrom(occupied))
            assertEquals(0, runCommand(arrayOf("lane", "plan", config.toString(), issuer, occupied.toString()), output::add, errors::add))
            assertTrue(output.single().contains("p0v3_alice"))
            assertFalse(output.single().contains("opaque-agent-a"))
            assertTrue(errors.isEmpty())
            Files.writeString(occupied, """["root","root"]""")
            assertFailsWith<IllegalArgumentException> { LaneAccounts.occupiedFrom(occupied) }
            Files.writeString(occupied, """["invalid name"]""")
            assertFailsWith<IllegalArgumentException> { LaneAccounts.occupiedFrom(occupied) }
            Files.writeString(occupied, "[]")
            assertFailsWith<IllegalArgumentException> { LaneAccounts.occupiedFrom(occupied) }
            Files.writeString(config, Files.readString(config).replace("\"agentSubjects\"", "\"secret\""))
            assertFailsWith<Exception> { LaneAccountRequest.from(config) }
        } finally {
            Files.delete(config)
            Files.delete(occupied)
        }
    }
}
