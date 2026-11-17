package net.datamancy.platform

import kotlin.test.*

class ForgejoLocalWorkflowSourceTest {
    private val imageId = "a".repeat(64)
    private val image = "localhost/p0v3-local-job@sha256:$imageId"
    private val commit = "b".repeat(40)
    private val workflow = """name: reviewed-local
on: workflow_dispatch
permissions:
  contents: read
jobs:
  reviewed:
    runs-on: p0v3-rootless-oci
    container:
      image: $image
    timeout-minutes: 10
    steps:
      - name: Local tool
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p artifacts
          printf 'fixture\\n' > artifacts/fixture.txt
""".toByteArray()
    private val enrollment = TrustedForgejoWorkflowEnrollment("private/trusted-repo",
        ReleaseLocks.sha256(workflow), commit, image, imageId, 784, 2048, 8192)

    @Test fun `exact local workflow needs no third party action mirrors`() {
        val reviewed = ForgejoWorkflowSource.inspect(enrollment, commit, workflow)
        assertEquals(image, reviewed.pinnedJobImage)
        assertFalse(reviewed.jobExecuted)
        assertFails { ForgejoWorkflowSource.inspect(enrollment.copy(workflowSha256 = "0".repeat(64)), commit, workflow) }
        assertFails { ForgejoWorkflowSource.inspect(enrollment, "c".repeat(40), workflow) }
    }

    @Test fun `local fixture cannot smuggle uses or altered image`() {
        val uses = workflow.decodeToString().replace("        run: |", "        uses: https://example.invalid/action@main\n        run: |")
            .toByteArray()
        assertFails { ForgejoWorkflowSource.inspect(enrollment.copy(workflowSha256 = ReleaseLocks.sha256(uses)), commit, uses) }
        val changed = workflow.decodeToString().replace(image, "localhost/other@sha256:$imageId").toByteArray()
        assertFails { ForgejoWorkflowSource.inspect(enrollment.copy(workflowSha256 = ReleaseLocks.sha256(changed)), commit, changed) }
    }
}
