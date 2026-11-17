package net.datamancy.platform

/** Runner configuration for one repository-scoped EPHEMERAL native job. The
 * source alone neither registers a runner nor authorizes a job create: the
 * rootless socket guard and effective native-image readback are still required.
 */
internal object ForgejoRunnerConfigSource {
    fun config(enrollment: TrustedForgejoWorkflowEnrollment, review: ForgejoWorkflowReview,
        registrationPath: String): String {
        require(review == ForgejoRunnerWorkflowPreview.review(enrollment, ForgejoWorkflowJobShape(
            enrollment.repository, enrollment.workflowSha256, enrollment.trustedCommit,
            "p0v3-rootless-oci", enrollment.jobImage, jobsContainerOverride = enrollment.jobImage)) &&
            registrationPath.matches(Regex("/home/webservices-lab-ci-runner/\\.local/share/p0v3-ci/q-[a-f0-9]{12}/\\.runner")) &&
            enrollment.jobImageId.matches(Regex("[a-f0-9]{64}")))
        val memoryBytes = Math.multiplyExact(enrollment.memoryMiB.toLong(), 1048576L)
        return """
            log:
              level: warn
              job_level: info
            runner:
              file: $registrationPath
              capacity: 1
              timeout: 30m
              labels:
                - p0v3-rootless-oci:docker://${enrollment.jobImage}
            cache:
              enabled: false
            container:
              network: "p0v3-ci-${registrationPath.substringAfter("p0v3-ci/").substringBefore('/')}-internal"
              privileged: false
              valid_volumes:
                - /home/webservices-lab-ci-runner/.local/share/p0v3-ci/${registrationPath.substringAfter("p0v3-ci/").substringBefore('/')}/transport-ca.pem
              docker_host: "-"
              options: "--memory=${memoryBytes} --memory-swap=${memoryBytes} --cpus=2 --pids-limit=256 --user=1000:1000 --cap-drop=ALL --security-opt=no-new-privileges --volume=/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${registrationPath.substringAfter("p0v3-ci/").substringBefore('/')}/transport-ca.pem:/etc/ssl/certs/p0v3-ci-forgejo-ca.pem:ro --env=SSL_CERT_FILE=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem --env=GIT_SSL_CAINFO=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem --env=NODE_EXTRA_CA_CERTS=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem --env=CURL_CA_BUNDLE=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem"
        """.trimIndent() + "\n"
    }
}
