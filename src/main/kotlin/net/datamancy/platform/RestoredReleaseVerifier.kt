package net.datamancy.platform

/** Read-only boundary, independent of the actor that runs and tears down restored cases.
 * Production reopens the original scope and aggregate/case evidence on every call. This
 * dependency is constructor-only, never selected by a serialized release request. Unit
 * orchestration fixtures can replace it without touching the production evidence roots. */
internal fun interface RestoredReleaseVerifier {
    fun verify(proof: ActivationInput, invocation: ReleaseAcceptanceInvocation, operation: String,
        source: ReleaseGeneration, target: ReleaseGeneration, ownedUpdate: Boolean)

    companion object {
        val NATIVE = RestoredReleaseVerifier { proof, invocation, operation, source, target, ownedUpdate ->
            RestoredAggregateEvidence.read(proof, QualificationOwnerControl.scope(invocation, operation),
                operation, source, target, ownedUpdate)
            Unit
        }
    }
}
