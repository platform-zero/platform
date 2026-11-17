package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import com.sun.security.auth.module.UnixSystem
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** A SECOND, distinct failed effect: CI and two source issuers completed, but the
 * selected member generated no inputs. Neither earlier failed result is repaired.
 */
@Serializable internal data class CiMemberPreEffectDisposition(val schemaVersion: Int = 1,
    val generation: String, val firstDispositionSha256: String, val secondFailedIntentSha256: String,
    val secondFailedResultSha256: String, val secondOwnershipSha256: String,
    val memberAttemptIntentSha256: String, val priorReadOnlyCensusSha256: String,
    val ciSourceSha256: Map<String,String>, val freshIssuerSha256: Map<String,String>,
    val memberRootLockOnly: Boolean = true, val originalPassed: Boolean = false)

internal object GenerationCiMemberPreEffectContinuation {
    const val FILE = "assembly-ci-member-pre-effect.disposition.json"
    const val INTENT = "assembly-ci-member-v3.intent.json"
    const val RESULT = "assembly-ci-member-v3.result.json"
    const val OWNERSHIP = "ownership-ci-member-v3.intent.json"
    private const val CENSUS = "1af2cc94f6f2181d9e86eb6a3db89b11744d8a55f479b1b3d6f320186a397755"
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val ci = mapOf(
        "account-stage.py" to "d340b0d6f66039df9f220047838db4dca13563086d4bbd3e337f1fff7880a8e8",
        "guard-config.json" to "d25abfc04d3a63177636aecb6f4b0026a21cecb56425267e36f84701f27674a2",
        "guard.py" to "a0c21151426ad1990610faf2bd36f9097939985017f947cb53a8b42aee11851a",
        "guard.sha256" to "53e5a4d5aa869706f1504d98731697125d95bee3e062ef0befdeaee56ba65468",
        "runner-config.yaml" to "69a1f3e51342f723347f26ed7596946dda9f82bf382cfcc9dcd8452cab9c3a8b",
        "transport-ca.pem" to "78988bd9dc0f2c0b4d9ef03bb72cd4057a4def429d001d932e56a87177f8161b",
        "transport-leaf-key.pem" to "375f58efb1cdf3be992191e8dc1d710eed868f436f149f87757c3da7fe7cdfff",
        "transport-leaf.pem" to "01b8471d97e7ff48f79e287f1806613ac361b3177459ef113249836f301b5216",
        "transport-upstream.pending.json" to "f79ce476a7486e069b4e6ffbaf3ddc3ddf4042dc281c8e1afb7f74d199d07d0b",
        "unit-p0v3-ci-q-5962a9fda75b-egress.network" to "7e6086a8d44bea0aaa2d5b886de673270feb57a2c19968a5078495b69de3969f",
        "unit-p0v3-ci-q-5962a9fda75b-guard.service" to "db9b568994bcca6390435947aab1eca389dfa21a3bc12f9077bdd573820ccfa4",
        "unit-p0v3-ci-q-5962a9fda75b-internal.network" to "85725c78b5e8b80ed6da0aada9851c2e3e55e11caecd33a15d2795d5a2950802",
        "unit-p0v3-ci-q-5962a9fda75b-runner.container" to "b2b31b3699e3add0545e27a061ba9d7820fff106a9c9858e3bd54e602bfd9aa0",
        "unit-p0v3-ci-q-5962a9fda75b-transport.container" to "2f1ca35c1716b888580a4579074e1da66eacfe51dd067ccd32348fe2e0436006",
        "workflow.sha256" to "2a6819c769a5d1d82d3a7763feb05394d4bee9f86c364269a862a1a72ac586f5")
    private val issuers = mapOf(
        "/mnt/media/p0-v3/release-bootstrap-anchors/ingress/fresh/q-5962a9fda75b.json" to
            "c0d9e1517816146f72926a23b0a8549848c8d2361f9de07ccb1390efb86d02d4",
        "/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/q-5962a9fda75b.json" to
            "b07113874ac17e732b558abb7587fbd8932f57c7d4d55c71daf2a7408bf2f69e")
    private val effect = mapOf(
        GenerationCiPreEffectContinuation.INTENT to "6ab14bfcb3e126bb27474c67380cc008600e726165b9d38abaa9ddada9f96dea",
        GenerationCiPreEffectContinuation.RESULT to "29872f8dc2b6bd9bbe6b7580de3f01558e01eb3940b6e333dccdb9e7dc625492",
        GenerationCiPreEffectContinuation.OWNERSHIP to "730cb4e69d53fe32fcca8c592f6380aad126fc5ede40c419865f0d8e1766b780",
        "q-5962a9fda75b-v2.prepare-ci-pre-effect-v2.intent.json" to "d72720bd2c544691d521354ec81c957cebe2363cc8a7861894f5a3c4826defc6")
    private fun children(root:Path): Set<String> = Files.list(root).use { stream -> stream.map { it.fileName.toString() }.toList().toSet() }
    private fun sha(path:Path) = ReleaseLocks.sha256(ReleasePrivateFiles.read(path,4194304))
    private fun verifyCiTls(root:Path) {
        val source=root.resolve("ci")
        fun certificate(file:String) = CertificateFactory.getInstance("X.509").generateCertificate(
            ReleasePrivateFiles.read(source.resolve(file),65536).inputStream()) as X509Certificate
        val ca=certificate("transport-ca.pem"); val leaf=certificate("transport-leaf.pem")
        ca.checkValidity();leaf.checkValidity()
        ca.verify(ca.publicKey);leaf.verify(ca.publicKey)
        require(ca.basicConstraints >= 0 && leaf.basicConstraints == -1 &&
            leaf.subjectAlternativeNames.filter { it[0] == 2 }.map { it[1] as String }.toSet() ==
                setOf("forgejo-ci","forgejo.datamancy.net")) { "Original CI CA/leaf or SAN differs" }
        val keyText=ReleasePrivateFiles.read(source.resolve("transport-leaf-key.pem"),65536).decodeToString(throwOnInvalidSequence = true)
        require(keyText.startsWith("-----BEGIN PRIVATE KEY-----") && keyText.trimEnd().endsWith("-----END PRIVATE KEY-----"))
        val privateKey=KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(
            keyText.substringAfter("-----BEGIN PRIVATE KEY-----").substringBefore("-----END PRIVATE KEY-----")))) as RSAPrivateCrtKey
        val publicKey=leaf.publicKey as RSAPublicKey
        require(privateKey.modulus == publicKey.modulus && privateKey.publicExponent == publicKey.publicExponent) {
            "Original CI leaf and private key do not form the issued pair"
        }
    }
    private fun verifyIssuers() {
        val binary=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142")
        val ingressPath=Path.of(issuers.keys.single { it.contains("/ingress/fresh/") })
        val ntfyPath=Path.of(issuers.keys.single { it.contains("/identity/ntfy-fresh/") })
        val ingress=FreshNativeIngressCustody.issueOnce(ingressPath,binary) {
            error("Immutable original ingress issuer cannot be replayed")
        }
        val ntfy=FreshNtfyCustody.issueOnce(ntfyPath,binary) {
            error("Immutable original ntfy issuer cannot be replayed")
        }
        require(FreshNativeIngressCustody.qbittorrentPassword(ingressPath,ingress).matches(Regex("[a-f0-9]{64}")) &&
            ntfy.ssoToken.matches(Regex("tk_[A-Za-z0-9]{32}")))
    }
    fun inspect(root:Path, memberRoot:Path, first:ActivationInput, beforeEffects:Boolean): CiMemberPreEffectDisposition {
        require(beforeEffects) { "This census is only valid before the new member operation intent" }
        require(root == GenerationRuntime.BASE.resolve(GenerationCiPreEffectContinuation.GENERATION) &&
            memberRoot == PrivateDeployment.BASE.resolve("q-5962a9fda75b-v2") &&
            first.path == root.resolve(GenerationCiPreEffectContinuation.FILE).toString())
        GenerationCiPreEffectContinuation.verify(root,first)
        val expectedRoot = setOf("assembly.intent.json", "assembly.result.json", "ownership.intent.json",
            "managed", "rss", "ci", GenerationCiPreEffectContinuation.FILE) + effect.keys +
            // The first read occurs before this disposition is saved; subsequent
            // pre-member-effect readbacks must allow *only* that exact saved file.
            (if (Files.exists(root.resolve(FILE),NOFOLLOW_LINKS)) setOf(FILE) else emptySet())
        require(children(root) == expectedRoot && children(root.resolve("ci")) == ci.keys &&
            ci.all { (file,hash) -> sha(root.resolve("ci/$file")) == hash } &&
            effect.all { (file,hash) -> sha(root.resolve(file)) == hash } &&
            issuers.all { (file,hash) -> sha(Path.of(file)) == hash } &&
            !Files.exists(PrivateDeployment.BASE.resolve("q-5962a9fda75b-v2.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("bundle.json"),NOFOLLOW_LINKS)) {
            "Unknown CI, issuer, member or bundle effect: cannot reattempt"
        }
        verifyCiTls(root)
        verifyIssuers()
        ReleasePrivateFiles.directory(memberRoot)
        val lock = memberRoot.resolve("runtime.lock")
        require(children(memberRoot) == setOf("runtime.lock") && Files.size(lock) == 0L &&
            Files.isRegularFile(lock,NOFOLLOW_LINKS) &&
            (Files.getAttribute(lock,"unix:uid",NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(lock,"unix:nlink",NOFOLLOW_LINKS) as Number).toInt() == 1 &&
            Files.getPosixFilePermissions(lock) == java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")) {
            "Member runtime input or foreign lock already exists"
        }
        val failed = json.decodeFromString<AssemblyPreparationOutcome>(ReleasePrivateFiles.read(root.resolve(
            GenerationCiPreEffectContinuation.RESULT)).decodeToString(throwOnInvalidSequence = true))
        require(!failed.passed && failed.bundleSha256 == null && failed.failureType == "java.lang.IllegalArgumentException" &&
            failed.assemblySha256 == effect.getValue(GenerationCiPreEffectContinuation.INTENT))
        val member = json.decodeFromString<AssemblyMemberIntent>(ReleasePrivateFiles.read(root.resolve(
            "q-5962a9fda75b-v2.prepare-ci-pre-effect-v2.intent.json")).decodeToString(throwOnInvalidSequence = true))
        require(member.assemblySha256 == failed.assemblySha256 && member.name == "q-5962a9fda75b-v2")
        return CiMemberPreEffectDisposition(generation = GenerationCiPreEffectContinuation.GENERATION,
            firstDispositionSha256 = first.sha256, secondFailedIntentSha256 = effect.getValue(GenerationCiPreEffectContinuation.INTENT),
            secondFailedResultSha256 = effect.getValue(GenerationCiPreEffectContinuation.RESULT),
            secondOwnershipSha256 = effect.getValue(GenerationCiPreEffectContinuation.OWNERSHIP),
            memberAttemptIntentSha256 = effect.getValue("q-5962a9fda75b-v2.prepare-ci-pre-effect-v2.intent.json"),
            priorReadOnlyCensusSha256 = CENSUS, ciSourceSha256 = ci, freshIssuerSha256 = issuers)
    }
    fun verify(root:Path,pin:ActivationInput, memberRoot:Path = PrivateDeployment.BASE.resolve("q-5962a9fda75b-v2"),
        beforeEffects:Boolean = false): CiMemberPreEffectDisposition {
        require(pin.path == root.resolve(FILE).toString())
        val bytes = ReleasePrivateFiles.read(root.resolve(FILE),4194304)
        require(ReleaseLocks.sha256(bytes) == pin.sha256)
        val saved = json.decodeFromString<CiMemberPreEffectDisposition>(bytes.decodeToString(throwOnInvalidSequence=true))
        if (beforeEffects) {
            require(saved == inspect(root,memberRoot,
                GenerationCiPreEffectContinuation.binding(root),true)) { "Pre-effect member disposition changed" }
        } else {
            GenerationCiPreEffectContinuation.verify(root,GenerationCiPreEffectContinuation.binding(root))
            require(saved.schemaVersion == 1 && saved.generation == GenerationCiPreEffectContinuation.GENERATION &&
                !saved.originalPassed && saved.memberRootLockOnly && saved.priorReadOnlyCensusSha256 == CENSUS &&
                saved.firstDispositionSha256 == GenerationCiPreEffectContinuation.binding(root).sha256 &&
                saved.ciSourceSha256 == ci && saved.freshIssuerSha256 == issuers &&
                saved.secondFailedIntentSha256 == effect.getValue(GenerationCiPreEffectContinuation.INTENT) &&
                saved.secondFailedResultSha256 == effect.getValue(GenerationCiPreEffectContinuation.RESULT) &&
                saved.secondOwnershipSha256 == effect.getValue(GenerationCiPreEffectContinuation.OWNERSHIP) &&
                saved.memberAttemptIntentSha256 == effect.getValue("q-5962a9fda75b-v2.prepare-ci-pre-effect-v2.intent.json") &&
                effect.all { (name,hash) -> sha(root.resolve(name)) == hash } &&
                children(root.resolve("ci")) == ci.keys && ci.all { (name,hash) -> sha(root.resolve("ci/$name")) == hash } &&
                issuers.all { (name,hash) -> sha(Path.of(name)) == hash }) {
                "Original failed member intent, CI or fresh source issuer changed"
            }
        }
        return saved
    }
    fun binding(root:Path):ActivationInput = ActivationInput(root.resolve(FILE).toString(),sha(root.resolve(FILE)))
}
