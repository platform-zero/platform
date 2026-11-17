package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal enum class FragmentTemplateFormat { INI, LITERAL }
@Serializable internal enum class FragmentValueKind { HEX64, BASE64_32, BASE64URL_32 }
@Serializable internal data class FragmentTemplateSpec(
    val output: String, val resource: String, val format: FragmentTemplateFormat,
    val parameters: Map<String, FragmentValueKind>, val constants: Map<String, String> = emptyMap())

/** Pure rendering, used only with an immutable packaged template. Returned bytes can contain secrets:
 * callers must keep them inside protected preparation; never include them in assembly/export reports.
 */
internal object FragmentTemplates {
    private val placeholder = Regex("\\{\\{([A-Z][A-Z0-9_]{0,63})}}")
    private val name = Regex("[A-Z][A-Z0-9_]{0,63}")
    private val atom = Regex("[a-z][a-z0-9_]{0,62}")

    fun validate(spec: FragmentTemplateSpec, text: String) {
        require(text.length <= FragmentYaml.MAX_BYTES &&
            (spec.format == FragmentTemplateFormat.INI ||
                (spec.format == FragmentTemplateFormat.LITERAL && spec.parameters.isEmpty() && spec.constants.isEmpty())))
        require(spec.parameters.keys.all(name::matches) && spec.constants.keys.all(name::matches))
        require(spec.constants.values.all(atom::matches) && spec.parameters.keys.intersect(spec.constants.keys).isEmpty())
        val found = placeholder.findAll(text).map { it.groupValues[1] }.toSet()
        require(found == spec.parameters.keys + spec.constants.keys) { "Template parameter closure mismatch" }
        val literal = placeholder.replace(text, "")
        require("{{" !in literal && "}}" !in literal && '\u0000' !in literal) { "Invalid template placeholder" }
    }

    fun render(fragment: PackagedGraphFragment, output: String, values: Map<String, String>): String {
        val spec = fragment.definition.templates.single { it.output == output }
        val text = fragment.template(spec.resource)
        validate(spec, text)
        require(values.keys == spec.parameters.keys) { "Template input closure mismatch" }
        spec.parameters.forEach { (key, kind) ->
            require(when (kind) {
                FragmentValueKind.HEX64 -> values.getValue(key).matches(Regex("[a-f0-9]{64}"))
                FragmentValueKind.BASE64_32 -> runCatching {
                    val raw = java.util.Base64.getDecoder().decode(values.getValue(key))
                    raw.size == 32 && java.util.Base64.getEncoder().encodeToString(raw) == values.getValue(key)
                }.getOrDefault(false)
                FragmentValueKind.BASE64URL_32 -> runCatching {
                    val raw = java.util.Base64.getUrlDecoder().decode(values.getValue(key))
                    raw.size == 32 && java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw) == values.getValue(key)
                }.getOrDefault(false)
            }) { "Invalid typed template value" }
        }
        val substitutions = values + spec.constants
        // Lambda replacement is literal, never regex replacement-string or shell expansion.
        return placeholder.replace(text) { substitutions.getValue(it.groupValues[1]) }
    }
}
