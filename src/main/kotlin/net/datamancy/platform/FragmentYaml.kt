package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.json.*
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.api.lowlevel.Parse
import org.snakeyaml.engine.v2.events.*
import org.snakeyaml.engine.v2.nodes.Tag
import org.snakeyaml.engine.v2.schema.JsonSchema

/** Syntax only. No constructors, includes, environment lookup or runtime authority.
 * Walk bounded parser events rather than composing an unbounded/alias-bearing object graph.
 * Errors deliberately omit parser excerpts and values: offline inputs may contain secrets.
 */
internal object FragmentYaml {
    const val MAX_BYTES = 1_048_576
    const val MAX_DEPTH = 32
    const val MAX_NODES = 65_536
    private val schema = JsonSchema()
    private val json = Json { ignoreUnknownKeys = false; isLenient = false; coerceInputValues = false }

    fun parse(bytes: ByteArray): JsonObject = sanitized {
        require(bytes.isNotEmpty() && bytes.size <= MAX_BYTES)
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        val settings = LoadSettings.builder().setSchema(schema).setAllowDuplicateKeys(false)
            .setAllowRecursiveKeys(false).setMaxAliasesForCollections(0).setCodePointLimit(MAX_BYTES).build()
        val reader = Reader(Parse(settings).parseString(text).iterator())
        reader.expect(Event.ID.StreamStart)
        val start = reader.expect(Event.ID.DocumentStart) as DocumentStartEvent
        require(start.tags.isEmpty() && start.specVersion.isEmpty)
        val root = reader.node(1)
        reader.expect(Event.ID.DocumentEnd)
        reader.expect(Event.ID.StreamEnd)
        require(!reader.events.hasNext())
        root as? JsonObject ?: throw IllegalArgumentException()
    }

    fun <T> decode(bytes: ByteArray, serializer: DeserializationStrategy<T>): T = sanitized {
        val document = parse(bytes)
        exactTypes(document, serializer.descriptor)
        json.decodeFromJsonElement(serializer, document)
    }

    private inline fun <T> sanitized(block: () -> T): T = try { block() }
        catch (_: Exception) { throw IllegalArgumentException("Invalid restricted fragment YAML") }

    private class Reader(val events: Iterator<Event>) {
        private var lookahead: Event? = null
        private var nodes = 0
        private fun peek(): Event = lookahead ?: events.next().also { lookahead = it }
        private fun take(): Event = peek().also { lookahead = null }
        fun expect(id: Event.ID): Event = take().also { require(it.eventId == id) }
        fun node(depth: Int): JsonElement {
            require(depth <= MAX_DEPTH && ++nodes <= MAX_NODES)
            val event = take()
            if (event is NodeEvent) require(event.anchor.isEmpty)
            if (event is CollectionStartEvent) require(event.tag.isEmpty)
            return when (event.eventId) {
                Event.ID.MappingStart -> {
                    val fields = linkedMapOf<String, JsonElement>()
                    while (peek().eventId != Event.ID.MappingEnd) {
                        val key = node(depth + 1) as? JsonPrimitive ?: throw IllegalArgumentException()
                        require(key.isString && key.content != "<<" && key.content !in fields)
                        fields[key.content] = node(depth + 1)
                    }
                    expect(Event.ID.MappingEnd)
                    JsonObject(fields)
                }
                Event.ID.SequenceStart -> {
                    val values = mutableListOf<JsonElement>()
                    while (peek().eventId != Event.ID.SequenceEnd) values.add(node(depth + 1))
                    expect(Event.ID.SequenceEnd)
                    JsonArray(values)
                }
                Event.ID.Scalar -> {
                    event as ScalarEvent
                    require(event.tag.isEmpty)
                    if (!event.isPlain) JsonPrimitive(event.value)
                    else when (schema.scalarResolver.resolve(event.value, true)) {
                        Tag.STR -> JsonPrimitive(event.value)
                        Tag.NULL -> JsonNull
                        Tag.BOOL, Tag.INT, Tag.FLOAT -> json.parseToJsonElement(event.value).also {
                            require(it is JsonPrimitive && !it.isString && it != JsonNull)
                        }
                        else -> throw IllegalArgumentException()
                    }
                }
                else -> throw IllegalArgumentException() // In particular, aliases are never accepted.
            }
        }
    }

    /** kotlinx's tree decoder accepts some quoted numbers/booleans. Reject coercion first. */
    @OptIn(ExperimentalSerializationApi::class)
    private fun exactTypes(value: JsonElement, type: SerialDescriptor) {
        if (value == JsonNull) { require(type.isNullable); return }
        when (type.kind) {
            StructureKind.CLASS -> {
                require(value is JsonObject)
                for ((key, child) in value) {
                    val index = type.getElementIndex(key)
                    require(index != CompositeDecoder.UNKNOWN_NAME)
                    exactTypes(child, type.getElementDescriptor(index))
                }
            }
            StructureKind.LIST -> {
                require(value is JsonArray)
                value.forEach { exactTypes(it, type.getElementDescriptor(0)) }
            }
            StructureKind.MAP -> {
                require(value is JsonObject && type.getElementDescriptor(0).kind == PrimitiveKind.STRING)
                value.values.forEach { exactTypes(it, type.getElementDescriptor(1)) }
            }
            PrimitiveKind.STRING, PrimitiveKind.CHAR, SerialKind.ENUM -> require(value is JsonPrimitive && value.isString)
            PrimitiveKind.BOOLEAN -> require(value is JsonPrimitive && !value.isString && value.booleanOrNull != null)
            PrimitiveKind.INT, PrimitiveKind.LONG, PrimitiveKind.SHORT, PrimitiveKind.BYTE ->
                require(value is JsonPrimitive && !value.isString && value.longOrNull != null)
            PrimitiveKind.FLOAT, PrimitiveKind.DOUBLE ->
                require(value is JsonPrimitive && !value.isString && value.doubleOrNull?.isFinite() == true)
            else -> throw IllegalArgumentException("Unsupported fragment field type")
        }
    }
}
