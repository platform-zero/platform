package net.datamancy.platform

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Native Pi SDK result -> Responses SSE frames consumed by the *installed* Pi
 * openai-responses parser. No fabricated upstream receipt: this only runs after
 * an acknowledged Pi provider result and live lane/issuer revocation readback.
 */
internal object ManagedPiSubscriptionResponse {
    fun sse(bytes:ByteArray):ByteArray {
        val value=Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(value["object"]?.jsonPrimitive?.content=="response" &&
            value["status"]?.jsonPrimitive?.content=="completed" &&
            value["model"]?.jsonPrimitive?.content=="gpt-6-sol")
        val output=value.getValue("output").jsonArray
        require(output.size<=128)
        val frames=StringBuilder()
        fun frame(item:JsonObject) { frames.append("data: ").append(item.toString()).append("\n\n") }
        frame(buildJsonObject { put("type","response.created");put("response",value) })
        output.forEachIndexed { index, item ->
            val content=item.jsonObject
            require(content["type"]?.jsonPrimitive?.content in setOf("message","reasoning","function_call"))
            frame(buildJsonObject { put("type","response.output_item.added");put("output_index",index);put("item",content) })
            frame(buildJsonObject { put("type","response.output_item.done");put("output_index",index);put("item",content) })
        }
        frame(buildJsonObject { put("type","response.completed");put("response",value) })
        frames.append("data: [DONE]\n\n")
        return frames.toString().toByteArray()
    }
}
