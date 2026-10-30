package net.datamancy.platform

import kotlin.system.exitProcess

fun main(args: Array<String>) {
    try {
        val catalog = ServiceCatalog.bundled()
        when (args.toList()) {
            listOf("catalog", "validate") ->
                println("Inventory valid: ${catalog.serviceIds.size} IDs in ${catalog.modules.size} known modules; no installation or acceptance claimed")
            listOf("catalog", "list") ->
                catalog.modules.forEach { module ->
                    module.services.forEach { service -> println("${module.id}\t$service\tinventory-only") }
                }
            else -> {
                System.err.println("Usage: platform catalog validate|list")
                exitProcess(2)
            }
        }
    } catch (e: IllegalArgumentException) {
        System.err.println("Catalog rejected: ${e.message}")
        exitProcess(1)
    }
}
