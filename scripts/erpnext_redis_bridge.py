#!/usr/bin/env python3
"""Source-review entrypoint for the ONE packaged ERP bridge implementation.

Production reads /runtime/erpnext_redis_bridge.py from the platform JAR. This
wrapper is for injected source unit tests only; it never runs at import time.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import asyncio
import importlib.util
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / 'src/main/resources/runtime/erpnext_redis_bridge.py'
SPEC = importlib.util.spec_from_file_location('p0v3_erp_native_redis_source', SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('Missing fixed packaged ERP bridge source')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# Intentionally delegate all policy and protocol to the packaged source, without
# maintaining another copy of its allowlist, Lua, credential or relay behavior.
frame = MODULE.frame
request = MODULE.request
permitted = MODULE.permitted
client_connected = MODULE.client_connected
verify_pinned_image = MODULE.verify_pinned_image
RQ_EMPTY = MODULE.RQ_EMPTY
RQ_EMPTY_SHA = MODULE.RQ_EMPTY_SHA

if __name__ == '__main__':
    asyncio.run(MODULE.main())
