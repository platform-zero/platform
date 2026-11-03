#!/usr/bin/env python3
"""Unit-only trace coverage for owned Hub runtime helpers; excludes all native/browser probes."""
if not __debug__:
    raise SystemExit('Unit coverage requires assertions enabled')
import sys
import threading
import trace
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'scripts'))
tracer = trace.Trace(count=True, trace=False)


def tests():
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in ('test_hub_agent', 'test_hub_config'))
    return unittest.TextTestRunner(verbosity=0).run(suite)


previous = threading.gettrace()
try:
    threading.settrace(tracer.globaltrace)
    result = tracer.runfunc(tests)
finally:
    threading.settrace(previous)
if not result.wasSuccessful():
    raise SystemExit('Hub unit tests failed')
for name in ('hub-agent.py', 'hub-config.py'):
    path = str(root / 'src/main/resources/runtime' / name)
    # Python 3.13 may include None line entries for artificial bytecode positions.
    executable = {line for line in trace._find_executable_linenos(path) if isinstance(line, int) and line > 0}
    executed = {line for (filename, line), count in tracer.results().counts.items() if filename == path and count}
    covered = len(executed & executable)
    print(f'{name}: {covered}/{len(executable)} executable lines ({100 * covered / len(executable):.2f}%), unit only')
    if covered / len(executable) < 0.90:
        raise SystemExit('Hub runtime unit coverage below 90%')
