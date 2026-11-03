#!/usr/bin/env python3
"""Unit-only coverage for the owned mail initializer, excluding native probes."""
if not __debug__:
    raise SystemExit('Unit coverage requires assertions enabled')
import sys
import trace
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'scripts'))
tracer = trace.Trace(count=True, trace=False)

def tests():
    return unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromName('test_mail_bootstrap'))

result = tracer.runfunc(tests)
if not result.wasSuccessful():
    raise SystemExit('Mail unit tests failed')
path = str(root / 'src/main/resources/runtime/mail-bootstrap.py')
executable = {line for line in trace._find_executable_linenos(path) if isinstance(line, int) and line > 0}
executed = {line for (filename, line), count in tracer.results().counts.items() if filename == path and count}
covered = len(executable & executed)
print(f'mail-bootstrap.py: {covered}/{len(executable)} executable lines ({100 * covered / len(executable):.2f}%), unit only')
if covered / len(executable) < 0.90:
    raise SystemExit('Mail runtime unit coverage below 90%')
