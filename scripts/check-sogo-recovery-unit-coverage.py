#!/usr/bin/env python3
"""Unit-only archive/oracle helper coverage; native restore probes are excluded."""
if not __debug__:
    raise SystemExit('Unit coverage requires assertions enabled')
import sys
import trace
import unittest
from pathlib import Path

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
tracer = trace.Trace(count=True, trace=False)


def tests():
    return unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromNames(['test_financial_restore_archive', 'test_restored_sogo_fixture', 'test_mail_fixture_selection']))


result = tracer.runfunc(tests)
if not result.wasSuccessful():
    raise SystemExit('Recovery helper unit tests failed')
for name in ('financial_restore_archive.py', 'restored_sogo_fixture.py', 'mail_fixture_selection.py'):
    path = str(root / name)
    executable = {line for line in trace._find_executable_linenos(path) if isinstance(line, int) and line > 0}
    executed = {line for (filename, line), count in tracer.results().counts.items() if filename == path and count}
    covered = len(executable & executed)
    print(f'{name}: {covered}/{len(executable)} executable lines ({100 * covered / len(executable):.2f}%), unit only')
    if covered / len(executable) < 0.90:
        raise SystemExit('Recovery helper unit coverage below 90%')
