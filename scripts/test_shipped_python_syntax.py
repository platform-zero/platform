"""Parse shipped native adapters and runtime helpers without importing or executing them."""
import ast
from pathlib import Path
import unittest

WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE_DIRS = (
    'platform/scripts',
    'platform/src/main/resources/runtime',
    'acceptance/runners',
    'acceptance/scripts',
)


class ShippedPythonSyntaxTest(unittest.TestCase):
    def test_all_shipped_python_parses_before_native_invocation(self):
        seen = set()
        for directory in SOURCE_DIRS:
            for source in sorted((WORKSPACE / directory).rglob('*.py')):
                if '__pycache__' in source.parts:
                    continue
                self.assertNotIn(source, seen)
                seen.add(source)
                with self.subTest(source=str(source.relative_to(WORKSPACE))):
                    ast.parse(source.read_bytes(), filename=str(source))
        self.assertGreaterEqual(len(seen), 280)


if __name__ == '__main__':
    unittest.main()
