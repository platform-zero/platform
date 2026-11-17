"""Source-only VM scope regression: Android TEST exception, no other guests."""
import importlib.util
import inspect
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/qualified-client-entry.py'


class ScopedAndroidVmExceptionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('p0v3_scoped_android_client', SOURCE)
        cls.client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.client)

    def test_non_android_cannot_launch_any_guest(self):
        for surface in ('WEB', 'HEADLESS'):
            with self.subTest(surface=surface), patch.object(subprocess, 'Popen', side_effect=AssertionError('VM launched')) as popen:
                self.assertIsNone(self.client.official_emulators({'surface': surface}, {}, []))
                popen.assert_not_called()

    def test_android_exception_retains_explicit_pins_without_running_guest(self):
        source = inspect.getsource(self.client.official_emulators)
        for requirement in ("('API34', 'API36')", 'p0v3-api', "'5564'", "'5580'",
                            "'/opt/android-sdk/emulator/emulator'", "'/opt/android-sdk/platform-tools/adb'",
                            "'ro.kernel.qemu'", 'only dedicated original AVD serials'):
            self.assertIn(requirement, source)
        self.assertNotIn('require(False', source)


if __name__ == '__main__':
    unittest.main()
