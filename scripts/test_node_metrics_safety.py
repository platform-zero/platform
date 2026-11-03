import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NodeMetricsSafetyTest(unittest.TestCase):
    def test_optimized_entrypoint_refuses_before_imports(self):
        script = Path(__file__).with_name('test-private-node-metrics.py').resolve()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'imported'
            (Path(directory) / 'argparse.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("must not import")\n')
            result = subprocess.run([sys.executable, '-O', str(script), '--help'], capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': directory})
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Optimized Python', result.stderr)
            self.assertFalse(marker.exists())

    def test_offline_image_recipe_pins_base_helper_and_reaps_without_restart(self):
        recipe = (Path(__file__).resolve().parents[1] / 'images/node-exporter/Containerfile').read_text()
        self.assertIn('FROM quay.io/prometheus/node-exporter@sha256:da83fae85603c4e47e6c68369a7d746e2dda683dc35ea2e234b4f171e0d92798', recipe)
        self.assertIn('84e9bde9a352e11949c9a09abe64b81e83d5dc345a9d99c62eefdfdfc359bb96', recipe)
        self.assertIn('USER 65534:65534', recipe)
        self.assertIn('ENTRYPOINT ["/sbin/catatonit", "--", "/bin/node_exporter"]', recipe)
        self.assertNotIn('restart', recipe)
        self.assertNotIn('apt-get', recipe)


if __name__ == '__main__': unittest.main()
