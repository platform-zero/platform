import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'src/main/resources/runtime/seafile-web.py'
LOADER="import importlib.util,json,sys; s=importlib.util.spec_from_file_location('supervisor',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); raise SystemExit(m.supervise(json.loads(sys.argv[2]),grace=.5))"

class SeafileSupervisorTests(unittest.TestCase):
    def command(self,commands):return [sys.executable,'-B','-c',LOADER,str(SCRIPT),json.dumps(commands)]

    def test_child_exit_fails_group_without_restart(self):
        for code,expected in [(0,1),(7,7)]:
            r=subprocess.run(self.command([[sys.executable,'-c','raise SystemExit('+str(code)+')'],[sys.executable,'-c','import time; time.sleep(60)']]),capture_output=True,timeout=10)
            self.assertEqual(r.returncode,expected)

    def test_signal_stops_group(self):
        children=[[sys.executable,'-c','import time; print("ready",flush=True); time.sleep(60)']]*2
        p=subprocess.Popen(self.command(children),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([p.stdout],[],[],10)[0]);self.assertEqual(p.stdout.readline().strip(),'ready')
            p.send_signal(signal.SIGTERM);self.assertEqual(p.wait(timeout=10),0)
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=10)
            p.stdout.close();p.stderr.close()

    def test_unresponsive_child_fails_shutdown(self):
        commands=[[sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(60)']]
        p=subprocess.Popen(self.command(commands),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([p.stdout],[],[],10)[0]);self.assertEqual(p.stdout.readline().strip(),'ready')
            p.send_signal(signal.SIGTERM);self.assertEqual(p.wait(timeout=10),1)
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=10)
            p.stdout.close();p.stderr.close()

    def test_spawn_and_configuration_failures(self):
        self.assertNotEqual(subprocess.run(self.command([]),capture_output=True,timeout=10).returncode,0)
        self.assertNotEqual(subprocess.run(self.command([[sys.executable,'-c','import time; time.sleep(60)'],['/not-a-fixture-executable']]),capture_output=True,timeout=10).returncode,0)
        r=subprocess.run([sys.executable,'-O',str(SCRIPT)],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(r.returncode,0);self.assertIn('Optimized Python refused',r.stderr)

if __name__=='__main__':unittest.main()
