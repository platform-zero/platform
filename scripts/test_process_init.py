import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'src/main/resources/runtime/process-init.py'

class ProcessInitTests(unittest.TestCase):
    def test_exit_status_and_configuration_failures(self):
        self.assertEqual(subprocess.run([sys.executable,str(SCRIPT),sys.executable,'-c','raise SystemExit(7)'],capture_output=True,timeout=10).returncode,7)
        self.assertNotEqual(subprocess.run([sys.executable,str(SCRIPT)],capture_output=True,timeout=10).returncode,0)
        result=subprocess.run([sys.executable,'-O',str(SCRIPT),sys.executable,'-c','print("effect")'],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0);self.assertNotIn('effect',result.stdout);self.assertIn('Optimized Python refused',result.stderr)

    def check_signal(self,handler,expected):
        child='import signal,time; '+handler+'; print("ready",flush=True); time.sleep(60)'
        process=subprocess.Popen([sys.executable,str(SCRIPT),sys.executable,'-c',child],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([process.stdout],[],[],10)[0]);self.assertEqual(process.stdout.readline().strip(),'ready')
            process.send_signal(signal.SIGTERM);self.assertEqual(process.wait(timeout=10),expected)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=10)
            process.stdout.close();process.stderr.close()

    def test_native_handler_receives_termination(self):
        self.check_signal('signal.signal(signal.SIGTERM,lambda *_:exit(0))',0)

    def test_unhandled_child_signal_is_preserved(self):
        self.check_signal('signal.signal(signal.SIGTERM,signal.SIG_DFL)',143)

if __name__=='__main__':unittest.main()
