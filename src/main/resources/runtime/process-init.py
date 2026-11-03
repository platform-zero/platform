#!/usr/bin/env python3
"""Minimal PID-1 signal forwarding for an immutable image lacking an init binary.
No restart policy. The caller must quiesce application work before shutdown.
"""
import os
import signal
import subprocess
import sys


def main():
    if not __debug__:
        raise SystemExit('Optimized Python refused')
    if len(sys.argv) < 2:
        raise SystemExit('Missing child command')
    child = subprocess.Popen(sys.argv[1:], start_new_session=True)

    def forward(signum, _frame):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)
    result = child.wait()
    # Do not leave a child process group alive after its leader exits.
    forward(signal.SIGTERM, None)
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except ChildProcessError:
            break
    raise SystemExit(result if result >= 0 else 128 - result)


if __name__ == '__main__':
    main()
