"""Run the native loopback-coupled fileserver and Seahub without a root supervisor.
No restart policy: losing either child fails the container. Shutdown is coordinated.
"""
import os
import signal
import subprocess
import time


def supervise(commands, grace=20):
    if not commands or grace <= 0:
        raise ValueError('Invalid supervision configuration')
    children = []
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
    result = 0
    try:
        for command in commands:
            if stopping:
                break
            children.append(subprocess.Popen(command, start_new_session=True))
        while not stopping:
            for child in children:
                status = child.poll()
                if status is not None:
                    result = status if status > 0 else (128 - status if status < 0 else 1)
                    stopping = True
                    break
            if not stopping:
                time.sleep(.1)
    finally:
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        end = time.monotonic() + grace
        for child in children:
            try:
                child.wait(timeout=max(.01, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                result = 1
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return result


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Optimized Python refused')
    root = '/opt/seafile/seafile-server-13.0.28'
    raise SystemExit(supervise([
        [root + '/seafile/bin/fileserver', '-F', '/state/conf', '-d', '/state/seafile-data',
         '-l', '/state/logs/fileserver.log', '-p', '/rpc', '-P', '/tmp/fileserver.pid'],
        ['/usr/bin/python3', '-m', 'gunicorn', 'seahub.wsgi:application', '--bind=0.0.0.0:8000',
         '--workers=2', '--threads=2', '--worker-tmp-dir=/tmp', '--timeout=120'],
    ]))
