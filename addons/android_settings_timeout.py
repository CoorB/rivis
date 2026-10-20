#!/usr/bin/python3 -I
"""Stream a Settings setup child and stop its whole process group at the deadline."""
import os
import selectors
import signal
import subprocess
import sys
import time


def main():
    limit, cli, serial = sys.argv[1:]
    proc = subprocess.Popen(["/bin/bash", cli, "__android_settings", serial], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    end = time.monotonic() + float(limit)
    while selector.get_map():
        left = end - time.monotonic()
        if left <= 0:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            return 124
        for key, _ in selector.select(timeout=min(left, 0.1)):
            data = os.read(key.fd, 4096)
            if data:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            else:
                selector.unregister(key.fileobj)
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main())
