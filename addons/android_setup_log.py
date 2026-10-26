#!/usr/bin/python3 -I
"""Mirror Android setup output to an append-only, timestamped diagnostic log."""
import datetime
import os
import re
import sys

path = sys.argv[1]
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
# An Authorization header carries a scheme word before the credential: redact both, or 'Bearer' alone goes
# and the token stays in the log.
auth = re.compile(r'(?i)((?:(?:proxy-)?authorization|bearer)\s*:?\s+)(?:\S+\s+)?\S+')
secret = re.compile(r'(?i)((?:token|password|secret|api[_-]?key)\s*[:=]\s*)\S+')
with open(path, 'a', encoding='utf-8') as log:
    os.chmod(path, 0o600)

    def record(line):
        clean = auth.sub(r'\1[REDACTED]', line.decode('utf-8', 'replace'))
        clean = secret.sub(r'\1[REDACTED]', clean)
        log.write('%s %s\n' % (datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), clean))
        log.flush()

    # Pass bytes on as they arrive rather than a line at a time: the one-click setup's consent question ends
    # without a newline and is answered from /dev/tty, so holding that fragment back left the whole run waiting
    # on a prompt nobody had been shown. The log still gets whole lines.
    pending = bytearray()
    while True:
        chunk = sys.stdin.buffer.read1(4096)
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        pending += chunk
        nl = pending.rfind(b'\n')
        if nl >= 0:
            for line in bytes(pending[:nl]).split(b'\n'):
                record(line)
            del pending[:nl + 1]
    if pending:
        record(bytes(pending))
