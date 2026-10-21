#!/usr/bin/python3 -I
"""Mirror Android setup output to an append-only, timestamped diagnostic log."""
import datetime
import os
import re
import sys

path = sys.argv[1]
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
secret = re.compile(r'(?i)((?:authorization|bearer)\s*:?\s+|(?:token|password|secret|api[_-]?key)\s*[:=]\s*)\S+')
with open(path, 'a', encoding='utf-8') as log:
    os.chmod(path, 0o600)
    for raw in sys.stdin.buffer:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        clean = secret.sub(r'\1[REDACTED]', raw.decode('utf-8', 'replace').rstrip('\n'))
        log.write('%s %s\n' % (datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), clean))
        log.flush()
