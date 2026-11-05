#!/usr/bin/env python3
"""Native regression: replay a real tracked WAL and return its exact record."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--fixture', required=True)
p.add_argument('--scanner', required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='matrix-wal-regression-') as root:
    database = str(Path(root)/'db')
    subprocess.run([str(Path(a.fixture).resolve()), database], check=True)
    data = subprocess.check_output([str(Path(a.scanner).resolve()), database])
    offset = 0
    def take(n):
        global offset
        value = data[offset:offset+n]; offset += n
        assert len(value) == n
        return value
    length, = struct.unpack('>I', take(4))
    assert take(length) == b'default'
    kl, vl = struct.unpack('>II', take(8))
    assert take(kl) == b'retained' and take(vl) == b'synthetic'
    assert struct.unpack('>II', take(8)) == (0xffffffff, 0)
    assert offset == len(data)
print('Tracked-WAL read-only recovery: passed')
