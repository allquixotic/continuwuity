#!/usr/bin/env python3
"""Prove a startup stream-counter rewrite changes only the server's push-rule pointer."""
import argparse
import hashlib
import json
import struct
import subprocess
from db_audit import exact, save

FAMILIES = ['roomuserdataid_accountdata', 'roomusertype_roomuserdataid']

def scan(scanner, database):
    tables = {}
    process = subprocess.Popen([scanner, database, *FAMILIES], stdout=subprocess.PIPE)
    try:
        while (header := process.stdout.read(4)):
            assert len(header) == 4
            name = exact(process.stdout, struct.unpack('>I', header)[0]).decode()
            table = tables[name] = {}
            while True:
                kl, vl = struct.unpack('>II', exact(process.stdout, 8))
                if kl == 0xffffffff:
                    break
                key, value = exact(process.stdout, kl), exact(process.stdout, vl)
                assert key not in table
                table[key] = value
        assert process.wait() == 0
    finally:
        if process.poll() is None:
            process.terminate(); process.wait()
    return tables

def prove(before, after, server_user):
    old, new = (t[FAMILIES[0]] for t in [before, after])
    oi, ni = (t[FAMILIES[1]] for t in [before, after])
    assert oi.keys() == ni.keys(), 'logical account-data index changed'
    changed = [key for key in oi if oi[key] != ni[key]]
    expected = b'\xff'+server_user.encode()+b'\xffm.push_rules'
    assert changed == [expected], 'unexpected account-data pointer changes'
    assert old.keys()-new.keys() == {oi[expected]}
    assert new.keys()-old.keys() == {ni[expected]}
    assert all(old[key] == new[key] for key in old.keys() & new.keys())
    assert json.loads(old[oi[expected]]) == json.loads(new[ni[expected]])
    def digests(tables):
        result = {}
        for name, table in tables.items():
            digest = hashlib.sha256()
            for key, value in sorted(table.items()):
                digest.update(struct.pack('>II', len(key), len(value)))
                digest.update(key); digest.update(value)
            result[name] = digest.hexdigest()
        return result
    return {'passed': True, 'logical_records': len(oi), 'unchanged_physical_records': len(old)-1,
            'changed_pointers': 1, 'exception': 'server_user_m.push_rules_stream_counter_only',
            'before_family_sha256': digests(before), 'after_family_sha256': digests(after)}

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--before', required=True); p.add_argument('--after', required=True)
    p.add_argument('--scanner', required=True); p.add_argument('--server-user', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    result = prove(scan(a.scanner, a.before), scan(a.scanner, a.after), a.server_user)
    save(a.output, result)
    print(json.dumps(result, sort_keys=True))
