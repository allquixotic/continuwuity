#!/usr/bin/env python3
"""Private offline audit. Requires the homeserver to be stopped; never prints records."""
import argparse
import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

KNOWN = set('event_id room_id sender origin origin_server_ts type content msc4354_sticky state_key prev_events depth auth_events redacts unsigned hashes signatures'.split())

def exact(f, n):
    data = bytearray()
    while len(data) < n:
        part = f.read(n-len(data))
        if not part:
            raise EOFError('truncated audit stream')
        data.extend(part)
    return bytes(data)

def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, sort_keys=True, indent=2)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', required=True)
    p.add_argument('--scanner', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    result = {'families': {}, 'timeline': {}, 'identity': {}}
    private = {'tokens': [], 'rooms': {}, 'media': []}
    versions = collections.Counter()
    fields = collections.Counter()
    references = collections.Counter()
    passwords = hashlib.sha256()
    password_count = 0
    process = subprocess.Popen([a.scanner, a.db], stdout=subprocess.PIPE)
    try:
        while (header := process.stdout.read(4)):
            if len(header) != 4:
                raise EOFError('truncated family header')
            name = exact(process.stdout, struct.unpack('>I', header)[0]).decode()
            print(f'scanning {name}', file=sys.stderr, flush=True)
            count = size = 0
            digest = hashlib.sha256()
            semantic = hashlib.sha256()
            while True:
                kl, vl = struct.unpack('>II', exact(process.stdout, 8))
                if kl == 0xffffffff:
                    break
                key, value = exact(process.stdout, kl), exact(process.stdout, vl)
                digest.update(struct.pack('>II', kl, vl)); digest.update(key); digest.update(value)
                count += 1; size += kl+vl
                if name == 'userid_password' and value:
                    passwords.update(struct.pack('>II', kl, vl)); passwords.update(key); passwords.update(value)
                    password_count += 1
                if name == 'global' and key == b'keypair':
                    result['identity']['keypair_sha256'] = hashlib.sha256(value).hexdigest()
                if name == 'global' and key in (b'unembed_unsigned_info', b'split_userid_password'):
                    result['identity'][key.decode()] = True
                if name == 'token_userdeviceid' and len(private['tokens']) < 100:
                    user, _, device = value.partition(b'\xff')
                    private['tokens'].append({'token': key.decode(), 'user': user.decode(), 'device': device.decode()})
                if name in ('mediaid_file', 'mediaid_filekey') and len(private['media']) < 100:
                    prefix, _, rest = key.partition(b'\xff')
                    if len(rest) >= 8 and rest[:8] == b'\0'*8:
                        filename = base64.urlsafe_b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
                        path = Path(a.db)/'media'/filename
                        if path.is_file() and path.stat().st_size < 8*1024*1024:
                            with path.open('rb') as f:
                                content_hash = hashlib.file_digest(f, 'sha256').hexdigest()
                            private['media'].append({'mxc': prefix.decode(), 'content_sha256': content_hash, 'bytes': path.stat().st_size})
                if name == 'pduid_pdu':
                    obj = json.loads(value)
                    unsigned = obj.pop('unsigned', None)
                    wire = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                    semantic.update(struct.pack('>II', kl, len(wire))); semantic.update(key); semantic.update(wire)
                    fields.update(set(obj)-KNOWN)
                    for ref in obj.get('prev_events', []) + obj.get('auth_events', []):
                        references['tuple' if isinstance(ref, list) else 'string'] += 1
                    if obj['type'] == 'm.room.create':
                        version = obj['content'].get('room_version', '1')
                        versions[str(version)] += 1
                        if len(private['rooms']) < 10000:
                            private['rooms'][obj.get('room_id', obj['event_id'].replace('$','!',1))] = version
                    if count % 500000 == 0:
                        print(f'{name}: {count} records scanned', file=sys.stderr, flush=True)
                if name == 'eventid_outlierpdu' and b'"m.room.create"' in value:
                    obj = json.loads(value)
                    if obj.get('type') == 'm.room.create':
                        room = obj.get('room_id', obj.get('event_id', '').replace('$','!',1))
                        if room:
                            private['rooms'][room] = obj['content'].get('room_version', '1')
            result['families'][name] = {'count': count, 'bytes': size, 'sha256': digest.hexdigest()}
            if name == 'pduid_pdu':
                result['timeline'] = {'signed_json_sha256': semantic.hexdigest(), 'extra_fields': dict(fields), 'references': dict(references), 'room_versions': dict(versions)}
            print(f'{name}: {count} records', file=sys.stderr, flush=True)
        if process.wait() != 0:
            raise RuntimeError('read-only scanner failed')
    finally:
        if process.poll() is None:
            process.terminate(); process.wait()
    result['identity']['nonempty_password_count'] = password_count
    result['identity']['nonempty_passwords_sha256'] = passwords.hexdigest()
    save(a.output, result)
    save(a.output+'.private', private)
    print(json.dumps({'families': len(result['families']), 'timeline': result['timeline'], 'identity': result['identity']}))

if __name__ == '__main__':
    main()
