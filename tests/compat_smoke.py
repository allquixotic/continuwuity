#!/usr/bin/env python3
"""Exercise local and federated compatibility using two disposable homeservers.

Run with --binary /absolute/path/to/conduwuit --work-dir /new/scratch/directory.
Both servers bind loopback. Test-only TLS and IP settings follow Complement's
configuration; no production configuration, credentials, or database is used.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import sys
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


TLS = ssl._create_unverified_context()
ROOM_VERSIONS = [str(version) for version in range(1, 13)]


def request(base, method, path, body=None, token=None, content_type=None, extra_headers=None):
    headers = dict(extra_headers or {})
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        content_type = 'application/json'
    if content_type:
        headers['Content-Type'] = content_type
    req = Request(base + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, context=TLS, timeout=45) as res:
            data = res.read()
            if 'application/json' in res.headers.get('Content-Type', ''):
                data = json.loads(data)
            return res.status, data, res.headers
    except HTTPError as err:
        data = err.read()
        try:
            data = json.loads(data)
        except ValueError:
            pass
        return err.code, data, err.headers


def ok(base, method, path, body=None, token=None, content_type=None):
    status, data, headers = request(base, method, path, body, token, content_type)
    assert 200 <= status < 300, (method, path, status, data)
    return data, headers


class Homeserver:
    def __init__(self, binary, root, port, registration_token):
        self.binary = binary
        self.root = root
        self.root.mkdir(mode=0o700)
        self.name = f'127.0.0.1:{port}'
        self.base = f'https://{self.name}'
        self.registration_token = registration_token
        self.process = None
        self.log = None
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=localhost', '-days', '1', '-out', str(cert),
            '-keyout', str(key),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.config = root / 'server.toml'
        self.config.write_text(f'''[global]
server_name = "{self.name}"
address = ["127.0.0.1"]
port = [{port}]
database_path = "{root / 'database'}"
allow_registration = true
registration_token = "{registration_token}"
force_disable_first_run_mode = true
allow_federation = true
allow_legacy_media = true
allow_public_room_directory_over_federation = true
trusted_servers = []
query_trusted_key_servers_first = false
ip_range_denylist = []
allow_invalid_tls_certificates_yes_i_know_what_the_fuck_i_am_doing_with_this_and_i_know_this_is_insecure = true
allow_check_for_updates = false
admin_room_notices = false
log = "warn"
log_colors = false
db_cache_capacity_mb = 64
[global.tls]
dual_protocol = true
certs = "{cert}"
key = "{key}"
''')
        self.config.chmod(0o600)

    def start(self):
        self.log = (self.root / 'server.log').open('ab')
        self.process = subprocess.Popen(
            [self.binary, '--config', str(self.config)],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            assert self.process.poll() is None, f'{self.name} exited; inspect {self.root}/server.log'
            try:
                if request(self.base, 'GET', '/_matrix/client/versions')[0] == 200:
                    return
            except (URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.2)
        raise AssertionError(f'{self.name} did not become ready')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.log:
            self.log.close()

    def register(self, username, password):
        body = {'username': username, 'password': password}
        status, response, _ = request(self.base, 'POST', '/_matrix/client/v3/register', body)
        assert status == 401, (status, response)
        body['auth'] = {
            'type': 'm.login.registration_token', 'token': self.registration_token,
            'session': response['session'],
        }
        response, _ = ok(self.base, 'POST', '/_matrix/client/v3/register', body)
        return response['access_token'], response['user_id']


class Synapse(Homeserver):
    """Independent implementation for interoperability tests (matrix-synapse 1.164.2)."""

    def __init__(self, python, root, port, registration_token):
        super().__init__(python, root, port, registration_token)
        self.config = root / 'homeserver.yaml'
        config = {
            'server_name': self.name, 'public_baseurl': self.base,
            'pid_file': str(root / 'synapse.pid'),
            'listeners': [{'port': port, 'bind_addresses': ['127.0.0.1'],
                           'type': 'http', 'tls': True,
                           'resources': [{'names': ['client', 'federation'], 'compress': False}]}],
            'tls_certificate_path': str(root / 'cert.pem'),
            'tls_private_key_path': str(root / 'key.pem'),
            'database': {'name': 'sqlite3', 'args': {'database': str(root / 'synapse.db')}},
            'media_store_path': str(root / 'media'),
            'signing_key_path': str(root / 'signing.key'),
            'enable_registration': True, 'enable_registration_without_verification': True,
            'report_stats': False, 'trusted_key_servers': [],
            'suppress_key_server_warning': True,
            'federation_verify_certificates': False, 'ip_range_blacklist': [],
            'url_preview_enabled': False,
            'macaroon_secret_key': secrets.token_urlsafe(32),
            'form_secret': secrets.token_urlsafe(32),
            'rc_joins': {'local': {'per_second': 100, 'burst_count': 100},
                         'remote': {'per_second': 100, 'burst_count': 100}},
            'rc_registration': {'per_second': 100, 'burst_count': 100},
            'rc_room_creation': {'per_second': 100, 'burst_count': 100},
            'rc_message': {'per_second': 100, 'burst_count': 100},
        }
        self.config.write_text(json.dumps(config))  # JSON is a YAML subset.
        self.config.chmod(0o600)

    def start(self):
        self.log = (self.root / 'server.log').open('ab')
        self.process = subprocess.Popen(
            [self.binary, '-m', 'synapse.app.homeserver', '--config-path', str(self.config)],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            assert self.process.poll() is None, f'{self.name} exited; inspect {self.root}/server.log'
            try:
                if request(self.base, 'GET', '/_matrix/client/versions')[0] == 200:
                    return
            except (URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.2)
        raise AssertionError(f'{self.name} did not become ready')

    def register(self, username, password):
        body = {'username': username, 'password': password}
        status, response, _ = request(self.base, 'POST', '/_matrix/client/v3/register', body)
        assert status == 401, (status, response)
        body['auth'] = {'type': 'm.login.dummy', 'session': response['session']}
        response, _ = ok(self.base, 'POST', '/_matrix/client/v3/register', body)
        return response['access_token'], response['user_id']


def wait_for_event(base, token, room, event, body):
    path = '/_matrix/client/v3/rooms/' + quote(room, safe='') + '/event/' + quote(event, safe='')
    deadline = time.monotonic() + 45
    last = None
    while time.monotonic() < deadline:
        status, response, _ = request(base, 'GET', path, token=token)
        if status == 200:
            assert response['content']['body'] == body, response
            return
        last = (status, response)
        time.sleep(0.25)
    raise AssertionError(('event was not delivered', room, event, last))


def verify_forwarded_event(destination, origin, event_id, room_version):
    """Verify a re-exported legacy event using Synapse's independent crypto code."""
    from signedjson.key import read_signing_keys, decode_verify_key_bytes
    from signedjson.sign import sign_json, verify_signed_json
    from unpaddedbase64 import decode_base64
    from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
    from synapse.crypto.event_signing import compute_content_hash
    from synapse.synapse_rust.events import redact_event_dict
    import hashlib

    path = '/_matrix/federation/v1/event/' + quote(event_id, safe='')
    signed = {'method': 'GET', 'uri': path, 'origin': origin.name, 'destination': destination.name}
    with (origin.root / 'signing.key').open() as f:
        key = read_signing_keys(f)[0]
    sign_json(signed, origin.name, key)
    key_id, signature = next(iter(signed['signatures'][origin.name].items()))
    auth = f'X-Matrix origin="{origin.name}",destination="{destination.name}",key="{key_id}",sig="{signature}"'
    status, response, _ = request(destination.base, 'GET', path, extra_headers={'Authorization': auth})
    assert status == 200, ('federation event export', status, response)
    pdu = response['pdus'][0]
    name, digest = compute_content_hash(pdu, hashlib.sha256)
    assert decode_base64(pdu['hashes'][name]) == digest, ('forwarded content hash changed', event_id)
    public, _ = ok(origin.base, 'GET', '/_matrix/key/v2/server')
    redacted = redact_event_dict(KNOWN_ROOM_VERSIONS[room_version], pdu)
    for signing_id, info in public['verify_keys'].items():
        verify_signed_json(redacted, origin.name, decode_verify_key_bytes(signing_id, decode_base64(info['key'])))


def run(args):
    root = Path(args.work_dir).resolve()
    root.mkdir(mode=0o700)
    password = secrets.token_urlsafe(24)
    bob_type = Synapse if args.synapse_python else Homeserver
    servers = [Homeserver(str(Path(args.binary).resolve()), root / 'alice',
                          args.base_port, secrets.token_urlsafe(24)),
               bob_type(str(Path(args.synapse_python or args.binary).absolute()), root / 'bob',
                        args.base_port + 1, secrets.token_urlsafe(24))]
    alice, bob = servers
    delivered = []
    try:
        for server in servers:
            server.start()
        at, au = alice.register('alice', password)
        bt, bu = bob.register('bob', password)
        caps, headers = ok(alice.base, 'GET', '/_matrix/client/v3/capabilities', token=at)
        assert 'no-store' in headers.get('Cache-Control', '')
        for creator, ct, joiner, jt in [(alice, at, bob, bt), (bob, bt, alice, at)]:
            for version in ROOM_VERSIONS:
                assert caps['capabilities']['m.room_versions']['available'][version] == 'stable'
                room, _ = ok(creator.base, 'POST', '/_matrix/client/v3/createRoom', {
                    'room_version': version, 'preset': 'public_chat', 'name': 'compat ' + version,
                }, ct)
                room = room['room_id']
                joined, _ = ok(joiner.base, 'POST', '/_matrix/client/v3/join/' + quote(room, safe='')
                               + '?' + urlencode({'server_name': creator.name}), {}, jt)
                assert joined['room_id'] == room
                for sender, st, receiver, rt in [(alice, at, bob, bt), (bob, bt, alice, at)]:
                    body = f'room version {version}, sent by {sender.name}'
                    event, _ = ok(sender.base, 'PUT', '/_matrix/client/v3/rooms/'
                                  + quote(room, safe='') + '/send/m.room.message/'
                                  + secrets.token_hex(8), {'msgtype': 'm.text', 'body': body}, st)
                    wait_for_event(receiver.base, rt, room, event['event_id'], body)
                    delivered.append((receiver, rt, room, event['event_id'], body, version))
                    if args.synapse_python and sender is bob and version in ['1', '2']:
                        verify_forwarded_event(alice, bob, event['event_id'], version)
                messages, _ = ok(alice.base, 'GET', '/_matrix/client/v3/rooms/'
                                 + quote(room, safe='') + '/messages?dir=f&from=s0_0_0&limit=2', token=at)
                assert isinstance(messages['chunk'], list)
                print(json.dumps({'room_version': version, 'creator': type(creator).__name__, 'bidirectional_federation': 'passed'}), flush=True)
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aP0kAAAAASUVORK5CYII=')
        uploaded, _ = ok(alice.base, 'POST', '/_matrix/media/v3/upload', png, at, 'image/png')
        media = uploaded['content_uri'][len('mxc://'):]
        for prefix in ['/_matrix/client/v1/media/download/'] + ([] if args.synapse_python else ['/_matrix/media/v3/download/']):
            content, _ = ok(bob.base, 'GET', prefix + media, token=bt)
            assert content == png
        content, _ = ok(bob.base, 'GET', ('/_matrix/client/v1/media/thumbnail/' if args.synapse_python else '/_matrix/media/v3/thumbnail/') + media
                        + '?width=1&height=1&method=scale', token=bt)
        assert content

        uploaded, _ = ok(bob.base, 'POST', '/_matrix/media/v3/upload', png, bt, 'image/png')
        remote_media = uploaded['content_uri'][len('mxc://'):]
        for suffix in ['download/' + remote_media, 'thumbnail/' + remote_media + '?width=1&height=1&method=scale']:
            content, _ = ok(alice.base, 'GET', '/_matrix/media/v3/' + suffix, token=at)
            assert content

        for server in servers:
            server.stop()
            server.start()
        for receiver, token, room, event, body, version in delivered:
            wait_for_event(receiver.base, token, room, event, body)
            if args.synapse_python and receiver is alice and version in ['1', '2']:
                verify_forwarded_event(alice, bob, event, version)
        logged_in, _ = ok(alice.base, 'POST', '/_matrix/client/v3/login', {
            'type': 'm.login.password', 'identifier': {'type': 'm.id.user', 'user': au},
            'password': password,
        })
        assert logged_in['user_id'] == au
        print(json.dumps({'result': 'passed', 'room_versions': len(ROOM_VERSIONS), 'room_creators': 2, 'federated_messages': len(delivered),
                          'authenticated_and_legacy_media': 'passed', 'restart_persistence': 'passed'}), flush=True)
    finally:
        for server in servers:
            server.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--synapse-python', help='Python from venv with matrix-synapse==1.164.2 installed')
    parser.add_argument('--base-port', type=int, default=38448)
    args = parser.parse_args()
    if args.synapse_python and os.path.abspath(sys.executable) != os.path.abspath(args.synapse_python):
        os.execv(os.path.abspath(args.synapse_python), [os.path.abspath(args.synapse_python), __file__, *sys.argv[1:]])
    run(args)
