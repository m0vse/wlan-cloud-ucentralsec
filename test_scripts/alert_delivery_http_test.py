"""Isolated SEC only. Uses the retained synthetic email-settings fixture.

Never run against production: saves synthetic disabled SMS settings.
"""
import json
import hashlib
import os
import runpy
import socketserver
import ssl
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs
from email import policy
from email.parser import BytesParser

# This script only runs inside the disposable test container.
ca = '/audit/certs/alert-test-ca.pem'
key = '/audit/certs/alert-test-key.pem'
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', key, '-out', ca, '-days', '1', '-subj', '/CN=127.0.0.1',
                '-addext', 'subjectAltName=IP:127.0.0.1,DNS:api.twilio.com'],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
fixture = runpy.run_path(sys.argv[1] if len(sys.argv) > 1 else '/audit/email_settings_test.py')
http, root, user, check = (fixture[k] for k in ('http', 'root', 'user', 'check'))
path = '/api/v1/smsSettings'
status, public = http('GET', path, token=root)
check(status == 200 and public == {'configured': False, 'enabled': False,
      'accountSid': '', 'fromNumber': '', 'tokenSet': False}, 'blank SMS settings')
settings = {'enabled': False, 'accountSid': 'AC' + '1' * 32,
            'fromNumber': '+441234567890', 'tokenAction': 'set', 'token': 'SyntheticOnlyToken'}
for method, body in [('GET', None), ('PUT', settings), ('POST', {'recipient': '+441234567891'})]:
    for token in (None, user):
        check(http(method, path, body, token)[0] in (401, 403), 'SMS root-only ' + method)
check(http('PUT', path, settings, root)[0] == 200, 'disabled synthetic SMS settings saved')
public = http('GET', path, token=root)[1]
check(public['tokenSet'] and 'token' not in public and 'SyntheticOnlyToken' not in json.dumps(public), 'token write-only')
check(stat.S_IMODE(os.stat('/audit/data/sms-settings.json').st_mode) == 0o600, 'SMS file0600')
check(http('POST', path, {'recipient': '+441234567891'}, root)[0] == 503, 'disabled no delivery')
for body in ({}, {'recipient': 'not-a-number'}, {'recipient': '+441234567891', 'text': 'arbitrary'}):
    check(http('POST', path, body, root)[0] == 400, 'test fixed payload only')
body = {'channel': 'email', 'recipient': 'operator@example.invalid', 'subject': 'Synthetic',
        'text': 'Plain fallback — Café venue/AP 東京',
        'html': '<p>Synthetic HTML — Café venue/AP 東京</p>', 'eventId': 'synthetic-event:1'}
for token in (root, user, None):
    check(http('POST', '/api/v1/alertDelivery', body, token)[0] in (401, 403), 'external delivery denied even root')
def internal(payload, key=None):
    headers = {'Content-Type': 'application/json', 'X-INTERNAL-NAME': 'synthetic-worker',
               'X-API-KEY': key or hashlib.sha256(b'https://127.0.0.1:16001').hexdigest()}
    req = urllib.request.Request('https://127.0.0.1:17001/api/v1/alertDelivery',
                                 json.dumps(payload).encode(), headers, method='POST')
    try:
        with urllib.request.urlopen(req, context=fixture['TLS'], timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())
check(internal(body, 'invalid-key')[0] in (401, 403), 'invalid internal key denied')
status, result = internal(body)
check(status == 503 and result == {'accepted': False, 'ambiguous': False, 'retryable': True}, 'disabled internal email safe retry')
class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        if getattr(self.server, 'implicit', False):
            self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile('rb')
            self.wfile = self.connection.makefile('wb', buffering=0)
        self.connection.settimeout(5)
        self.wfile.write(b'220 synthetic SMTP\r\n')
        while True:
            command = self.rfile.readline().upper()
            if not command: return
            if command.startswith(b'STARTTLS'):
                self.wfile.write(b'220 TLS\r\n')
                self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile('rb')
                self.wfile = self.connection.makefile('wb', buffering=0)
            elif command.startswith(b'DATA'):
                self.wfile.write(b'354 data\r\n')
                chunks = []
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk == b'.\r\n': break
                    chunks.append(chunk)
                self.server.messages.append(b''.join(chunks))
                self.wfile.write(b'250 accepted\r\n')
            elif command.startswith(b'QUIT'):
                self.wfile.write(b'221 bye\r\n'); return
            else: self.wfile.write(b'250 synthetic\r\n')
server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SMTP)
server.messages = []
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    smtp = {'enabled': True, 'host': '127.0.0.1', 'port': server.server_address[1],
            'tlsMode': 'none', 'sender': 'sender@example.invalid', 'username': '',
            'authMethod': 'none', 'passwordAction': 'clear'}
    check(http('PUT', '/api/v1/emailSettings', smtp, root)[0] == 200, 'disposable SMTP saved')
    check(internal(body) == (200, {'accepted': True}), 'authenticated internal HTML email accepted')
    check(len(server.messages) == 1, 'exactly one multipart email')
    message = BytesParser(policy=policy.default).parsebytes(server.messages[0])
    parts = {part.get_content_type(): part for part in message.walk() if not part.is_multipart()}
    check(body['text'] in parts['text/plain'].get_content() and
          body['html'] in parts['text/html'].get_content() and
          all(part.get_content_charset() == 'utf-8' for part in parts.values()),
          'actual UTF8 multipart HTML and plain fallback decode Unicode venue/AP names')
    for bad in ({**body, 'html': 'x' * 32769}, {**body, 'channel': 'sms'}, {**body, 'extra': 'no'}):
        check(internal(bad)[0] == 400, 'internal body strict validation')
    check(len(server.messages) == 1, 'invalid inputs never sent')
finally:
    server.shutdown(); server.server_close()

# All certificates and endpoint overrides below are disposable-container only.
# No global/production trust store is edited. The runtime receives SSL_CERT_FILE
# pointing at this synthetic CA file before startup.
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(ca, key)
for mode in ('implicit', 'starttls'):
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 0), SMTP)
    server.handle_error = lambda *args: None  # Expected synthetic hostname failures.
    server.messages, server.tls, server.implicit = [], tls, mode == 'implicit'
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        smtp.update(port=server.server_address[1], tlsMode=mode)
        check(http('PUT', '/api/v1/emailSettings', smtp, root)[0] == 200, 'synthetic TLS SMTP saved')
        check(internal(body) == (200, {'accepted': True}), mode + ' bounded alert accepted with verified hostname')
        check(len(server.messages) == 1, mode + ' exactly one SMTP message')
        smtp['host'] = '127.0.0.2'  # Same loopback server; certificate has only .1.
        check(http('PUT', '/api/v1/emailSettings', smtp, root)[0] == 200, 'synthetic mismatched TLS hostname saved')
        status, result = internal(body)
        check(status == 504 and result['ambiguous'] and not result['retryable'], mode + ' hostname mismatch fails closed')
        check(len(server.messages) == 1, mode + ' no content sent after hostname failure')
        smtp['host'] = '127.0.0.1'
    finally:
        server.shutdown(); server.server_close()

# Exercise the actual HTTPS Twilio request against a loopback TLS provider.
# Refuse to enable SMS unless the disposable container explicitly overrides DNS.
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
check(socket.gethostbyname('api.twilio.com') == '127.0.0.1', 'Twilio isolated DNS override required')
class Twilio(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        content = self.rfile.read(int(self.headers['Content-Length']))
        self.server.received.append((self.path, content, self.headers.get('Authorization', '')))
        self.send_response(self.server.response_status)
        self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(json.dumps(self.server.response_body).encode())
server = HTTPServer(('127.0.0.1', 443), Twilio)
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.received = []
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    settings['enabled'] = True
    check(http('PUT', path, settings, root)[0] == 200, 'synthetic enabled SMS saved only with mock TLS provider')
    sms = {**body, 'channel': 'sms', 'recipient': '+441234567891', 'text': 'Concise synthetic SMS'}
    sms.pop('html')
    for code, provider, expected in (
        (201, {'status': 'queued', 'sid': 'SM' + '1' * 32}, (200, True, False)),
        (401, {'message': 'private provider detail'}, (502, False, False)),
        (429, {'message': 'private provider detail'}, (502, False, True)),
        (503, {'message': 'private provider detail'}, (502, False, True)),
        (201, {}, (504, False, False))):
        server.response_status, server.response_body = code, provider
        status, result = internal(sms)
        check((status, result['accepted'], result.get('retryable', False)) == expected, 'actual TLS Twilio response ' + str(code))
        check('private provider detail' not in json.dumps(result), 'provider details not exposed')
    check(len(server.received) == 5, 'no hidden retries')
    check(all(p == '/2010-04-01/Accounts/AC' + '1' * 32 + '/Messages.json' and
              parse_qs(data.decode()).get('To') == ['+441234567891'] and
              parse_qs(data.decode()).get('Body') == ['Concise synthetic SMS'] and
              auth.startswith('Basic ') for p, data, auth in server.received), 'actual authenticated form only to expected endpoint')
finally:
    server.shutdown(); server.server_close()
print('PASS native SEC SMS settings privacy/access/disabled delivery and external alert denial')
