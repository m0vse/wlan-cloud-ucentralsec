"""Disposable native SEC test only. Run after audit-native-sec/email_settings_test.py.

Requires that harness's synthetic ROOT/scoped tokens and HTTP helpers via runpy.
Never run against a production SEC instance: this test replaces disposable settings.
"""
import runpy
import socketserver
import threading
import time
import sys

fixture = runpy.run_path(sys.argv[1])
http, root, user, check = (fixture[key] for key in ('http', 'root', 'user', 'check'))


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        self.wfile.write(b'220 isolated SMTP\r\n')
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.upper()
            if command.startswith((b'EHLO', b'HELO')):
                self.wfile.write(b'250 isolated\r\n')
            elif command.startswith(b'MAIL FROM:'):
                self.server.envelopes.append(line.decode().strip())
                self.wfile.write(b'250 OK\r\n')
            elif command.startswith(b'RCPT TO:'):
                self.server.envelopes.append(line.decode().strip())
                self.wfile.write(b'250 OK\r\n')
            elif command.startswith(b'DATA'):
                self.wfile.write(b'354 send data\r\n')
                body = []
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk == b'.\r\n':
                        break
                    body.append(chunk)
                self.server.messages.append(b''.join(body).decode())
                self.wfile.write(b'550 rejected\r\n' if self.server.reject else b'250 accepted\r\n')
            elif command.startswith(b'QUIT'):
                self.wfile.write(b'221 bye\r\n')
                return
            else:
                self.wfile.write(b'250 OK\r\n')


server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SMTP)
server.reject = False
server.messages, server.envelopes = [], []
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    path = '/api/v1/emailSettings'
    recipient = {'recipient': 'operator@example.invalid'}
    check(http('POST', path, recipient)[0] in (401, 403), 'anonymous test denied')
    check(http('POST', path, recipient, user)[0] in (401, 403), 'scoped test denied')
    for body in ({}, {'recipient': 1}, {'recipient': 'a@example.invalid\r\nBCC:x'},
                 {'recipient': 'a@example.invalid,b@example.invalid'},
                 {'recipient': 'a@example.invalid', 'password': 'not-accepted'},
                 {'recipient': '@'}, {'recipient': 'a' * 255 + '@example.invalid'}):
        check(http('POST', path, body, root)[0] == 400, 'invalid or expanded test payload rejected')
    check(http('POST', path, recipient, root)[0] == 503, 'disabled SMTP test rejected')
    settings = {'enabled': True, 'host': '127.0.0.1', 'port': server.server_address[1],
                'tlsMode': 'none', 'sender': 'sender@example.invalid', 'username': '',
                'authMethod': 'none', 'passwordAction': 'clear'}
    check(http('PUT', path, settings, root)[0] == 200, 'isolated SMTP settings saved')
    before = http('GET', path, token=root)[1]
    status, result = http('POST', path, recipient, root)
    check(status == 200 and result == {'accepted': True}, 'actual SMTP acceptance reported')
    check(len(server.messages) == 1 and 'OpenWiFi test email' in server.messages[0], 'fixed test subject sent exactly once')
    check('operator@example.invalid' in server.envelopes[-1], 'single selected recipient')
    check(http('GET', path, token=root)[1] == before, 'test does not mutate settings')
    server.reject = True
    status, result = http('POST', path, recipient, root)
    check(status == 503 and result.get('accepted') is not True, 'SMTP rejection is not success')
    time.sleep(.3)
    check(len(server.messages) == 2, 'failed test is not queued or retried')
finally:
    server.shutdown()
    server.server_close()
print('PASS native SMTP test-send acceptance/rejection/privacy/access checks; disposable mail only')
