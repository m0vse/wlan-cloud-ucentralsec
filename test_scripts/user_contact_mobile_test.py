"""Disposable SEC only: profile contact must never alter MFA or credentials."""
import json
import runpy
import sqlite3
import sys
import uuid

f = runpy.run_path(sys.argv[1] if len(sys.argv) > 1 else '/audit/email_settings_test.py')
http, root, user, check = (f[k] for k in ('http', 'root', 'user', 'check'))
number = '+441234567890'
new = {'email': 'contact@example.invalid', 'name': 'Synthetic contact', 'userRole': 'admin',
       'currentPassword': 'AuditContact9!', 'contactMobileNumber': number}
status, created = http('POST', '/api/v1/user/0', new, root)
check(status == 200 and created['contactMobileNumber'] == number, 'contact saved on create')
uid = created['id']; path = '/api/v1/user/' + uid
check(http('GET', path, token=root)[1]['contactMobileNumber'] == number, 'contact loaded from persistent metadata')
db = sqlite3.connect('/audit/data/security.db')
original = json.loads(db.execute('select userTypeProprietaryInfo from Users where id=?', (uid,)).fetchone()[0])
original.update(mfa={'enabled': True, 'method': 'authenticator'},
                authenticatorSecret='SyntheticUnchangedAuthenticatorSecret',
                mobiles=[{'number': '+441111111111', 'verified': True, 'primary': True},
                         {'number': '+442222222222', 'verified': False, 'primary': False}])
# Clone a synthetic record under a fresh ID before it ever enters SEC's user
# cache. Directly changing an already-cached row would be a misleading fixture.
names = [row[1].lower() for row in db.execute('pragma table_info(Users)')]
record = list(db.execute('select * from Users where id=?', (uid,)).fetchone())
uid = str(uuid.uuid4()); path = '/api/v1/user/' + uid
for name, value in (('id', uid), ('email', 'mfa-contact-target@example.invalid'),
                    ('userTypeProprietaryInfo', json.dumps(original))):
    record[names.index(name.lower())] = value
db.execute('insert into Users values (' + ','.join('?' for _ in names) + ')', record); db.commit()
columns = 'userTypeProprietaryInfo,currentPassword,validated,changePassword,lastPasswordChange,securityPolicy,securityPolicyChange'
def snapshot():
    row = db.execute('select ' + columns + ' from Users where id=?', (uid,)).fetchone()
    metadata = json.loads(row[0]); metadata.pop('contactMobileNumber', None)
    return (metadata,) + row[1:]
before = snapshot()
for value in ('+443333333333', ''):
    status, result = http('PUT', path, {'contactMobileNumber': value}, root)
    check(status == 200 and result['contactMobileNumber'] == value, 'admin edit/clear contact')
    check('SyntheticUnchangedAuthenticatorSecret' not in json.dumps(result), 'contact response excludes MFA secret')
    check(snapshot() == before, 'MFA phones/verification/secret/password/access unchanged')
    check(http('GET', path, token=root)[1]['contactMobileNumber'] == value, 'contact persistence readback')
check(http('PUT', path, {'name': 'Contact renamed'}, root)[0] == 200, 'omitted contact edit accepted')
check(http('GET', path, token=root)[1]['contactMobileNumber'] == '', 'omitted contact stays unchanged')
for value in ('not-a-phone', '+0123456789', '+441234567890\r\n', 42, None):
    check(http('PUT', path, {'contactMobileNumber': value}, root)[0] == 400, 'invalid contact PUT rejected')
    check(snapshot() == before, 'invalid update does not mutate credentials/MFA')
    check(http('POST', '/api/v1/user/0', {**new, 'contactMobileNumber': value}, root)[0] == 400, 'invalid contact POST rejected')
scoped_id = f['created']['id']
self_path = '/api/v1/user/' + scoped_id
check(http('PUT', self_path, {'contactMobileNumber': number}, user)[0] == 200, 'scoped user self contact edit')
check(http('GET', self_path, token=user)[1]['contactMobileNumber'] == number, 'scoped own contact read')
check(http('PUT', path, {'contactMobileNumber': number}, user)[0] in (401, 403), 'scoped other user edit denied')
check(snapshot() == before, 'denied scoped edit preserves target MFA/credentials')
combined = {'contactMobileNumber': number,
            'userTypeProprietaryInfo': {'mfa': {'enabled': True, 'method': 'authenticator'}}}
status, result = http('PUT', path, combined, root)
check(status == 200 and result['contactMobileNumber'] == number, 'combined explicit MFA/profile edit accepted')
check(result['userTypeProprietaryInfo']['authenticatorSecret'] == 'SyntheticUnchangedAuthenticatorSecret',
      'explicit existing-authenticator enrolment retains its normal secret response')
after_mfa = snapshot()
check(after_mfa[0]['authenticatorSecret'] == before[0]['authenticatorSecret'] and
      after_mfa[0]['mfa'] == before[0]['mfa'] and after_mfa[1:] == before[1:],
      'combined explicit MFA edit preserves existing authenticator/password/access')
db.close()
print('PASS native profile contact create/edit/clear/omit/validation/self/scope and exact MFA/password/access preservation')
