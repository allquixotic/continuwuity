#!/usr/bin/env python3
"""Compare aggregate offline audits without reading or printing credentials."""
import argparse
import json
import os

CRITICAL = '''
alias_roomid alias_userid aliasid_alias backupid_algorithm backupid_etag backupkeyid_backup
eventid_outlierpdu eventid_pduid eventid_shorteventid fallbackkeyid_fallbackkey
id_appserviceregistrations keyid_key mediaid_file mediaid_user onetimekeyid_onetimekeys
roomuserdataid_accountdata roomusertype_roomuserdataid shorteventid_eventid
shortstatehash_statediff shortstatekey_statekey statehash_shortstatehash statekey_shortstatekey
todeviceid_events token_userdeviceid userdeviceid_metadata userdeviceid_token
userdeviceid_tokenexpires userfilterid_filter userid_avatarurl userid_blurhash
userid_dehydrateddevice userid_displayname userid_masterkeyid userid_selfsigningkeyid
userid_usersigningkeyid useridprofilekey_value roomid_shortroomid roomid_shortstatehash
roomid_lasttimelinecount
'''.split()
p = argparse.ArgumentParser()
p.add_argument('before'); p.add_argument('after'); p.add_argument('--output',required=True)
p.add_argument('--account-data-proof')
a = p.parse_args()
before, after = [json.load(open(path)) for path in (a.before,a.after)]
failures = []
checked = []
proof = json.load(open(a.account_data_proof)) if a.account_data_proof else None
account_families = ['roomuserdataid_accountdata','roomusertype_roomuserdataid']
if proof:
    assert proof['passed'] and proof['changed_pointers']==1
    assert proof['exception']=='server_user_m.push_rules_stream_counter_only'
    for name in account_families:
        assert proof['before_family_sha256'][name]==before['families'][name]['sha256']
        assert proof['after_family_sha256'][name]==after['families'][name]['sha256']
for name in CRITICAL:
    old = before['families'].get(name)
    new = after['families'].get(name)
    if old is None:
        continue
    checked.append(name)
    if old != new and not (proof and name in account_families):
        failures.append(name)
if before['families']['pduid_pdu']['count'] != after['families']['pduid_pdu']['count']:
    failures.append('timeline_count')
if before['timeline']['signed_json_sha256'] != after['timeline']['signed_json_sha256']:
    failures.append('timeline_signed_json')
for name in ['keypair_sha256','nonempty_password_count','nonempty_passwords_sha256']:
    if before['identity'][name] != after['identity'][name]:
        failures.append(name)
for name in ['unembed_unsigned_info','split_userid_password']:
    if not after['identity'].get(name):
        failures.append(name+'_marker')
changed = [name for name,old in before['families'].items() if old != after['families'].get(name)]
result = {'passed':not failures,'failures':failures,'immutable_families_checked':len(checked),
          'account_data_semantically_preserved':bool(proof),
          'timeline_events':after['families']['pduid_pdu']['count'],
          'outlier_events':after['families']['eventid_outlierpdu']['count'],
          'nonempty_passwords':after['identity']['nonempty_password_count'],
          'changed_families':changed,
          'added_families':sorted(set(after['families'])-set(before['families'])),
          'historical_fields':after['timeline']['extra_fields']}
fd = os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as f:
    json.dump(result,f,indent=2,sort_keys=True)
print(json.dumps(result,sort_keys=True))
assert not failures, 'offline preservation checks failed'
