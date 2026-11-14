"""Summarize only bounded protocol fields; never copy raw diagnostic content."""
import json
import re

INSPECTION = re.compile(r"PROVIDER_BROKER settings_stage=connection_inspection call=(0x[0-9a-fA-F]{1,8}) status=(-?\d+) image_matched=([01]) observation=([0-4])(?: stage=([0-9]))? allowed=([01])")
CLEANUP = re.compile(r"PROVIDER_BROKER settings_cleanup_call=(0x[0-9a-fA-F]{1,8}) status=(-?\d+) restored=([01])")
RECOVERY = re.compile(r"PROVIDER_BROKER settings_stage=connection_recovery attempted=([01]) status=(-?\d+)(?: modified=(0|1|unknown))?(?: phase=([0-7]) rollback_status=(-?\d+))?")
ATTACH = re.compile(r"ELAN_PROVIDER settings_attach=(-?\d+) pid=([1-9]\d*)")
RESTORE = re.compile(r"ELAN_PROVIDER settings_restore=(-?\d+)")
DONE = re.compile(r"PROVIDER_BROKER_DONE status=(-?\d+)")


def summarize(broker_log, provider_log, result=None):
    """Return sanitized phase outcomes. Observation/exit success never proves settings functionality."""
    result = {} if result is None else result
    if not isinstance(result, dict) or not isinstance(broker_log, str) or not isinstance(provider_log, str):
        raise TypeError('Expected log strings and an optional result dictionary')
    issues = []
    def issue(value):
        if value not in issues:
            issues.append(value)
    def signed(value):
        number = int(value)
        if not -(2**31) <= number < 2**31:
            raise ValueError('out-of-range status')
        return number
    def flag(name):
        value = result.get(name)
        if value is not None and type(value) is not bool:
            issue('invalid_result_' + name)
            return None
        return value
    inspected, attached, restores, cleanups, recoveries, dones = [], [], [], [], [], []
    protocol_order = []
    def parse(log, patterns):
        for line in log.splitlines():
            for marker, pattern, consume in patterns:
                if marker not in line:
                    continue
                match = pattern.fullmatch(line)
                if match is None:
                    issue('malformed_' + marker.split('=')[-1].replace(' ', '_'))
                else:
                    try:
                        consume(match)
                    except (ValueError, OverflowError):
                        issue('invalid_protocol_number')
                break
    def inspection(m):
        call, status, image, observation, stage, allowed = m.groups()
        value = dict(call_status=int(call, 16), operation_status=signed(status), image_matched=image == '1',
                     observation=int(observation), stage=None if stage is None else int(stage), allowed=allowed == '1')
        if ((value['observation'] != 0 and (not value['image_matched'] or value['operation_status'] != 0 or value['call_status'] != 0)) or
                (value['allowed'] and (value['call_status'] or value['operation_status'] or not value['image_matched'] or
                                      value['observation'] not in (1, 2) or value['stage'] not in (None, 9)))):
            issue('inconsistent_inspection')
        inspected.append(value)
        protocol_order.append('inspection')
    def recovery(m):
        attempted, status, modified, phase, rollback = m.groups()
        value = dict(attempted=attempted == '1', status=signed(status),
                     modified=None if modified in (None, 'unknown') else modified == '1',
                     phase=None if phase is None else int(phase), rollback_status=None if rollback is None else signed(rollback))
        if phase is not None and value['modified'] and (int(phase) != 7 or value['status'] or value['rollback_status']):
            issue('inconsistent_recovery')
        if value['modified'] is None:
            issue('recovery_modification_unknown')
        if value['modified'] and not value['attempted']:
            issue('inconsistent_recovery')
        recoveries.append(value)
        protocol_order.append('recovery')
    parse(broker_log, [
        ('settings_stage=connection_inspection', INSPECTION, inspection),
        ('settings_stage=connection_recovery', RECOVERY, recovery),
        ('settings_cleanup_call=', CLEANUP, lambda m: cleanups.append((int(m[1], 16), signed(m[2]), m[3] == '1'))),
        ('PROVIDER_BROKER_DONE', DONE, lambda m: dones.append(signed(m[1]))),
    ])
    parse(provider_log, [
        ('settings_attach=', ATTACH, lambda m: attached.append(signed(m[1]))),
        ('settings_restore=', RESTORE, lambda m: restores.append(signed(m[1]))),
    ])
    if inspected and any(x != inspected[-1] for x in inspected):
        issue('multiple_inspection_outcomes')
    if attached and any((x == 0) != (attached[-1] == 0) for x in attached):
        issue('mixed_attach_outcomes')
    if recoveries and any(x != recoveries[-1] for x in recoveries):
        issue('multiple_recovery_outcomes')
    if inspected and inspected[-1]['allowed'] and inspected[-1]['observation'] == 2:
        if not recoveries or not recoveries[-1]['attempted'] or protocol_order[-1] != 'recovery':
            issue('recovery_evidence_missing')
    observed = flag('settings_diagnostic_observed')
    native = flag('native_success')
    restored = flag('restored')
    # The content of errors may contain private paths or data; retain only their presence.
    cleanup_error = result.get('cleanup_error') not in (None, '', False)
    diagnostic = {'state': 'not_run', 'stage': None, 'image_matched': None, 'observation': None,
                  'allowed': None, 'call_status': None, 'operation_status': None}
    if inspected:
        diagnostic.update(inspected[-1])
        diagnostic['state'] = 'accepted' if inspected[-1]['allowed'] else 'rejected'
    attachment = {'state': 'not_run', 'status': attached[-1] if attached else None}
    if attached:
        attachment['state'] = 'attached' if attached[-1] == 0 else 'rejected'
    if inspected and not inspected[-1]['allowed'] and attached and attached[-1] == 0:
        issue('attachment_after_rejection')
    cleanup = {'state': 'not_run', 'broker_status': cleanups[-1][1] if cleanups else None,
               'provider_restore_status': restores[-1] if restores else None, 'reported_restored': restored}
    cleanup_failed = cleanup_error or restored is False or bool(cleanups and (cleanups[-1][0] or cleanups[-1][1] or not cleanups[-1][2])) or bool(restores and restores[-1]) or bool(dones and dones[-1])
    if cleanup_failed:
        cleanup['state'] = 'failed'
    elif cleanups and cleanups[-1] == (0, 0, True) and (not dones or dones[-1] == 0):
        cleanup['state'] = 'success'
    elif restored is True:
        cleanup['state'] = 'reported_only'
    elif inspected or attached or recoveries or observed:
        cleanup['state'] = 'unknown'
    if restored is True and cleanup_failed:
        issue('conflicting_cleanup_evidence')
    if restored is True and not cleanups:
        issue('cleanup_not_independently_confirmed')
    recovery_value = recoveries[-1] if recoveries else {'attempted': None, 'status': None, 'modified': None, 'phase': None, 'rollback_status': None}
    if cleanup_failed:
        state = 'cleanup_failed'
    elif issues:
        state = 'uncertain'
    elif cleanup['state'] == 'success':
        state = 'restored'
    elif diagnostic['state'] == 'rejected' or attachment['state'] == 'rejected':
        state = 'diagnostic_rejected'
    elif attachment['state'] == 'attached':
        state = 'attached'
    elif observed:
        state = 'observed_only'
    elif inspected or recoveries:
        state = 'uncertain'
    else:
        state = 'not_run'
    return {'schema_version': 1, 'state': state, 'diagnostic': diagnostic, 'attachment': attachment,
            'recovery': recovery_value, 'cleanup': cleanup, 'user_observed': observed is True,
            'native_authentication_passed': native, 'settings_function_verified': False, 'issues': issues}


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument('--broker-log', required=True)
    parser.add_argument('--provider-log', required=True)
    parser.add_argument('--result')
    args = parser.parse_args()
    result = json.loads(Path(args.result).read_text()) if args.result else None
    print(json.dumps(summarize(Path(args.broker_log).read_text(errors='replace'),
                               Path(args.provider_log).read_text(errors='replace'), result), indent=2))
