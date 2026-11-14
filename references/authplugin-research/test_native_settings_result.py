import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('settings_result', Path(__file__).with_name('native-settings-result.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
GOOD = 'PROVIDER_BROKER settings_stage=connection_inspection call=0x0 status=0 image_matched=1 observation=1 stage=9 allowed=1'
REJECT = 'PROVIDER_BROKER settings_stage=connection_inspection call=0x0 status=-31001 image_matched=0 observation=0 stage=5 allowed=0'
CLEAN = 'PROVIDER_BROKER settings_cleanup_call=0x0 status=0 restored=1'
DONE = 'PROVIDER_BROKER_DONE status=0'
ATTACH = 'ELAN_PROVIDER settings_attach=0 pid=4216'

class SummaryTests(unittest.TestCase):
    def test_extended_recovery(self):
        r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=-31001 modified=unknown phase=4 rollback_status=-31002', '')
        self.assertEqual(r['recovery']['phase'], 4)
        self.assertEqual(r['recovery']['rollback_status'], -31002)
        self.assertEqual(r['recovery']['status'], -31001)
        self.assertIsNone(r['recovery']['modified'])

    def test_extended_recovery_rejects_bad_phase_and_conflicting_success(self):
        for suffix in ('phase=8 rollback_status=0', 'phase=7 rollback_status=99999999999999999'):
            r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=0 modified=1 ' + suffix, '')
            self.assertEqual(r['state'], 'uncertain')
        r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=0 modified=1 phase=4 rollback_status=0', '')
        self.assertIn('inconsistent_recovery', r['issues'])

    def test_not_run(self):
        r = m.summarize('', '')
        self.assertEqual(r['state'], 'not_run'); self.assertIsNone(r['recovery']['attempted'])

    def test_exit_zero_is_not_success(self):
        r = m.summarize(DONE, '')
        self.assertEqual(r['state'], 'not_run'); self.assertFalse(r['settings_function_verified'])

    def test_observed_only(self):
        r = m.summarize('', '', {'settings_diagnostic_observed': True, 'native_success': True})
        self.assertEqual(r['state'], 'observed_only'); self.assertFalse(r['settings_function_verified'])

    def test_diagnostic_rejected(self):
        r = m.summarize(REJECT, 'ELAN_PROVIDER settings_attach=-536870184 pid=4216')
        self.assertEqual(r['state'], 'diagnostic_rejected'); self.assertEqual(r['diagnostic']['stage'], 5)

    def test_rejected_but_restored(self):
        r = m.summarize('\n'.join([REJECT, CLEAN, DONE]), '', {'restored': True, 'settings_diagnostic_observed': True})
        self.assertEqual(r['state'], 'restored'); self.assertEqual(r['diagnostic']['state'], 'rejected')
        self.assertFalse(r['settings_function_verified'])

    def test_attached_not_functional_success(self):
        r = m.summarize(GOOD, ATTACH)
        self.assertEqual(r['state'], 'attached'); self.assertFalse(r['settings_function_verified'])

    def test_complete_cleanup(self):
        r = m.summarize(GOOD + '\n' + CLEAN + '\n' + DONE, ATTACH + '\nELAN_PROVIDER settings_restore=0', {'restored': True})
        self.assertEqual(r['cleanup']['state'], 'success'); self.assertEqual(r['state'], 'restored')

    def test_cleanup_failure_overrides_success_claim(self):
        r = m.summarize(CLEAN.replace('restored=1', 'restored=0'), '', {'restored': True})
        self.assertEqual(r['state'], 'cleanup_failed'); self.assertIn('conflicting_cleanup_evidence', r['issues'])

    def test_result_restored_false(self):
        r = m.summarize(CLEAN, '', {'restored': False})
        self.assertEqual(r['state'], 'cleanup_failed')

    def test_provider_restore_failure(self):
        r = m.summarize(CLEAN, 'ELAN_PROVIDER settings_restore=-42')
        self.assertEqual(r['state'], 'cleanup_failed')

    def test_broker_completion_failure(self):
        r = m.summarize(CLEAN + '\nPROVIDER_BROKER_DONE status=1', '')
        self.assertEqual(r['state'], 'cleanup_failed')

    def test_restored_report_without_log_is_not_independent(self):
        r = m.summarize('', '', {'restored': True})
        self.assertEqual(r['state'], 'uncertain'); self.assertEqual(r['cleanup']['state'], 'reported_only')

    def test_recovery_requires_explicit_event(self):
        r = m.summarize('PROVIDER_BROKER settings_recovery_requested=1', '')
        self.assertIsNone(r['recovery']['attempted']); self.assertIsNone(r['recovery']['modified'])

    def test_recovery_partial_failure(self):
        r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=-43 modified=1', '')
        self.assertTrue(r['recovery']['attempted']); self.assertTrue(r['recovery']['modified'])
        self.assertEqual(r['recovery']['status'], -43); self.assertEqual(r['state'], 'uncertain')

    def test_completed_empty_allowed_with_recovery_evidence(self):
        inspection = GOOD.replace('observation=1', 'observation=2')
        recovery = 'PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=0 modified=1'
        r = m.summarize('\n'.join([inspection, recovery, CLEAN, DONE]), ATTACH, {'restored': True})
        self.assertEqual(r['state'], 'restored'); self.assertEqual(r['issues'], [])
        self.assertEqual(r['diagnostic']['observation'], 2); self.assertTrue(r['recovery']['modified'])

    def test_completed_empty_allowed_without_recovery_evidence(self):
        inspection = GOOD.replace('observation=1', 'observation=2')
        for recovery in ['', '\nPROVIDER_BROKER settings_stage=connection_recovery attempted=0 status=0 modified=0']:
            r = m.summarize(inspection + recovery + '\n' + CLEAN, ATTACH, {'restored': True})
            self.assertEqual(r['state'], 'uncertain'); self.assertIn('recovery_evidence_missing', r['issues'])

    def test_prior_recovery_does_not_satisfy_later_inspection(self):
        inspection = GOOD.replace('observation=1', 'observation=2')
        recovery = 'PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=0 modified=1'
        r = m.summarize(recovery + '\n' + inspection + '\n' + CLEAN, ATTACH)
        self.assertEqual(r['state'], 'uncertain'); self.assertIn('recovery_evidence_missing', r['issues'])

    def test_recovery_unknown_or_missing_modification(self):
        for suffix in [' modified=unknown', '']:
            r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=-43' + suffix, '')
            self.assertTrue(r['recovery']['attempted']); self.assertIsNone(r['recovery']['modified'])
            self.assertEqual(r['recovery']['status'], -43)
            self.assertEqual(r['state'], 'uncertain'); self.assertIn('recovery_modification_unknown', r['issues'])

    def test_confirmed_recovery_event(self):
        r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=1 status=0 modified=1', '')
        self.assertTrue(r['recovery']['attempted']); self.assertTrue(r['recovery']['modified'])
        self.assertEqual(r['recovery']['status'], 0); self.assertFalse(r['settings_function_verified'])

    def test_inconsistent_recovery(self):
        r = m.summarize('PROVIDER_BROKER settings_stage=connection_recovery attempted=0 status=0 modified=1', '')
        self.assertIn('inconsistent_recovery', r['issues'])

    def test_multiple_outcomes_uncertain(self):
        r = m.summarize(GOOD + '\n' + REJECT + '\n' + CLEAN, '')
        self.assertEqual(r['state'], 'uncertain'); self.assertIn('multiple_inspection_outcomes', r['issues'])

    def test_duplicate_events_allowed(self):
        r = m.summarize(GOOD + '\n' + GOOD + '\n' + CLEAN + '\n' + CLEAN, ATTACH)
        self.assertEqual(r['state'], 'restored'); self.assertEqual(r['issues'], [])

    def test_malformed_and_out_of_range_status(self):
        for line in [GOOD + ' private=secret', GOOD.replace('status=0', 'status=no'), GOOD.replace('status=0', 'status=2147483648')]:
            r = m.summarize(line, '')
            self.assertEqual(r['state'], 'uncertain'); self.assertTrue(r['issues'])

    def test_unknown_observation_is_rejected(self):
        r = m.summarize(GOOD.replace('observation=1', 'observation=9'), '')
        self.assertEqual(r['state'], 'uncertain')

    def test_legacy_stage_unavailable(self):
        r = m.summarize(GOOD.replace(' stage=9', ''), ATTACH)
        self.assertEqual(r['state'], 'attached'); self.assertIsNone(r['diagnostic']['stage'])

    def test_conflicting_attachment(self):
        r = m.summarize(REJECT, ATTACH)
        self.assertEqual(r['state'], 'uncertain'); self.assertIn('attachment_after_rejection', r['issues'])

    def test_privacy_no_raw_content(self):
        secret = '/Users/private/biometric-identity-AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE 0xdeadbeef'
        r = m.summarize('unrelated ' + secret + '\n' + REJECT, secret, {'cleanup_error': secret, 'other': secret})
        self.assertNotIn(secret, json.dumps(r)); self.assertNotIn('AAAAAAAA', json.dumps(r))
        self.assertEqual(r['state'], 'cleanup_failed')

    def test_invalid_result_flags(self):
        r = m.summarize('', '', {'restored': 'true', 'native_success': 1, 'settings_diagnostic_observed': 'yes'})
        self.assertEqual(r['state'], 'uncertain'); self.assertFalse(r['user_observed']); self.assertIsNone(r['native_authentication_passed'])

    def test_inputs_typed(self):
        with self.assertRaises(TypeError): m.summarize(None, '')
        with self.assertRaises(TypeError): m.summarize('', '', [])

if __name__ == '__main__': unittest.main()
