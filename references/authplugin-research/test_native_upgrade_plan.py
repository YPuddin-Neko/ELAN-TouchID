import hashlib
import uuid
import importlib.util
from pathlib import Path
import sys
import struct
import plistlib
import unittest
from dataclasses import replace

spec = importlib.util.spec_from_file_location('native_upgrade_plan', Path(__file__).with_name('native-upgrade-plan.py'))
u = importlib.util.module_from_spec(spec); sys.modules[spec.name] = u; spec.loader.exec_module(u)


def release(version):
    kernel = {'Contents/Info.plist': plistlib.dumps({'CFBundleVersion': version}), 'Contents/MacOS/ELANNativeProbe': (struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 24, 0, 0) + struct.pack('<2I', 0x1b, 24) + uuid.uuid5(uuid.NAMESPACE_DNS, version).bytes)}
    broker = ('broker-' + version).encode()
    return u.Release.verified(version, kernel, broker, u.kernel_digest(kernel), hashlib.sha256(broker).hexdigest())


class MemoryBackend:
    def __init__(self, source):
        self.state = u.State(source.version, source.version, source.kernel_hash, source.broker_hash, 'boot-1', '0', True, source.kernel_uuid, source.kernel_uuid)
        self.events = []
        self.fault = None
        self.calls = 0
        self.foreign_state = None

    def read_state(self):
        return self.state

    def backup(self, expected):
        if self.state != expected: raise u.ConcurrentChange('backup CAS')
        self.events.append('backup')
        if self.fault == 'backup': raise OSError('backup failure')
        if self.fault == 'backup-mismatch': return u.Backup('bad', expected.broker_hash)
        if self.fault == 'backup-uuid': return u.Backup(expected.kernel_hash, expected.broker_hash, '')
        if self.fault == 'backup-race': self.state = replace(self.state, revision='foreign')
        return u.Backup(expected.kernel_hash, expected.broker_hash, expected.disk_uuid)

    def write(self, expected, kind, **values):
        self.calls += 1
        if self.fault == ('race', self.calls):
            self.state = replace(self.state, broker_hash='foreign', revision='foreign')
            self.foreign_state = self.state
        if self.state != expected: raise u.ConcurrentChange('write CAS')
        self.events.append(kind)
        if self.fault == ('before', self.calls) or self.fault == ('recovery-failure', self.calls):
            raise OSError('before mutation')
        self.state = replace(self.state, revision=str(self.calls), **values)
        if self.fault == ('after', self.calls): raise u.WriteFailure('after mutation', self.state)
        if self.fault == ('unknown-return', self.calls): self.state = replace(self.state, kernel_hash='foreign')
        if self.fault == ('unreceipted-after', self.calls): raise OSError('ambiguous failure')
        return self.state

    def replace_broker(self, expected, broker):
        return self.write(expected, 'broker', broker_hash=hashlib.sha256(broker).hexdigest())

    def replace_kernel(self, expected, version, files):
        return self.write(expected, 'kernel:' + version, disk_version=version, kernel_hash=u.kernel_digest(files), disk_uuid=u.kernel_uuid(files))


class UpgradePlanTests(unittest.TestCase):
    def setUp(self):
        self.releases = {v: release(v) for v in ('0.4.0', '0.4.1', '0.4.2')}
        self.source = self.releases['0.4.1']; self.backend = MemoryBackend(self.source)

    def plan(self, action='upgrade', target='0.4.2'):
        return u.make_plan(action, self.backend.state, self.releases, target)

    def assert_source(self):
        s = self.backend.state
        self.assertEqual(s.disk_uuid, self.source.kernel_uuid)
        self.assertEqual(s.loaded_uuid, self.source.kernel_uuid)
        self.assertEqual((s.disk_version, s.kernel_hash, s.broker_hash), (self.source.version, self.source.kernel_hash, self.source.broker_hash))

    def test_same_version_missing_or_other_build_uuid_rejected_even_noop(self):
        original = self.backend.state
        foreign = self.releases['0.4.2'].kernel_uuid
        for changes in ({'loaded_uuid': ''}, {'disk_uuid': ''},
                        {'loaded_uuid': foreign}, {'disk_uuid': foreign},
                        {'loaded_uuid': foreign, 'disk_uuid': foreign}):
            with self.subTest(changes=changes):
                self.backend.state = replace(original, **changes)
                with self.assertRaises(u.PlanError): self.plan(target=self.source.version)
                self.assertEqual(self.backend.events, [])

    def test_release_identity_decoded_from_hash_verified_bytes(self):
        kernel = dict(self.source.kernel)
        self.assertEqual(self.source.kernel_uuid, u.kernel_uuid(kernel))
        kernel['Contents/MacOS/ELANNativeProbe'] = b'not Mach-O'
        with self.assertRaises(u.PlanError):
            u.Release.verified(self.source.version, kernel, self.source.broker,
                               u.kernel_digest(kernel), self.source.broker_hash)
        kernel = dict(self.source.kernel)
        kernel['Contents/Info.plist'] = plistlib.dumps({'CFBundleVersion': '0.4.9'})
        with self.assertRaises(u.PlanError):
            u.Release.verified(self.source.version, kernel, self.source.broker,
                               u.kernel_digest(kernel), self.source.broker_hash)

    def test_identity_change_after_planning_never_writes(self):
        pending = self.plan()
        self.backend.state = replace(self.backend.state, loaded_uuid=self.releases['0.4.2'].kernel_uuid)
        with self.assertRaises(u.ConcurrentChange): u.execute(pending, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_wrong_identity_in_owned_failure_receipt_is_not_recovered(self):
        original = self.backend.replace_kernel
        def kernel(expected, version, files):
            state = original(expected, version, files)
            self.backend.state = replace(state, disk_uuid=self.source.kernel_uuid)
            raise u.WriteFailure('incorrect identity', self.backend.state)
        self.backend.replace_kernel = kernel
        with self.assertRaises(u.TransactionError) as result:
            u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete)
        self.assertEqual(self.backend.calls, 2)

    def test_direct_upgrade_no_intermediate_baseline(self):
        result = u.execute(self.plan(), self.backend)
        self.assertEqual(self.backend.events, ['backup', 'broker', 'kernel:0.4.2'])
        self.assertEqual(self.backend.state.loaded_version, '0.4.1')
        self.assertTrue(result.reboot_required)
        self.assertNotIn('kernel:0.4.0', self.backend.events)
        self.assertEqual(self.backend.state.loaded_uuid, self.source.kernel_uuid)
        self.assertEqual(self.backend.state.disk_uuid, self.releases['0.4.2'].kernel_uuid)

    def test_explicit_rollback_only_targets_stable(self):
        p = self.plan('rollback', None)
        self.assertEqual(p.target.version, '0.4.0')
        u.execute(p, self.backend)
        self.assertEqual(self.backend.state.disk_version, '0.4.0')
        with self.assertRaises(u.PlanError): self.plan('rollback', '0.4.1')

    def test_pending_reboot_rejected(self):
        self.backend.state = replace(self.backend.state, loaded_version='0.4.0')
        with self.assertRaises(u.PlanError): self.plan()
        self.assertEqual(self.backend.events, [])

    def test_unknown_version_or_hash_rejected(self):
        original = self.backend.state
        for state in [replace(original, disk_version='0.4.9', loaded_version='0.4.9'), replace(original, kernel_hash='unknown'), replace(original, broker_hash='unknown'), replace(original, idle=False), replace(original, boot_id='')]:
            self.backend.state = state
            with self.assertRaises(u.PlanError): self.plan()
        self.backend.state = original
        with self.assertRaises(u.PlanError): self.plan(target='0.4.9')
        del self.releases['0.4.0']
        with self.assertRaises(u.PlanError): self.plan()

    def test_bad_release_payload_rejected(self):
        with self.assertRaises(u.PlanError): u.Release.verified('0.4.1', {'../x': b'x'}, b'b', 'x', 'y')
        with self.assertRaises(u.PlanError): u.Release.verified('0.4.1', {'x': b'x'}, b'b', 'bad', hashlib.sha256(b'b').hexdigest())

    def test_noop_is_read_only(self):
        result = u.execute(self.plan(target='0.4.1'), self.backend)
        self.assertFalse(result.changed); self.assertFalse(result.reboot_required)
        self.assertEqual(self.backend.events, [])

    def test_failure_before_each_write_restores_source_not_stable(self):
        for index in (1, 2):
            self.backend = MemoryBackend(self.source); self.backend.fault = ('before', index)
            with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
            self.assertTrue(result.exception.rollback_complete); self.assert_source()
            self.assertNotIn('kernel:0.4.0', self.backend.events)

    def test_failure_after_each_owned_write_restores_source(self):
        for index in (1, 2):
            self.backend = MemoryBackend(self.source); self.backend.fault = ('after', index)
            with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
            self.assertTrue(result.exception.rollback_complete); self.assert_source()
            self.assertNotIn('kernel:0.4.0', self.backend.events)

    def test_backup_failure_or_mismatch_never_writes(self):
        for fault in ('backup', 'backup-mismatch', 'backup-uuid', 'backup-race'):
            self.backend = MemoryBackend(self.source); self.backend.fault = fault
            with self.assertRaises(Exception): u.execute(self.plan(), self.backend)
            self.assertEqual(self.backend.events, ['backup']); self.assert_source()

    def test_plan_state_changed_never_writes(self):
        plan = self.plan(); self.backend.state = replace(self.backend.state, revision='foreign')
        with self.assertRaises(u.ConcurrentChange): u.execute(plan, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_race_before_write_preserves_foreign_state(self):
        for index in (1, 2):
            self.backend = MemoryBackend(self.source); self.backend.fault = ('race', index)
            with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
            self.assertFalse(result.exception.rollback_complete)
            self.assertEqual(self.backend.state, self.backend.foreign_state)
            self.assertEqual(self.backend.calls, index)

    def test_unreceipted_or_unknown_mutation_never_overwritten(self):
        for fault in ('unknown-return', 'unreceipted-after'):
            self.backend = MemoryBackend(self.source); self.backend.fault = (fault, 1)
            with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
            self.assertFalse(result.exception.rollback_complete); self.assertEqual(self.backend.calls, 1)

    def test_foreign_change_during_kernel_recovery_stops_before_broker(self):
        original = self.backend.replace_kernel
        def kernel(expected, version, files):
            result = original(expected, version, files)
            if version == '0.4.2':
                raise u.WriteFailure('after kernel', result)
            self.backend.state = replace(result, broker_hash='foreign')
            return self.backend.state
        self.backend.replace_kernel = kernel
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete)
        self.assertEqual(self.backend.state.broker_hash, 'foreign')
        self.assertEqual(self.backend.calls, 3)

    def test_recovery_failure_reports_incomplete(self):
        original = self.backend.replace_kernel
        def kernel(expected, version, files):
            result = original(expected, version, files)
            if version == '0.4.2':
                self.backend.fault = ('recovery-failure', 3)
                raise u.WriteFailure('after kernel', result)
            return result
        self.backend.replace_kernel = kernel
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete)
        self.assertEqual(self.backend.state.disk_version, '0.4.2')
        self.assertEqual(self.backend.calls, 3)


if __name__ == '__main__': unittest.main()
