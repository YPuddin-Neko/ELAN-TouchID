import copy
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch
import test_native_update_preflight as fixtures

spec = importlib.util.spec_from_file_location('current_update', Path(__file__).with_name('native-current-update.py'))
u = importlib.util.module_from_spec(spec); spec.loader.exec_module(u)


class CurrentUpdateTests(unittest.TestCase):
    def setUp(self):
        fixtures.PreflightTests.setUp(self)
        self.install = self.root
        self.parent = self.install.parent
        (self.install / 'state').mkdir()
        (self.install / 'state/unrelated').write_text('preserve')
        self.oc = self.parent / 'EFI/OC'; (self.oc / 'Kexts').mkdir(parents=True)
        shutil.copytree(self.install / u.KERNEL, self.oc / 'Kexts' / u.BUNDLE)
        entry = {'Arch': 'x86_64', 'BundlePath': u.BUNDLE, 'Comment': 'ELAN native credential interface probe 0.4.0', 'Enabled': True,
                 'ExecutablePath': 'Contents/MacOS/ELANNativeProbe', 'MaxKernel': '24.6.0', 'MinKernel': '24.6.0', 'PlistPath': 'Contents/Info.plist'}
        (self.oc / 'config.plist').write_bytes(plistlib.dumps({'Kernel': {'Add': [entry]}, 'Unrelated': 19}))
        self.package = self.parent / 'package'; self.package.mkdir()
        self.mapping = {}
        for path in sorted(self.install.rglob('*')):
            if not path.is_file() or 'state' in path.relative_to(self.install).parts: continue
            relative = str(path.relative_to(self.install))
            if relative.startswith(u.KERNEL + '/'):
                origin = 'kernel/' + u.BUNDLE + relative[len(u.KERNEL):]
            elif relative.endswith('.py'): origin = 'scripts/' + relative
            else: origin = 'userland/' + relative
            output = self.package / origin; output.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            if path.name == 'ELANNativeProbe': data = fixtures.binary(11, fixtures.OTHER)
            elif origin.startswith('userland/') and '/MacOS/' in origin: data += b'candidate'
            elif origin.startswith('scripts/'): data += b'# new\n'
            output.write_bytes(data); output.chmod(path.stat().st_mode & 0o777)
            self.mapping[origin] = relative
        self.manifest = {'schema_version': 1, 'version': '0.4.0', 'install_map': self.mapping,
                         'kernel_identity': u.identity.artifact_identity(self.package / 'kernel' / u.BUNDLE, '0.4.0')}
        for name in u.RUNTIME_SCRIPTS:
            origin = 'scripts/' + name
            if origin not in self.mapping:
                (self.package / origin).write_text('# inert runtime fixture\n')
                self.mapping[origin] = name
        (self.package / 'kernel/kernel-identity.json').write_text(json.dumps(self.manifest['kernel_identity']))
        (self.package / 'kernel/elan-native-probe').write_bytes(fixtures.binary())
        self.mapping['kernel/kernel-identity.json'] = 'payload/native-kernel-probe-06/kernel-identity.json'
        self.mapping['kernel/elan-native-probe'] = 'payload/native-kernel-probe-06/elan-native-probe'
        (self.package / 'kernel/manage-efi.py').write_text('# inert validator fixture\n')
        self.mapping['kernel/manage-efi.py'] = 'payload/native-kernel-probe-06/manage-efi.py'
        self.save_manifest()
        self.active = False; self.boot = fixtures.BOOT
        self.baseline = u.preflight.inspect(self.install, command_fn=self.command)
        self.backend = u.Backend(self.install, self.oc, self.observe, self.idle, lambda root: None, runtime=self.runtime)

    write = fixtures.PreflightTests.write
    command = fixtures.PreflightTests.command

    def save_manifest(self):
        self.manifest['sha256'] = {name: hashlib.sha256((self.package / name).read_bytes()).hexdigest() for name in self.mapping}
        (self.package / 'package.json').write_text(json.dumps(self.manifest))

    def observe(self):
        return u.preflight.inspect(self.install, command_fn=self.command)

    def runtime(self):
        return dict(self.baseline, boot_uuid=self.boot)

    def idle(self):
        if self.active: raise u.UpdateError('active')
        return {'inactive': True}

    def prepare(self): return self.backend.prepare(self.package)

    def apply(self):
        plan = self.prepare()
        return plan, self.backend.apply(self.package, plan['approval_digest'])

    def transaction(self):
        transaction, = self.parent.glob('.elan-current-update-*')
        return transaction

    def test_prepare_has_no_writes_or_process_execution(self):
        before = u.tree(self.parent)
        with patch.object(u.subprocess, 'run', side_effect=AssertionError('no commands')):
            plan = self.prepare()
        self.assertEqual(u.tree(self.parent), before)
        self.assertNotEqual(plan['source_identity']['macho_uuid'], plan['target_identity']['macho_uuid'])

    def test_apply_and_preboot_rollback_restore_all_assets(self):
        before = u.tree(self.install); config = (self.oc / 'config.plist').read_bytes()
        plan, result = self.apply()
        self.assertEqual(result['state'], 'committed')
        self.assertEqual((self.install / 'state/unrelated').read_text(), 'preserve')
        self.assertEqual((self.oc / 'config.plist').read_bytes(), config)
        self.assertEqual(u.identity.artifact_identity(self.install / u.KERNEL, '0.4.0'), plan['target_identity'])
        self.assertEqual(u.identity.artifact_identity(self.oc / 'Kexts' / u.BUNDLE, '0.4.0'), plan['target_identity'])
        self.assertEqual(self.backend.rollback(result['transaction'], plan['approval_digest'])['state'], 'rolled_back')
        after = u.tree(self.install); after.pop('state/runtime.lock')
        self.assertEqual(after, before)

    def test_no_approval_or_changed_package_never_replaces_assets(self):
        before = u.tree(self.install)
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, '')
        plan = self.prepare()
        (self.package / next(iter(self.mapping))).write_bytes(b'foreign')
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'])
        after = u.tree(self.install); after.pop('state/runtime.lock', None)
        self.assertEqual(after, before)

    def test_same_version_wrong_loaded_source_rejected(self):
        self.backend.observe = lambda: dict(self.baseline, loaded_kernel=dict(self.baseline['loaded_kernel'], macho_uuid=fixtures.OTHER))
        with self.assertRaisesRegex(u.UpdateError, 'source_identity'): self.prepare()

    def test_wrong_efi_and_active_session_rejected(self):
        self.active = True
        with self.assertRaises(u.UpdateError): self.prepare()
        self.active = False
        (self.oc / 'Kexts' / u.BUNDLE / 'Contents/MacOS/ELANNativeProbe').write_bytes(fixtures.binary(11, fixtures.OTHER))
        with self.assertRaisesRegex(u.UpdateError, 'source_identity'): self.prepare()

    def test_invalid_destinations_and_duplicate_map_rejected(self):
        key = next(iter(self.mapping)); old = self.mapping[key]
        for destination in ('../escape', 'state/data', 'previous/secrets', 'different'):
            self.mapping[key] = destination; self.save_manifest()
            with self.assertRaises(u.UpdateError): self.prepare()
        self.mapping[key] = old

    def test_each_write_interruption_can_restore_verified_backup(self):
        # Every managed top-level swap plus the sole changed EFI binary.
        for point in ['installed:' + n for n in sorted({p.split('/')[0] for p in self.mapping.values()})] + ['efi:Contents/MacOS/ELANNativeProbe']:
            with self.subTest(point=point):
                plan = self.prepare()
                def fault(name):
                    if name == point: raise KeyboardInterrupt()
                self.backend.fault = fault
                with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'])
                self.backend.fault = None
                txn = sorted(self.parent.glob('.elan-current-update-*'), key=lambda p: p.stat().st_mtime_ns)[-1]
                self.backend.rollback(txn, plan['approval_digest'])
                self.assertEqual(u.identity.artifact_identity(self.install / u.KERNEL, '0.4.0'), plan['source_identity'])

    def test_foreign_efi_change_preserved_during_rollback(self):
        plan, result = self.apply()
        file = self.oc / 'Kexts' / u.BUNDLE / 'Contents/MacOS/ELANNativeProbe'
        file.write_bytes(b'foreign')
        before = u.tree(self.install)
        with self.assertRaisesRegex(u.UpdateError, 'foreign_efi'): self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.assertEqual(file.read_bytes(), b'foreign'); self.assertEqual(u.tree(self.install), before)

    def test_foreign_userland_change_preserved(self):
        plan, result = self.apply()
        (self.install / 'ELANNativeBroker').write_bytes(b'foreign')
        before = u.tree(self.install)
        with self.assertRaisesRegex(u.UpdateError, 'foreign_install'): self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.assertEqual(u.tree(self.install), before)

    def test_boot_change_blocks_remaining_updates_and_rollback(self):
        plan = self.prepare()
        def fault(name): self.boot = fixtures.OTHER
        self.backend.fault = fault
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'])
        with self.assertRaisesRegex(u.UpdateError, 'original_boot'): self.backend.rollback(self.transaction(), plan['approval_digest'])

    def test_corrupt_backup_never_restored(self):
        plan, result = self.apply()
        (Path(result['transaction']) / 'before/ELANNativeBroker').write_bytes(b'corrupt')
        before = u.tree(self.install)
        with self.assertRaisesRegex(u.UpdateError, 'backup_changed'): self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.assertEqual(u.tree(self.install), before)

    def test_displaced_foreign_userland_is_retained_not_committed(self):
        plan = self.prepare(); original = self.backend.swap; changed = []
        def racing(left, right):
            if not changed and left.name == 'ELANNativeProvider.app':
                victim = left / 'Contents/Info.plist'
                victim.write_bytes(victim.read_bytes() + b'FOREIGN')
                changed.append(True)
            original(left, right)
        self.backend.swap = racing
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'])
        txn = self.transaction()
        self.assertTrue((txn / 'after/ELANNativeProvider.app/Contents/Info.plist').read_bytes().endswith(b'FOREIGN'))
        record = json.loads((txn / 'transaction.json').read_text())
        self.assertTrue(record['conflict']); self.assertNotEqual(record['phase'], 'committed')
        with self.assertRaisesRegex(u.UpdateError, 'requires_review'): self.backend.rollback(txn, plan['approval_digest'])

    def test_displaced_foreign_efi_is_retained_not_committed(self):
        plan = self.prepare(); original = self.backend.swap
        def racing(left, right):
            if left == self.oc / 'Kexts' / u.BUNDLE / 'Contents/MacOS/ELANNativeProbe':
                left.write_bytes(b'FOREIGN EFI')
            original(left, right)
        self.backend.swap = racing
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'])
        txn = self.transaction(); record = json.loads((txn / 'transaction.json').read_text())
        self.assertTrue(record['conflict'])
        self.assertIn(b'FOREIGN EFI', [Path(p).read_bytes() for p in record['retained_efi_files']])

    def test_unsupported_or_false_success_exchange_never_installs(self):
        plan = self.prepare(); before = u.tree(self.install)
        def ordinary_rename(left, right):
            import os
            os.replace(left, right)
        self.backend.swap = ordinary_rename
        with self.assertRaisesRegex(u.UpdateError, 'semantics_invalid'):
            self.backend.apply(self.package, plan['approval_digest'])
        self.assertEqual(list(self.parent.glob('.elan-current-update-*')), [])
        after = u.tree(self.install); after.pop('state/runtime.lock', None)
        self.assertEqual(after, before)
        self.backend.storage_status = lambda: {'filesystem': 'msdos', 'exchange_supported': False}
        plan = self.prepare()
        with self.assertRaisesRegex(u.UpdateError, 'exclusive_maintenance'):
            self.backend.apply(self.package, plan['approval_digest'])
        self.assertEqual(list(self.oc.glob('.elan-exchange-check-*')), [])

    def test_new_asset_added_and_rollback_removes_only_owned_generation(self):
        origin = 'scripts/native-new-test.py'; self.mapping[origin] = 'native-new-test.py'
        (self.package / origin).write_text('# new helper\n'); self.save_manifest()
        plan, result = self.apply()
        self.assertTrue((self.install / 'native-new-test.py').exists())
        self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.assertFalse((self.install / 'native-new-test.py').exists())

    def test_rollback_retry_after_restore_copy_interruption(self):
        plan, result = self.apply(); original = self.backend.swap; failed = []
        def interrupted(left, right):
            if not failed and left.name not in ('a', 'b'):
                failed.append(True); raise KeyboardInterrupt()
            original(left, right)
        self.backend.swap = interrupted
        # First restore may be the EFI exchange; retry remains valid in either phase.
        with self.assertRaises(KeyboardInterrupt): self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.backend.swap = original
        self.assertEqual(self.backend.rollback(result['transaction'], plan['approval_digest'])['state'], 'rolled_back')

    def test_live_runtime_requires_explicit_no_pending_restore(self):
        def commands(args):
            if args[0] == '/bin/launchctl': return 113, b''
            if args[0] == '/bin/ps': return 0, b'/sbin/launchd\n'
            return 0, plistlib.dumps([properties])
        properties = {'AuthenticationEnabled': False, 'ProviderSessionActive': False}
        with patch.object(u.os.path, 'lexists', return_value=False), patch.object(u, 'command', side_effect=commands):
            with self.assertRaisesRegex(u.UpdateError, 'driver_not_idle'): u.live_runtime()
            properties['ProviderRestorePending'] = True
            with self.assertRaisesRegex(u.UpdateError, 'driver_not_idle'): u.live_runtime()
            properties['ProviderRestorePending'] = False
            self.assertTrue(u.live_runtime()['driver_session_inactive'])

    def test_mount_validation_runs_before_each_update(self):
        calls = []
        def check(): calls.append(True)
        self.backend.location_check = check
        self.apply()
        self.assertGreater(len(calls), len({p.split('/')[0] for p in self.mapping.values()}))

    def test_missing_runtime_dependency_is_rejected(self):
        for name in u.RUNTIME_SCRIPTS | {'payload/native-kernel-probe-06/kernel-identity.json', 'payload/native-kernel-probe-06/manage-efi.py'}:
            with self.subTest(name=name):
                origin = next(k for k, v in self.mapping.items() if v == name)
                self.mapping.pop(origin); self.save_manifest()
                with self.assertRaisesRegex(u.UpdateError, 'incomplete_package'): self.prepare()
                self.mapping[origin] = name
        self.save_manifest()

    def test_disk_only_mode_reports_pending_without_weakening_strict(self):
        properties = {'AuthenticationEnabled': False, 'ProviderSessionActive': False}
        calls = []
        def commands(args):
            calls.append(args[0])
            if args[0] == '/bin/launchctl': return 113, b''
            if args[0] == '/bin/ps': return 0, b'/sbin/launchd\n'
            return 0, plistlib.dumps([properties])
        with patch.object(u.os.path, 'lexists', return_value=False), patch.object(u, 'command', side_effect=commands):
            for pending, label in ((None, 'unknown'), (True, 'pending'), (False, 'clear')):
                if pending is None: properties.pop('ProviderRestorePending', None)
                else: properties['ProviderRestorePending'] = pending
                result = u.live_runtime('disk_only_mandatory_reboot')
                self.assertEqual(result['restore_pending'], label)
                self.assertTrue(result['mandatory_reboot_before_component_use'])
                self.assertFalse(result['running_apple_process_state_repaired'])
                if pending is not False:
                    with self.assertRaises(u.UpdateError): u.live_runtime()
            properties['ProviderSessionActive'] = True
            with self.assertRaises(u.UpdateError): u.live_runtime('disk_only_mandatory_reboot')
        self.assertEqual(set(calls), {'/bin/launchctl', '/bin/ps', '/usr/sbin/ioreg'})
        with patch.object(u.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(u.UpdateError, 'session_artifact'):
                u.live_runtime('disk_only_mandatory_reboot')

    def test_disk_only_mode_changes_approval_digest(self):
        strict = self.prepare()
        self.backend.maintenance_mode = 'disk_only_mandatory_reboot'
        disk_only = self.prepare()
        self.assertNotEqual(strict['approval_digest'], disk_only['approval_digest'])
        with self.assertRaisesRegex(u.UpdateError, 'approval_plan_changed'):
            self.backend.apply(self.package, strict['approval_digest'])


class FATIntegratedTests(unittest.TestCase):
    write = CurrentUpdateTests.write
    command = CurrentUpdateTests.command
    save_manifest = CurrentUpdateTests.save_manifest
    observe = CurrentUpdateTests.observe
    runtime = CurrentUpdateTests.runtime
    idle = CurrentUpdateTests.idle
    prepare = CurrentUpdateTests.prepare

    def setUp(self):
        CurrentUpdateTests.setUp(self)
        self.fatroot = tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT'))
        self.addCleanup(self.fatroot.cleanup)
        target = Path(self.fatroot.name).resolve() / 'EFI/OC'
        shutil.copytree(self.oc, target)
        self.oc = target; self.backend.oc = target
        self.backend.storage_status = lambda: {'filesystem': 'msdos', 'exchange_supported': False}
        self.backend.allow_same_device_fat = not bool(os.environ.get('ELAN_FAT_TEST_ROOT'))

    def test_full_current_update_and_preboot_rollback(self):
        before = u.tree(self.install); original = u.fat.snapshot(self.oc / 'Kexts' / u.BUNDLE)
        config = (self.oc / 'config.plist').read_bytes(); plan = self.prepare()
        result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.assertEqual(result['state'], 'committed')
        self.assertNotEqual(self.backend._active_bundle().name, u.BUNDLE)
        self.assertEqual(u.identity.artifact_identity(self.backend._active_bundle(), '0.4.0'), plan['target_identity'])
        self.assertEqual(u.fat.snapshot(self.oc / 'Kexts' / u.BUNDLE), original)
        self.assertEqual(self.backend.rollback(result['transaction'], plan['approval_digest'])['state'], 'rolled_back')
        after = u.tree(self.install); after.pop('state/runtime.lock')
        self.assertEqual(after, before); self.assertEqual((self.oc / 'config.plist').read_bytes(), config)

    def test_interrupted_userland_and_config_publication_resume(self):
        for point in ('installed:ELANNativeProvider.app', 'fat:before_stage', 'fat:publish_intent', 'fat:published'):
            plan = self.prepare()
            def fault(name):
                if name == point: raise KeyboardInterrupt()
            self.backend.fault = fault
            with self.assertRaises(u.UpdateError):
                self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
            self.backend.fault = None
            transactions = [p for p in self.parent.glob('.elan-current-update-*') if (p / 'transaction.json').is_file()]
            transaction = max(transactions, key=lambda p: p.stat().st_mtime_ns)
            self.assertEqual(self.backend.resume(transaction, plan['approval_digest'])['state'], 'committed')
            self.backend.rollback(transaction, plan['approval_digest'])
            # Candidate generations are intentionally retained. Each next reviewed
            # package changes a script, producing a distinct approval/generation.
            script = self.package / 'scripts/native-current-update.py'
            script.write_bytes(script.read_bytes() + b'# next fixture generation\n'); self.save_manifest()

    def test_resume_after_unreported_swap_verifies_retained_generation(self):
        plan = self.prepare(); original = self.backend.swap; injected = []
        def interrupted(left, right):
            if not injected:
                injected.append(True)
                if left.is_dir():
                    victim = left / 'Contents/Info.plist'; victim.write_bytes(victim.read_bytes() + b'FOREIGN')
                else: left.write_bytes(left.read_bytes() + b'FOREIGN')
                original(left, right)
                raise KeyboardInterrupt()
            original(left, right)
        self.backend.swap = interrupted
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.backend.swap = original
        transaction, = self.parent.glob('.elan-current-update-*')
        with self.assertRaises(u.UpdateError): self.backend.resume(transaction, plan['approval_digest'])
        self.assertTrue(json.loads((transaction / 'transaction.json').read_text())['conflict'])

    def test_leaf_preparation_cannot_accept_different_approved_config(self):
        plan = self.prepare(); original = u.fat.Transaction.prepare
        def changed(engine, candidate, token):
            value = plistlib.loads((self.oc / 'config.plist').read_bytes()); value['Unrelated'] = 'foreign'
            (self.oc / 'config.plist').write_bytes(plistlib.dumps(value))
            return original(engine, candidate, token)
        before = u.tree(self.install)
        with patch.object(u.fat.Transaction, 'prepare', changed):
            with self.assertRaisesRegex(u.UpdateError, 'approved_source_changed'):
                self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        after = u.tree(self.install); after.pop('state/runtime.lock')
        self.assertEqual(before, after)

    def test_resume_continues_interrupted_rollback_not_upgrade(self):
        plan = self.prepare()
        result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.backend.fault = lambda name: (_ for _ in ()).throw(KeyboardInterrupt()) if name == 'fat:rolled_back_config' else None
        with self.assertRaises(KeyboardInterrupt): self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.backend.fault = None
        resumed = self.backend.resume(result['transaction'], plan['approval_digest'])
        self.assertEqual(resumed['state'], 'rolled_back')
        self.assertEqual(self.backend._active_bundle().name, u.BUNDLE)
        self.assertEqual(u.identity.artifact_identity(self.install / u.KERNEL, '0.4.0'), plan['source_identity'])

    def test_incomplete_local_preparation_does_not_claim_full_resume(self):
        plan = self.prepare(); before = u.tree(self.install)
        with patch.object(u.fat, '_copy_checked', side_effect=KeyboardInterrupt()):
            with self.assertRaisesRegex(u.UpdateError, 'local_preparation_interrupted'):
                self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        transaction, = self.parent.glob('.elan-current-update-*')
        with self.assertRaisesRegex(u.UpdateError, 'local_preparation_incomplete'):
            self.backend.resume(transaction, plan['approval_digest'])
        for _ in range(2):
            self.assertFalse(self.backend.rollback(transaction, plan['approval_digest'])['changed'])
        after = u.tree(self.install); after.pop('state/runtime.lock')
        self.assertEqual(after, before)

    def boot_into_target(self):
        self.boot = fixtures.OTHER
        loaded = dict(self.baseline['loaded_kernel'], macho_uuid=fixtures.OTHER)
        self.backend.runtime = lambda: {'boot_uuid': self.boot, 'loaded_kernel': loaded}
        def query(args, **kwargs):
            return {'status': 0, 'stdout': self.boot if tuple(args) == u.preflight.BOOT_COMMAND else fixtures.row(loaded['macho_uuid']), 'stderr': ''}
        self.backend.observe = lambda: u.preflight.inspect(self.install, command_fn=query)
        return loaded

    def test_crossboot_new_approval_then_restore_requires_second_reboot(self):
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        loaded = self.boot_into_target(); before = u.tree(self.parent); external = u.fat.snapshot(self.backend._active_bundle())
        recovery = self.backend.prepare_rollback(result['transaction'])
        self.assertEqual(u.tree(self.parent), before); self.assertEqual(u.fat.snapshot(self.backend._active_bundle()), external)
        self.assertNotEqual(recovery['approval_digest'], plan['approval_digest'])
        with self.assertRaisesRegex(u.UpdateError, 'new_boot_recovery_approval'):
            self.backend.rollback_after_reboot(result['transaction'], plan['approval_digest'], exclusive_maintenance=True)
        restored = self.backend.rollback_after_reboot(result['transaction'], recovery['approval_digest'], exclusive_maintenance=True)
        self.assertEqual(restored['state'], 'rolled_back'); self.assertTrue(restored['reboot_required'])
        self.assertEqual(loaded['macho_uuid'], plan['target_identity']['macho_uuid'])
        self.assertEqual(u.identity.artifact_identity(self.install / u.KERNEL, '0.4.0'), plan['source_identity'])
        self.assertTrue(self.backend.resume_rollback(result['transaction'], recovery['approval_digest'])['reboot_required'])

    def test_crossboot_interruption_requires_new_token_and_same_recovery_boot(self):
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.boot_into_target(); recovery = self.backend.prepare_rollback(result['transaction'])
        self.backend.fault = lambda name: (_ for _ in ()).throw(KeyboardInterrupt()) if name == 'fat:rolled_back_config' else None
        with self.assertRaises(KeyboardInterrupt):
            self.backend.rollback_after_reboot(result['transaction'], recovery['approval_digest'], exclusive_maintenance=True)
        self.backend.fault = None
        with self.assertRaises(u.UpdateError): self.backend.resume(result['transaction'], plan['approval_digest'])
        self.boot = '11111111-2222-3333-4444-555555555555'
        with self.assertRaisesRegex(u.UpdateError, 'recovery_boot'):
            self.backend.resume_rollback(result['transaction'], recovery['approval_digest'])
        self.boot = fixtures.OTHER
        self.assertTrue(self.backend.resume_rollback(result['transaction'], recovery['approval_digest'])['reboot_required'])

    def test_crossboot_prepare_rejects_wrong_loaded_or_unknown_userland(self):
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        loaded = self.boot_into_target(); loaded['macho_uuid'] = fixtures.UUID
        with self.assertRaisesRegex(u.UpdateError, 'loaded_target'): self.backend.prepare_rollback(result['transaction'])
        loaded['macho_uuid'] = fixtures.OTHER
        (self.install / 'NativeNamespaceProbe').write_bytes(b'foreign')
        with self.assertRaises(u.UpdateError): self.backend.prepare_rollback(result['transaction'])

    def test_crossboot_approval_never_mutates_receipt_while_lock_held(self):
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.boot_into_target(); recovery = self.backend.prepare_rollback(result['transaction'])
        receipt = Path(result['transaction']) / 'transaction.json'; before = receipt.read_bytes()
        with (self.install / 'state/runtime.lock').open('rb') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.backend.rollback_after_reboot(result['transaction'], recovery['approval_digest'], exclusive_maintenance=True)
            self.assertEqual(receipt.read_bytes(), before)

    def test_crossboot_prepare_rejects_changed_backup(self):
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.boot_into_target()
        (Path(result['transaction']) / 'before/ELANNativeBroker').write_bytes(b'foreign')
        with self.assertRaisesRegex(u.UpdateError, 'backup_changed'): self.backend.prepare_rollback(result['transaction'])

    def test_disk_only_update_and_revert_both_require_reboot(self):
        self.backend.maintenance_mode = 'disk_only_mandatory_reboot'
        plan = self.prepare(); result = self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.assertTrue(result['must_reboot_before_component_use'])
        self.assertFalse(result['running_apple_process_state_repaired'])
        reverted = self.backend.rollback(result['transaction'], plan['approval_digest'])
        self.assertTrue(reverted['reboot_required'])
        self.assertTrue(reverted['must_reboot_before_component_use'])

    def test_postboot_prepare_locates_selected_generation_not_original_name(self):
        plan = self.prepare()
        self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        def query(args, **kwargs):
            return {'status': 0, 'stdout': fixtures.BOOT if tuple(args) == u.preflight.BOOT_COMMAND else fixtures.row(fixtures.OTHER), 'stderr': ''}
        self.backend.observe = lambda: u.preflight.inspect(self.install, command_fn=query)
        next_plan = self.prepare()
        self.assertEqual(next_plan['source_identity'], plan['target_identity'])

    def test_unknown_config_during_fat_resume_is_not_overwritten(self):
        plan = self.prepare()
        self.backend.fault = lambda name: (_ for _ in ()).throw(KeyboardInterrupt()) if name == 'fat:publish_intent' else None
        with self.assertRaises(u.UpdateError): self.backend.apply(self.package, plan['approval_digest'], exclusive_maintenance=True)
        self.backend.fault = None
        transaction, = self.parent.glob('.elan-current-update-*')
        original = (self.oc / 'config.plist').read_bytes()
        value = plistlib.loads(original); value['Unrelated'] = 'foreign'; foreign = plistlib.dumps(value)
        (self.oc / 'config.plist').write_bytes(foreign)
        for method in (self.backend.resume, self.backend.rollback):
            with self.assertRaises((u.UpdateError, u.fat.FATUpdateError)): method(transaction, plan['approval_digest'])
        self.assertEqual((self.oc / 'config.plist').read_bytes(), foreign)


if __name__ == '__main__': unittest.main()
