import importlib.util
import sys
import unittest
from dataclasses import replace
from pathlib import Path

spec = importlib.util.spec_from_file_location('recovery_plan', Path(__file__).with_name('native-settings-recovery-plan.py'))
m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m)
I = m.Identity('transaction', 'boot', 'task', 'map')


class RecoveryTests(unittest.TestCase):
    def test_dirty_without_atomic_backend_blocks(self):
        d = m.recover(m.State(I, True), m.Evidence(I, clean_verified=True, paused=True, atomic_resume=True))
        self.assertEqual(d.action, 'blocked'); self.assertFalse(d.allow_new_session)

    def test_dirty_never_resumes(self):
        for phase in ('pending', 'retiring', 'resuming'):
            for clean in (False, True):
                for resumed in (False, True):
                    d = m.recover(m.State(I, True, phase=phase), m.Evidence(I, clean_verified=clean,
                        resumed=resumed, paused=True, atomic_resume=True, atomic_retirement=True))
                    self.assertEqual(d.action, 'retire_bound'); self.assertTrue(d.state.pending)
                    self.assertEqual(d.identity, I)

    def test_all_identity_components_must_match(self):
        for field in ('transaction', 'boot', 'task', 'map'):
            other = replace(I, **{field: 'other'})
            for gone in (False, True):
                d = m.recover(m.State(I, True), m.Evidence(other, original_gone=gone, atomic_retirement=True))
                self.assertEqual(d.action, 'blocked'); self.assertTrue(d.state.pending)

    def test_unknown_identity_blocks(self):
        self.assertEqual(m.recover(m.State(I, True), m.Evidence()).reason, 'identity_unverified')
        self.assertEqual(m.recover(m.State(replace(I, task=''), True), m.Evidence()).reason, 'invalid_identity')

    def test_pid_cannot_authorize(self):
        with self.assertRaises(TypeError): m.Evidence(pid=42)
        self.assertEqual(m.recover(m.State(I, True), m.Evidence(identity=42)).action, 'blocked')

    def test_retirement_reentrant_before_and_after_execution(self):
        original = m.State(I, True)
        e = m.Evidence(I, atomic_retirement=True)
        a = m.recover(original, e)
        # Death before persisting the intent or after persisting it yields the same intent.
        self.assertEqual(m.recover(original, e), a)
        self.assertEqual(m.recover(a.state, e), a)
        # Backend completed retirement but caller died before recording its receipt.
        gone = m.Evidence(I, original_gone=True)
        for state in (original, a.state):
            done = m.recover(state, gone)
            self.assertTrue(done.allow_new_session)
            self.assertEqual(m.recover(done.state, m.Evidence()).action, 'none')

    def test_clean_resume_requires_atomic_backend(self):
        s = m.State(I, False)
        self.assertEqual(m.recover(s, m.Evidence(I, paused=True)).reason, 'clean_unverified')
        self.assertEqual(m.recover(s, m.Evidence(I, clean_verified=True)).reason, 'pause_unverified')
        self.assertEqual(m.recover(s, m.Evidence(I, clean_verified=True, paused=True)).reason, 'atomic_resume_unavailable')

    def test_clean_resume_reentrant(self):
        s = m.State(I, False)
        e = m.Evidence(I, paused=True, clean_verified=True, atomic_resume=True)
        d = m.recover(s, e)
        self.assertEqual(d.action, 'resume_bound'); self.assertFalse(d.allow_new_session)
        self.assertEqual(m.recover(d.state, e), d)
        for state in (s, d.state):
            done = m.recover(state, m.Evidence(I, clean_verified=True, resumed=True))
            self.assertTrue(done.allow_new_session)

    def test_partial_resume_becomes_dirty(self):
        d = m.recover(m.State(I, True, phase='resuming'), m.Evidence(I, resumed=True))
        self.assertEqual(d.action, 'blocked'); self.assertTrue(d.state.pending)

    def test_retiring_cannot_switch_back_to_resume(self):
        d = m.recover(m.State(I, False, phase='retiring'), m.Evidence(I, clean_verified=True, resumed=True))
        self.assertEqual(d.action, 'blocked')

    def test_gone_conflict_blocks(self):
        for field in ('paused', 'resumed'):
            d = m.recover(m.State(I, True), m.Evidence(I, original_gone=True, **{field: True}))
            self.assertEqual(d.action, 'blocked'); self.assertFalse(d.allow_new_session)

    def test_clean_resume_conflict_blocks(self):
        d = m.recover(m.State(I, False), m.Evidence(I, clean_verified=True, resumed=True, paused=True))
        self.assertEqual(d.action, 'blocked')

    def test_invalid_states_block(self):
        for s in (m.State(I, True, pending=False), m.State(I, True, phase='unknown'),
                  m.State(I, True, phase='complete'), m.State(I, 'false')):
            d = m.recover(s, m.Evidence(I, original_gone=True))
            self.assertEqual(d.action, 'blocked'); self.assertFalse(d.allow_new_session)

    def test_truthy_evidence_rejected(self):
        d = m.recover(m.State(I, True), m.Evidence(I, original_gone=1))
        self.assertEqual(d.action, 'blocked')


if __name__ == '__main__': unittest.main()
