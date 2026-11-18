"""Pure recovery planner. No process, filesystem, or system operations."""
from dataclasses import dataclass, replace
from typing import Optional


@dataclass(frozen=True)
class Identity:
    transaction: str
    boot: str
    task: str
    map: str

    def valid(self):
        return all(type(v) is str and bool(v) for v in
                   (self.transaction, self.boot, self.task, self.map))


@dataclass(frozen=True)
class State:
    identity: Identity
    dirty: bool
    pending: bool = True
    phase: str = 'pending'


@dataclass(frozen=True)
class Evidence:
    # Backend attestations refer to the entire identity, never a PID lookup.
    identity: Optional[Identity] = None
    original_gone: bool = False
    clean_verified: bool = False
    paused: bool = False
    resumed: bool = False
    atomic_retirement: bool = False
    atomic_resume: bool = False


@dataclass(frozen=True)
class Decision:
    state: State
    action: str
    reason: str
    identity: Optional[Identity] = None

    @property
    def allow_new_session(self):
        return not self.state.pending and self.state.phase == 'complete'


def recover(state, evidence):
    """Return an idempotent intent, not a claim that an action executed.

    An eventual backend must atomically bind identity verification and its operation.
    Its success receipt must survive caller death or be reconstructible by inspection.
    """
    if not isinstance(state, State) or not isinstance(evidence, Evidence):
        raise TypeError('Expected State and Evidence')
    if not isinstance(state.identity, Identity) or not state.identity.valid():
        return Decision(replace(state, pending=True), 'blocked', 'invalid_identity')
    if any(type(v) is not bool for v in (state.dirty, state.pending, evidence.original_gone,
            evidence.clean_verified, evidence.paused, evidence.resumed,
            evidence.atomic_retirement, evidence.atomic_resume)):
        return Decision(replace(state, pending=True), 'blocked', 'invalid_evidence')
    if state.phase not in ('pending', 'retiring', 'resuming', 'complete'):
        return Decision(replace(state, pending=True), 'blocked', 'invalid_phase')
    if state.phase == 'complete' and not state.pending:
        return Decision(state, 'none', 'already_complete')
    if not state.pending or state.phase == 'complete':
        return Decision(replace(state, pending=True), 'blocked', 'inconsistent_state')
    if evidence.identity != state.identity:
        return Decision(state, 'blocked', 'identity_unverified')
    if evidence.original_gone:
        if evidence.paused or evidence.resumed:
            return Decision(state, 'blocked', 'conflicting_evidence')
        return Decision(replace(state, pending=False, phase='complete'), 'none', 'original_gone')
    if state.dirty or state.phase == 'retiring':
        if not evidence.atomic_retirement:
            return Decision(state, 'blocked', 'atomic_retirement_unavailable')
        return Decision(replace(state, phase='retiring'), 'retire_bound',
                        'await_original_exit', state.identity)
    if not evidence.clean_verified:
        return Decision(state, 'blocked', 'clean_unverified')
    if evidence.resumed:
        if evidence.paused:
            return Decision(state, 'blocked', 'conflicting_evidence')
        return Decision(replace(state, pending=False, phase='complete'), 'none', 'clean_resumed')
    if not evidence.paused:
        return Decision(state, 'blocked', 'pause_unverified')
    if not evidence.atomic_resume:
        return Decision(state, 'blocked', 'atomic_resume_unavailable')
    return Decision(replace(state, phase='resuming'), 'resume_bound',
                    'await_resume_receipt', state.identity)
