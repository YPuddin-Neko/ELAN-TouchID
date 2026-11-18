"""Pure upgrade planning and injected transactions. No installation or OS access.

An adapter must normalize only validated metadata before hashing a kernel tree,
include EFI config/other concurrent state in State.revision, and implement each
replace as compare-and-swap against the complete expected State. Kernel replace
covers both the payload and its owned EFI version entry. It must not silently
replace unrelated config. No adapter or reboot operation is provided here.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import plistlib
from pathlib import Path, PurePosixPath
from typing import Mapping, Protocol, Optional, Tuple

_identity_spec = importlib.util.spec_from_file_location('native_upgrade_identity', Path(__file__).with_name('native-kernel-identity.py'))
_identity = importlib.util.module_from_spec(_identity_spec)
_identity_spec.loader.exec_module(_identity)


class PlanError(ValueError):
    pass


class ConcurrentChange(RuntimeError):
    pass


def kernel_digest(files: Mapping[str, bytes]) -> str:
    if not files:
        raise PlanError('Empty kernel payload')
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or str(path) != name or not isinstance(data, bytes):
            raise PlanError('Invalid kernel payload entry')
        encoded = name.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big') + encoded)
        digest.update(len(data).to_bytes(8, 'big') + data)
    return digest.hexdigest()


def kernel_uuid(files):
    try:
        return _identity.macho_uuid(files['Contents/MacOS/ELANNativeProbe'])
    except (KeyError, _identity.IdentityError) as error:
        raise PlanError('Invalid kernel executable identity') from error


@dataclass(frozen=True)
class Release:
    version: str
    kernel: Tuple[Tuple[str, bytes], ...]
    broker: bytes

    @classmethod
    def verified(cls, version, kernel, broker, expected_kernel, expected_broker):
        if not version or not isinstance(broker, bytes) or not broker:
            raise PlanError('Invalid release')
        if kernel_digest(kernel) != expected_kernel or hashlib.sha256(broker).hexdigest() != expected_broker:
            raise PlanError('Release payload hash mismatch')
        try:
            if plistlib.loads(kernel['Contents/Info.plist']).get('CFBundleVersion') != version:
                raise PlanError('Release metadata version mismatch')
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise PlanError('Invalid release metadata') from error
        kernel_uuid(kernel)
        return cls(version, tuple(sorted(kernel.items())), broker)

    @property
    def kernel_uuid(self):
        return kernel_uuid(dict(self.kernel))

    @property
    def kernel_hash(self):
        return kernel_digest(dict(self.kernel))

    @property
    def broker_hash(self):
        return hashlib.sha256(self.broker).hexdigest()


@dataclass(frozen=True)
class State:
    loaded_version: str
    disk_version: str
    kernel_hash: str
    broker_hash: str
    boot_id: str
    revision: str
    idle: bool
    loaded_uuid: str = ""
    disk_uuid: str = ""


@dataclass(frozen=True)
class Plan:
    action: str
    before: State
    source: Release
    target: Release
    stable: Release

    @property
    def noop(self):
        return self.source == self.target


@dataclass(frozen=True)
class Backup:
    kernel_hash: str
    broker_hash: str
    kernel_uuid: str = ""


@dataclass(frozen=True)
class Result:
    disk_version: str
    reboot_required: bool
    changed: bool
    receipt_pending: bool = False


class WriteFailure(RuntimeError):
    """Adapter failed after an owned operation, with a verified CAS receipt."""
    def __init__(self, message, applied_state: State):
        super().__init__(message)
        self.applied_state = applied_state


class TransactionError(RuntimeError):
    def __init__(self, message, rollback_complete):
        super().__init__(message)
        self.rollback_complete = rollback_complete
        self.pending = not rollback_complete


class Backend(Protocol):
    def read_state(self) -> State: ...
    def backup(self, expected: State) -> Backup: ...
    def replace_broker(self, expected: State, broker: bytes) -> State: ...
    def replace_kernel(self, expected: State, version: str, files: Mapping[str, bytes]) -> State: ...
    def finalize(self, expected: State, plan: Plan) -> None: ...


def make_plan(action: str, state: State, releases: Mapping[str, Release], target_version: Optional[str] = None) -> Plan:
    if action not in ('upgrade', 'rollback'):
        raise PlanError('Unknown action')
    if not state.idle or not state.boot_id or not state.revision:
        raise PlanError('Require idle, identified boot and state revision')
    if state.loaded_version != state.disk_version:
        raise PlanError('Pending reboot or mismatched loaded/disk version')
    if any(key != release.version for key, release in releases.items()):
        raise PlanError('Release registry key/version mismatch')
    stable = releases.get('0.4.0')
    source = releases.get(state.disk_version)
    target = releases.get(target_version) if action == 'upgrade' else stable
    if not stable or not source or not target:
        raise PlanError('Unknown source, target, or stable rollback release')
    if action == 'rollback' and target_version not in (None, '0.4.0'):
        raise PlanError('Explicit rollback targets stable 0.4.0 only')
    if (not state.loaded_uuid or not state.disk_uuid or
            state.loaded_uuid != state.disk_uuid or state.disk_uuid != source.kernel_uuid):
        raise PlanError('Missing or mismatched loaded/disk kernel UUID')
    for release in (source, target, stable):
        kernel_uuid(dict(release.kernel))
    if source.kernel_hash != state.kernel_hash or source.broker_hash != state.broker_hash:
        raise PlanError('Installed payload differs from the verified source')
    return Plan(action, state, source, target, stable)


def _matches(state, before, kernel, broker, version, disk_uuid):
    return (state.loaded_version == before.loaded_version and state.boot_id == before.boot_id and
            state.loaded_uuid == before.loaded_uuid and state.disk_uuid == disk_uuid and
            state.idle and state.disk_version == version and state.kernel_hash == kernel and state.broker_hash == broker)


def execute(plan: Plan, backend: Backend) -> Result:
    if backend.read_state() != plan.before:
        raise ConcurrentChange('State changed after planning; nothing written')
    if plan.noop:
        return Result(plan.before.disk_version, False, False)
    try:
        backup = backend.backup(plan.before)
    except BaseException as failure:
        try:
            unchanged = backend.read_state() == plan.before
        except BaseException:
            unchanged = False
        raise TransactionError('Preparation stopped; no upgrade writes performed', unchanged) from failure
    if backup != Backup(plan.source.kernel_hash, plan.source.broker_hash, plan.source.kernel_uuid):
        raise TransactionError('Backup verification failed; nothing written', True)
    if backend.read_state() != plan.before:
        raise ConcurrentChange('State changed during backup; nothing written')
    current = plan.before
    phase = 'broker'
    try:
        current = backend.replace_broker(current, plan.target.broker)
        if not _matches(current, plan.before, plan.source.kernel_hash, plan.target.broker_hash, plan.source.version, plan.source.kernel_uuid):
            raise ConcurrentChange('Broker step returned an unexpected state')
        phase = 'kernel'
        current = backend.replace_kernel(current, plan.target.version, dict(plan.target.kernel))
        if not _matches(current, plan.before, plan.target.kernel_hash, plan.target.broker_hash, plan.target.version, plan.target.kernel_uuid):
            raise ConcurrentChange('Kernel step returned an unexpected state')
        if backend.read_state() != current:
            raise ConcurrentChange('State changed after installation')
        # Payload/config readback is the commit point. A receipt failure must not
        # turn a committed kernel update into an unrelated broker-only rollback.
        try:
            finalize = getattr(backend, 'finalize', None)
            if finalize is not None:
                finalize(current, plan)
        except BaseException as receipt_failure:
            if backend.read_state() == current:
                return Result(plan.target.version, True, True, receipt_pending=True)
            raise ConcurrentChange('State changed during receipt finalization') from receipt_failure
        if backend.read_state() != current:
            raise ConcurrentChange('State changed after receipt finalization')
        return Result(plan.target.version, True, True)
    except BaseException as failure:
        if isinstance(failure, WriteFailure):
            # A receipt is usable only for the expected complete mutation in this phase.
            receipt = failure.applied_state
            wanted = ((plan.source.kernel_hash, plan.source.broker_hash, plan.source.version, plan.source.kernel_uuid),
                      (plan.source.kernel_hash, plan.target.broker_hash, plan.source.version, plan.source.kernel_uuid)) if phase == 'broker' else (
                      (plan.source.kernel_hash, plan.target.broker_hash, plan.source.version, plan.source.kernel_uuid),
                      (plan.target.kernel_hash, plan.target.broker_hash, plan.target.version, plan.target.kernel_uuid))
            if not any(_matches(receipt, plan.before, *state) for state in wanted):
                raise TransactionError('Unrecognized partial write; preserved for recovery', False) from failure
            current = receipt
        known_states = ((plan.source.kernel_hash, plan.source.broker_hash, plan.source.version, plan.source.kernel_uuid),
                        (plan.source.kernel_hash, plan.target.broker_hash, plan.source.version, plan.source.kernel_uuid),
                        (plan.target.kernel_hash, plan.target.broker_hash, plan.target.version, plan.target.kernel_uuid))
        if not any(_matches(current, plan.before, *state) for state in known_states):
            raise TransactionError('Unknown post-write state preserved; recovery requires review', False) from failure
        try:
            if backend.read_state() != current:
                raise ConcurrentChange('Concurrent state preserved; automatic recovery stopped')
            # Internal failure recovery returns to this attempt\'s source, not stable 0.4.0.
            if current.kernel_hash != plan.source.kernel_hash or current.disk_version != plan.source.version:
                expected_broker = current.broker_hash
                current = backend.replace_kernel(current, plan.source.version, dict(plan.source.kernel))
                if not _matches(current, plan.before, plan.source.kernel_hash, expected_broker, plan.source.version, plan.source.kernel_uuid):
                    raise ConcurrentChange('Kernel recovery returned unexpected state; broker preserved')
            if current.broker_hash != plan.source.broker_hash:
                current = backend.replace_broker(current, plan.source.broker)
            if not _matches(current, plan.before, plan.source.kernel_hash, plan.source.broker_hash, plan.source.version, plan.source.kernel_uuid) or backend.read_state() != current:
                raise ConcurrentChange('Failure recovery readback differs')
        except BaseException as recovery:
            raise TransactionError('Upgrade failed; recovery incomplete: ' + str(recovery), False) from failure
        raise TransactionError('Upgrade failed; restored pre-attempt release ' + plan.source.version, True) from failure
