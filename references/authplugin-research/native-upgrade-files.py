"""Offline filesystem adapter for native-upgrade-plan; not an installer.

Only an explicitly initialized directory below a temporary-directory root is
accepted. Runtime version/boot values are simulated files, never OS queries.
The caller injects the strict kernel payload reader (including AppleDouble
validation). No /Library or real EFI adapter is implemented.
"""
import copy
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import uuid
import zipfile

_plan_path = Path(__file__).with_name('native-upgrade-plan.py')
if 'native_upgrade_plan' not in sys.modules:
    _spec = importlib.util.spec_from_file_location('native_upgrade_plan', _plan_path)
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _module
    _spec.loader.exec_module(_module)
plan = sys.modules['native_upgrade_plan']

_MARKER = b'ELAN_OFFLINE_UPGRADE_TEST_V1\n'
_BUNDLE = 'ELANNativeProbe.kext'
_COMMENT = 'ELAN native credential interface probe '


def _test_root(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('An existing non-symlink test directory is required')
    root = path.resolve()
    anchors = {Path('/tmp').resolve(), Path(tempfile.gettempdir()).resolve()}
    if not any(root != anchor and anchor in root.parents for anchor in anchors):
        raise ValueError('Only a child of a temporary-directory root is supported')
    return root


def _bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Not a regular test file')
        return stream.read()


def _xattrs(path):
    # Values are archived as hex; they are never printed. This includes native
    # extended attributes on APFS as well as their AppleDouble storage on FAT.
    if sys.platform != 'darwin':
        return {name: os.getxattr(path, name, follow_symlinks=False).hex()
                for name in os.listxattr(path, follow_symlinks=False)}
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    listing = library.listxattr
    listing.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    listing.restype = ctypes.c_ssize_t
    reading = library.getxattr
    reading.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    reading.restype = ctypes.c_ssize_t
    encoded = os.fsencode(path)
    size = listing(encoded, None, 0, 1)
    if size < 0: raise OSError(ctypes.get_errno(), 'Cannot inspect test attributes')
    names = ctypes.create_string_buffer(size)
    count = listing(encoded, names, size, 1)
    if count < 0: raise OSError(ctypes.get_errno(), 'Test attributes changed while listing')
    result = {}
    for name in names.raw[:count].split(b'\0'):
        if not name: continue
        length = reading(encoded, name, None, 0, 0, 1)
        if length < 0: raise OSError(ctypes.get_errno(), 'Cannot inspect test attribute')
        value = ctypes.create_string_buffer(length)
        actual = reading(encoded, name, value, length, 0, 1)
        if actual != length: raise OSError('Test attribute changed while reading')
        result[os.fsdecode(name)] = value.raw[:actual].hex()
    return result


def _metadata(st, path):
    return {'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid,
            'links': st.st_nlink, 'size': st.st_size, 'mtime': st.st_mtime_ns,
            'ctime': st.st_ctime_ns, 'inode': st.st_ino, 'device': st.st_dev,
            'flags': getattr(st, 'st_flags', 0),
            # FAT exposes attributes through AppleDouble; asking the storage file
            # itself for attributes is rejected. Its complete bytes are archived.
            'xattrs': {} if path.name.startswith('._') else _xattrs(path)}


def _manifest(snapshot):
    result = {}
    for name, record in snapshot.items():
        result[name] = {key: value for key, value in record.items() if key != 'data'}
        if 'data' in record:
            result[name]['sha256'] = hashlib.sha256(record['data']).hexdigest()
    return result


def _revision(snapshot):
    return hashlib.sha256(json.dumps(_manifest(snapshot), sort_keys=True).encode()).hexdigest()


@dataclass
class _OwnedContext:
    snapshot: dict


class _OwnedFailure(RuntimeError):
    pass


class TestFilesystemBackend:
    """The explicit marker and temporary-root check are enforced on every read/write."""
    @classmethod
    def initialize(cls, root, release, kernel_reader, config=None, boot_id='test-boot'):
        root = _test_root(root)
        if any(root.iterdir()):
            raise ValueError('Initialize requires an empty test directory')
        (root / '.offline-test').write_bytes(_MARKER)
        (root / 'kernel').mkdir()
        for name, data in release.kernel:
            destination = root / 'kernel' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        (root / 'broker').write_bytes(release.broker)
        config = copy.deepcopy(config) if config is not None else {'Kernel': {'Add': []}, 'Unrelated': 'keep'}
        entries = config['Kernel']['Add']
        if any(entry.get('BundlePath') == _BUNDLE for entry in entries):
            raise ValueError('Test config must not already contain the owned entry')
        entries.append({'BundlePath': _BUNDLE, 'Comment': _COMMENT + release.version, 'Enabled': True})
        (root / 'config.plist').write_bytes(plistlib.dumps(config))
        (root / 'runtime.json').write_text(json.dumps({'loaded_version': release.version, 'loaded_uuid': release.kernel_uuid, 'boot_id': boot_id, 'idle': True}))
        return cls(root, kernel_reader)

    def __init__(self, root, kernel_reader, fault=None):
        self.root = _test_root(root)
        self.kernel_reader = kernel_reader
        self.fault = fault
        self.events = []
        self.last_backup = None
        self._guard()

    def _guard(self):
        if _test_root(self.root) != self.root or _bytes(self.root / '.offline-test') != _MARKER:
            raise ValueError('Offline test root identity changed')

    def _point(self, name):
        self.events.append(name)
        if self.fault:
            self.fault(name, self)

    def _snapshot(self):
        self._guard()
        root_stat = self.root.lstat()
        # Root timestamps change for our lock/archive bookkeeping, which is outside
        # managed state. Root ownership/mode and all managed-entry metadata are bound.
        result = {'.': {'mode': root_stat.st_mode, 'uid': root_stat.st_uid, 'gid': root_stat.st_gid, 'xattrs': _xattrs(self.root)}}
        paths = [self.root / name for name in ('broker', 'config.plist', 'runtime.json', 'kernel')]
        paths.extend(self.root / name for name in ('._broker', '._config.plist', '._runtime.json', '._kernel')
                     if os.path.lexists(self.root / name))
        while paths:
            path = paths.pop()
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise ValueError('Unexpected managed test file type')
            name = str(path.relative_to(self.root))
            record = _metadata(st, path)
            if stat.S_ISREG(st.st_mode):
                record['data'] = _bytes(path)
            else:
                paths.extend(path.iterdir())
            result[name] = record
        return result

    def read_state(self):
        before = self._snapshot()
        runtime = json.loads(before['runtime.json']['data'])
        config = plistlib.loads(before['config.plist']['data'])
        kernel = self.kernel_reader(self.root / 'kernel')
        version = plistlib.loads(kernel['Contents/Info.plist']).get('CFBundleVersion')
        entries = [item for item in config['Kernel']['Add'] if item.get('BundlePath') == _BUNDLE]
        if len(entries) != 1 or entries[0].get('Comment') != _COMMENT + str(version):
            version = '<inconsistent>'
        after = self._snapshot()
        if before != after:
            raise plan.ConcurrentChange('State changed while reading')
        return plan.State(runtime['loaded_version'], version, plan.kernel_digest(kernel),
                          hashlib.sha256(before['broker']['data']).hexdigest(), runtime['boot_id'],
                          _revision(after), runtime['idle'] is True, runtime.get('loaded_uuid', ''), plan.kernel_uuid(kernel))

    def _check(self, expected):
        if self.read_state() != expected:
            raise plan.ConcurrentChange('Filesystem compare-and-swap failed')

    def backup(self, expected):
        self._check(expected)
        snapshot = self._snapshot()
        directory = self.root / 'backups'
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Unsafe test backup directory')
        archive = directory / (uuid.uuid4().hex + '.zip')
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as output:
            output.writestr('manifest.json', json.dumps(_manifest(snapshot), sort_keys=True))
            for name, record in snapshot.items():
                if 'data' in record:
                    output.writestr('files/' + name, record['data'])
        self.last_backup = archive
        self._point('backup_written')
        with zipfile.ZipFile(archive, 'r') as saved:
            if json.loads(saved.read('manifest.json')) != _manifest(snapshot):
                raise ValueError('Backup metadata readback differs')
            for name, record in snapshot.items():
                if 'data' in record and saved.read('files/' + name) != record['data']:
                    raise ValueError('Backup file readback differs')
        self._check(expected)
        return plan.Backup(expected.kernel_hash, expected.broker_hash, expected.disk_uuid)

    def _known_point(self, name, context):
        try:
            self._point(name)
        except BaseException as error:
            if self._snapshot() != context.snapshot:
                raise plan.ConcurrentChange('Foreign change at ' + name) from error
            raise _OwnedFailure(name) from error
        if self._snapshot() != context.snapshot:
            raise plan.ConcurrentChange('Foreign change at ' + name)

    def _atomic(self, path, data, label, context):
        if self._snapshot() != context.snapshot:
            raise plan.ConcurrentChange('Managed state changed before file replacement')
        mode = path.lstat().st_mode & 0o777
        fd, temporary = tempfile.mkstemp(prefix='.offline-owned-', dir=path.parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        context.snapshot = self._snapshot()
        try:
            self._known_point('before_replace:' + label, context)
        except _OwnedFailure:
            os.unlink(temporary)
            context.snapshot = self._snapshot()
            raise
        try:
            os.replace(temporary, path)
        except BaseException as error:
            if self._snapshot() == context.snapshot:
                os.unlink(temporary)
                context.snapshot = self._snapshot()
                raise _OwnedFailure('replace failed') from error
            raise plan.ConcurrentChange('Unattributable replacement result') from error
        context.snapshot = self._snapshot()
        if _bytes(path) != data:
            raise plan.ConcurrentChange('Replaced content changed before readback')
        self._known_point('after_replace:' + label, context)

    def _replace(self, expected, changes, label):
        self._guard()
        lock = self.root / '.transaction.lock'
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._check(expected)
            context = _OwnedContext(self._snapshot())
            originals = {str(path): _bytes(path) for path, _ in changes}
            touched = []
            try:
                for path, data in changes:
                    # Include the current item because a reported failure can occur after replacement.
                    touched.append(path)
                    self._atomic(path, data, label + ':' + str(path.relative_to(self.root)), context)
            except _OwnedFailure as failure:
                try:
                    if self._snapshot() != context.snapshot:
                        raise plan.ConcurrentChange('Foreign change before local restoration')
                    for path in reversed(touched):
                        if _bytes(path) != originals[str(path)]:
                            self._atomic(path, originals[str(path)], 'local_restore:' + str(path.relative_to(self.root)), context)
                    result = self.read_state()
                except BaseException as recovery:
                    raise plan.TransactionError('Filesystem local restoration incomplete: ' + str(recovery), False) from failure
                raise plan.WriteFailure('Filesystem step failed and restored its input contents', result) from failure
            if self._snapshot() != context.snapshot:
                raise plan.ConcurrentChange('Foreign change after filesystem step')
            return self.read_state()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def replace_broker(self, expected, broker):
        return self._replace(expected, [(self.root / 'broker', broker)], 'broker')

    def replace_kernel(self, expected, version, files):
        plan.kernel_digest(files)
        current = self.kernel_reader(self.root / 'kernel')
        if set(files) != set(current):
            raise ValueError('Kernel layout change is not supported by this test adapter')
        if plistlib.loads(files['Contents/Info.plist']).get('CFBundleVersion') != version:
            raise ValueError('Kernel payload version differs from requested version')
        config = plistlib.loads(_bytes(self.root / 'config.plist'))
        entries = [item for item in config['Kernel']['Add'] if item.get('BundlePath') == _BUNDLE]
        if len(entries) != 1:
            raise ValueError('Expected one owned EFI entry')
        entries[0]['Comment'] = _COMMENT + version
        changes = [(self.root / 'kernel' / name, data) for name, data in sorted(files.items())]
        changes.append((self.root / 'config.plist', plistlib.dumps(config)))
        return self._replace(expected, changes, 'kernel')

    def finalize(self, expected, transaction):
        self._check(expected)
        directory = self.root / 'receipts'
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Unsafe test receipt directory')
        self._point('before_receipt')
        self._check(expected)
        record = {'source': transaction.source.version, 'target': transaction.target.version,
                  'kernel_hash': expected.kernel_hash, 'broker_hash': expected.broker_hash,
                  'loaded_uuid': expected.loaded_uuid, 'disk_uuid': expected.disk_uuid,
                  'source_uuid': transaction.source.kernel_uuid, 'target_uuid': transaction.target.kernel_uuid,
                  'boot_id': expected.boot_id, 'revision': expected.revision, 'reboot_required': True}
        destination = directory / (uuid.uuid4().hex + '.json')
        with destination.open('x') as stream:
            json.dump(record, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
        if json.loads(_bytes(destination)) != record:
            raise ValueError('Receipt readback differs')
        self._point('after_receipt')
        self._check(expected)
