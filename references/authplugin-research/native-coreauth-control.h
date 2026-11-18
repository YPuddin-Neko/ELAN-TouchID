#pragma once
#include <libproc.h>
#include <sys/proc.h>
#include <fcntl.h>
#include "native-coreauth-journal-lock.h"

static constexpr const char *CoreAuthJournal = "/private/var/run/elan-native-provider-501.state";
struct CoreAuthTarget { uint32_t magic; int32_t pid; uint64_t seconds; uint64_t microseconds; };
static bool coreAuthIdentity(pid_t pid, CoreAuthTarget &target, uint32_t *processState = nullptr) {
    if (pid <= 1) return false;
    proc_bsdinfo info {};
    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        info.pbi_uid != 501 || proc_pidpath(pid, path, sizeof(path)) <= 0 ||
        strcmp(path, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd")) return false;
    SecCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributePid: @(pid)};
    OSStatus status = SecCodeCopyGuestWithAttributes(nullptr, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
    if (!status) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    if (status) return false;
    target = {0x454c414e, pid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    if (processState) *processState = info.pbi_status;
    return true;
}
static bool sameCoreAuth(const CoreAuthTarget &target, uint32_t *state = nullptr) {
    CoreAuthTarget now {};
    return coreAuthIdentity(target.pid, now, state) && !memcmp(&target, &now, sizeof(target));
}
static bool coreAuthGone(const CoreAuthTarget &target) {
    proc_bsdinfo info {};
    int count = proc_pidinfo(target.pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return count == 0 || (count == sizeof(info) &&
           (info.pbi_status == SZOMB || info.pbi_start_tvsec != target.seconds || info.pbi_start_tvusec != target.microseconds));
}
static int readCoreAuthJournalLocked(const CoreAuthJournalLock &lock, CoreAuthTarget &target) {
    if (!lock.held()) { errno = lock.error(); return -1; }
    int fd = open(CoreAuthJournal, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat info {};
    bool valid = !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 && !(info.st_mode & 077) &&
                 info.st_size == sizeof(target) && read(fd, &target, sizeof(target)) == sizeof(target) &&
                 target.magic == 0x454c414e && target.pid > 1;
    close(fd); return valid ? 1 : -1;
}
static int readCoreAuthJournal(CoreAuthTarget &target) {
    CoreAuthJournalLock lock;
    return readCoreAuthJournalLocked(lock, target);
}
static bool stopCoreAuth(pid_t pid) {
    CoreAuthJournalLock lock; if (!lock.held()) return false;
    CoreAuthTarget target {}; uint32_t state = 0;
    if (!coreAuthIdentity(pid, target, &state) || state == SSTOP || state == SZOMB) return false;
    int fd = open(CoreAuthJournal, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool saved = write(fd, &target, sizeof(target)) == sizeof(target) && !fsync(fd);
    close(fd);
    if (!saved) { unlink(CoreAuthJournal); return false; }
    if (!sameCoreAuth(target) || kill(pid, SIGSTOP)) return false;
    for (unsigned i = 0; i < 100; i++) {
        if (!sameCoreAuth(target, &state)) return false;
        if (state == SSTOP) return true;
        usleep(10000);
    }
    return false;
}
static bool resumeCoreAuthLocked(const CoreAuthJournalLock &lock) {
    CoreAuthTarget target {};
    if (readCoreAuthJournalLocked(lock, target) != 1) return false;
    if (coreAuthGone(target)) return true;
    if (!sameCoreAuth(target) || kill(target.pid, SIGCONT)) return false;
    for (unsigned i = 0; i < 100; i++) {
        uint32_t state = 0;
        if (coreAuthGone(target)) return true;
        if (!sameCoreAuth(target, &state)) return false;
        if (state != SSTOP) return true;
        usleep(10000);
    }
    return false;
}
static bool resumeCoreAuth(void) {
    CoreAuthJournalLock lock;
    return lock.held() && resumeCoreAuthLocked(lock);
}
static bool retireCoreAuth(pid_t pid) {
    CoreAuthJournalLock lock; if (!lock.held()) return false;
    CoreAuthTarget target {};
    if (readCoreAuthJournalLocked(lock, target) != 1 || target.pid != pid) return false;
    if (coreAuthGone(target)) return true;
    if (!sameCoreAuth(target) || kill(pid, SIGTERM)) return false;
    if (!coreAuthGone(target) && sameCoreAuth(target)) kill(pid, SIGCONT);
    for (unsigned i = 0; i < 200; i++) {
        if (coreAuthGone(target)) return true;
        usleep(10000);
    }
    if (!sameCoreAuth(target) || kill(pid, SIGKILL)) return false;
    for (unsigned i = 0; i < 100; i++) {
        if (coreAuthGone(target)) return true;
        usleep(10000);
    }
    return false;
}
