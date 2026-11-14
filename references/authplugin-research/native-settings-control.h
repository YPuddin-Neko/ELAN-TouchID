#pragma once
#include <libproc.h>
#include <sys/proc.h>
#include <fcntl.h>
#include <errno.h>
#include "native-executable-slice.h"
#include <mach/vm_prot.h>

static constexpr const char *SettingsExecutable = "/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password";
static constexpr const char *SettingsJournal = "/private/var/run/elan-native-settings-501.state";
struct SettingsTarget { uint32_t magic; int32_t pid; uint64_t seconds; uint64_t microseconds; };

static bool settingsIdentity(pid_t pid, SettingsTarget &target, uint32_t *processState = nullptr) {
    proc_bsdinfo info {}; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (pid <= 1 || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) || info.pbi_uid != 501 ||
        proc_pidpath(pid, path, sizeof(path)) <= 0 || strcmp(path, SettingsExecutable)) return false;
    SecCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributePid: @(pid)};
    OSStatus status = SecCodeCopyGuestWithAttributes(nullptr, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple and identifier \"com.apple.Touch-ID-Settings.extension\""), kSecCSDefaultFlags, &requirement);
    if (!status) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    if (status) return false;
    target = {0x45535447, pid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    if (processState) *processState = info.pbi_status;
    return true;
}
struct ExecutableMappingDiagnostics {
    unsigned regions = 0, pathMatches = 0, headerMatches = 0;
    int queryBytes = 0, queryError = 0;
    const char *outcome = "limit";
};
static uint64_t executableMapping(pid_t pid, const char *path, ExecutableMappingDiagnostics *diagnostics = nullptr) {
    ExecutableMappingDiagnostics local {};
    auto &trace = diagnostics ? *diagnostics : local;
    trace = {};
#if defined(__x86_64__)
    constexpr uint32_t nativeCPU = 0x01000007;
#elif defined(__arm64__)
    constexpr uint32_t nativeCPU = 0x0100000c;
#else
#error Unsupported settings broker architecture
#endif
    int image = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat imageInfo {};
    uint64_t sliceOffset = 0;
    bool parsed = image >= 0 && !fstat(image, &imageInfo) && S_ISREG(imageInfo.st_mode) && imageInfo.st_size >= 0 &&
        nativeExecutableSlice(uint64_t(imageInfo.st_size), nativeCPU,
            [&](uint64_t at, void *bytes, size_t size) {
                return pread(image, bytes, size, static_cast<off_t>(at)) == static_cast<ssize_t>(size);
            }, sliceOffset);
    if (image >= 0) close(image);
    if (!parsed) { trace.outcome = "image_rejected"; return 0; }
    uint64_t address = 0;
    for (unsigned index = 0; index < 4096; index++) {
        proc_regionwithpathinfo info {};
        errno = 0;
        trace.queryBytes = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &info, sizeof(info));
        trace.queryError = errno;
        if (trace.queryBytes != sizeof(info)) { trace.outcome = "query_failed"; return 0; }
        trace.regions++;
        const auto &region = info.prp_prinfo;
        if (!strcmp(info.prp_vip.vip_path, path)) {
            trace.pathMatches++;
            if (region.pri_offset == sliceOffset) {
                trace.headerMatches++;
                if (region.pri_protection & VM_PROT_EXECUTE) {
                    trace.outcome = "found"; return region.pri_address;
                }
            }
        }
        if (!region.pri_size || region.pri_address > UINT64_MAX - region.pri_size || region.pri_address + region.pri_size <= address) {
            trace.outcome = "invalid_region"; return 0;
        }
        address = region.pri_address + region.pri_size;
    }
    return 0;
}
static bool sameSettings(const SettingsTarget &target, uint32_t *state = nullptr) {
    SettingsTarget now {};
    return settingsIdentity(target.pid, now, state) && !memcmp(&target, &now, sizeof(target));
}
static bool settingsGone(const SettingsTarget &target) {
    proc_bsdinfo info {};
    int count = proc_pidinfo(target.pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return count == 0 || (count == sizeof(info) &&
        (info.pbi_status == SZOMB || info.pbi_start_tvsec != target.seconds || info.pbi_start_tvusec != target.microseconds));
}
static int readSettingsJournal(SettingsTarget &target) {
    int fd = open(SettingsJournal, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat info {};
    bool valid = !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 && !(info.st_mode & 077) &&
        info.st_size == sizeof(target) && read(fd, &target, sizeof(target)) == sizeof(target) && target.magic == 0x45535447 && target.pid > 1;
    close(fd); return valid ? 1 : -1;
}
static bool stopSettings(pid_t pid, bool &ownedAttempt) {
    ownedAttempt = false;
    SettingsTarget target {}; uint32_t state = 0;
    if (!settingsIdentity(pid, target, &state) || state == SSTOP || state == SZOMB) return false;
    int fd = open(SettingsJournal, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool saved = write(fd, &target, sizeof(target)) == sizeof(target) && !fsync(fd); close(fd);
    if (!saved) { unlink(SettingsJournal); return false; }
    ownedAttempt = true;
    if (!sameSettings(target) || kill(pid, SIGSTOP)) return false;
    for (unsigned index = 0; index < 100; index++) {
        if (!sameSettings(target, &state)) return false;
        if (state == SSTOP) return true;
        usleep(10000);
    }
    return false;
}
static bool resumeSettings(void) {
    SettingsTarget target {};
    if (readSettingsJournal(target) != 1) return false;
    if (settingsGone(target)) return true;
    if (!sameSettings(target) || kill(target.pid, SIGCONT)) return false;
    for (unsigned index = 0; index < 100; index++) {
        uint32_t state = 0;
        if (settingsGone(target)) return true;
        if (!sameSettings(target, &state)) return false;
        if (state != SSTOP) return true;
        usleep(10000);
    }
    return false;
}
static bool retireSettings(pid_t pid) {
    SettingsTarget target {};
    if (readSettingsJournal(target) != 1 || target.pid != pid) return false;
    if (settingsGone(target)) return true;
    if (!sameSettings(target) || kill(pid, SIGTERM)) return false;
    if (!settingsGone(target) && sameSettings(target)) kill(pid, SIGCONT);
    for (unsigned index = 0; index < 200; index++) { if (settingsGone(target)) return true; usleep(10000); }
    if (!sameSettings(target) || kill(pid, SIGKILL)) return false;
    for (unsigned index = 0; index < 100; index++) { if (settingsGone(target)) return true; usleep(10000); }
    return false;
}
