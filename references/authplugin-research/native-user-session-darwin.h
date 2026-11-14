#pragma once
#include "native-user-session.h"
#include <CoreGraphics/CGSession.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <Security/AuthSession.h>
#include <libproc.h>
#include <sys/proc.h>
#include <stdlib.h>
#include <string.h>

static inline bool nativeConsoleUser(uint32_t *user) {
    uid_t uid = (uid_t)-1; gid_t group = (gid_t)-1;
    CFStringRef name = SCDynamicStoreCopyConsoleUser(NULL, &uid, &group);
    if (!name) { *user = UINT32_MAX; return false; }
    CFRelease(name); *user = uid; return true;
}

static inline NativeSessionProcess nativeCoreAuthProcess(int32_t pid) {
    NativeSessionProcess result = {0, 0, 0};
    struct proc_bsdinfo info = {};
    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (pid > 1 && proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) &&
        info.pbi_uid == 501 && info.pbi_status != SZOMB && proc_pidpath(pid, path, sizeof(path)) > 0 &&
        !strcmp(path, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd"))
        result = (NativeSessionProcess){pid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    return result;
}

static inline NativeSessionProcess nativeFindCoreAuth(void) {
    NativeSessionProcess found = {0, 0, 0};
    int size = proc_listpids(PROC_UID_ONLY, 501, NULL, 0);
    if (size <= 0 || size > 1024 * 1024 - 128) return found;
    size += 128;
    pid_t *pids = (pid_t *)calloc(1, (size_t)size);
    if (!pids) return found;
    int count = proc_listpids(PROC_UID_ONLY, 501, pids, size);
    if (count > 0 && count < size) {
        for (int index = 0; index < count / (int)sizeof(pid_t); index++) {
            NativeSessionProcess value = nativeCoreAuthProcess(pids[index]);
            if (!value.pid) continue;
            if (found.pid) { found = (NativeSessionProcess){0, 0, 0}; break; }
            found = value;
        }
    }
    free(pids); return found;
}

static inline NativeUserSessionSnapshot nativeReadUserSession(int32_t coreauth) {
    NativeUserSessionSnapshot value = {};
    value.consoleKnown = nativeConsoleUser(&value.consoleUser);
    CFDictionaryRef session = CGSessionCopyCurrentDictionary();
    if (session) {
        CFTypeRef user = CFDictionaryGetValue(session, kCGSessionUserIDKey);
        CFTypeRef console = CFDictionaryGetValue(session, kCGSessionOnConsoleKey);
        CFTypeRef done = CFDictionaryGetValue(session, kCGSessionLoginDoneKey);
        int64_t uid = -1;
        value.guiKnown = user && CFGetTypeID(user) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)user, kCFNumberSInt64Type, &uid) && uid >= 0 && uid <= UINT32_MAX &&
            console && CFGetTypeID(console) == CFBooleanGetTypeID() && done && CFGetTypeID(done) == CFBooleanGetTypeID();
        if (value.guiKnown) {
            value.guiUser = (uint32_t)uid;
            value.onConsole = CFBooleanGetValue((CFBooleanRef)console);
            value.loginDone = CFBooleanGetValue((CFBooleanRef)done);
        }
        CFRelease(session);
    }
    SecuritySessionId identity = noSecuritySession;
    SessionAttributeBits attributes = 0;
    value.securityKnown = SessionGetInfo(callerSecuritySession, &identity, &attributes) == errSecSuccess;
    value.securitySession = identity;
    value.graphicAccess = (attributes & sessionHasGraphicAccess) != 0;
    value.coreauth = coreauth > 1 ? nativeCoreAuthProcess(coreauth) : nativeFindCoreAuth();
    return value;
}
