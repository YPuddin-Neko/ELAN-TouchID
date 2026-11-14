#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t pid;
    uint64_t seconds, microseconds;
} NativeSessionProcess;

typedef struct {
    bool consoleKnown, guiKnown, securityKnown, onConsole, loginDone, graphicAccess;
    uint32_t consoleUser, guiUser, securitySession;
    NativeSessionProcess coreauth;
} NativeUserSessionSnapshot;

typedef enum {
    NativeSessionCurrent = 0,
    NativeSessionNoConsole = 1,
    NativeSessionOtherUser = 2,
    NativeSessionNoGUI = 3,
    NativeSessionInactiveGUI = 4,
    NativeSessionNoSecuritySession = 5,
    NativeSessionNoCoreAuth = 6,
    NativeSessionSecurityChanged = 7,
    NativeSessionCoreAuthChanged = 8,
    NativeSessionNotStarted = 9,
} NativeSessionStatus;

typedef struct {
    bool started;
    uint32_t securitySession;
    NativeSessionProcess coreauth;
    NativeSessionStatus stopped;
} NativeUserSessionState;

static inline bool nativeConsoleUserAllowed(bool known, uint32_t user) { return known && user == 501; }

static inline NativeSessionStatus nativeSessionAdmission(NativeUserSessionSnapshot value, bool requireCoreAuth) {
    if (!value.consoleKnown) return NativeSessionNoConsole;
    if (value.consoleUser != 501) return NativeSessionOtherUser;
    if (!value.guiKnown || value.guiUser != 501) return NativeSessionNoGUI;
    if (!value.onConsole || !value.loginDone) return NativeSessionInactiveGUI;
    if (!value.securityKnown || !value.graphicAccess || !value.securitySession || value.securitySession == UINT32_MAX)
        return NativeSessionNoSecuritySession;
    if (requireCoreAuth && (value.coreauth.pid <= 1 || !value.coreauth.seconds)) return NativeSessionNoCoreAuth;
    return NativeSessionCurrent;
}

static inline NativeSessionStatus nativeSessionStart(NativeUserSessionState *state, NativeUserSessionSnapshot value) {
    if (state->started || state->stopped) return NativeSessionNotStarted;
    NativeSessionStatus status = nativeSessionAdmission(value, true);
    if (status) { state->stopped = status; return status; }
    state->started = true;
    state->securitySession = value.securitySession;
    state->coreauth = value.coreauth;
    return NativeSessionCurrent;
}

static inline NativeSessionStatus nativeSessionObserve(NativeUserSessionState *state, NativeUserSessionSnapshot value) {
    if (state->stopped) return state->stopped;
    if (!state->started) return NativeSessionNotStarted;
    NativeSessionStatus status = nativeSessionAdmission(value, true);
    if (!status && state->securitySession != value.securitySession) status = NativeSessionSecurityChanged;
    if (!status && (state->coreauth.pid != value.coreauth.pid || state->coreauth.seconds != value.coreauth.seconds ||
                   state->coreauth.microseconds != value.coreauth.microseconds)) status = NativeSessionCoreAuthChanged;
    if (status) state->stopped = status;
    return status;
}
