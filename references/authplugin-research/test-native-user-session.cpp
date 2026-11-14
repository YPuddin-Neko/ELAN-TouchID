#include "native-user-session.h"
#include <assert.h>
#include <stdio.h>

static NativeUserSessionSnapshot eligible() {
    return {true, true, true, true, true, true, 501, 501, 100004, {1234, 100, 20}};
}
static void rejected(NativeUserSessionSnapshot bad, NativeSessionStatus expected) {
    NativeUserSessionState state {};
    assert(!nativeSessionStart(&state, eligible()));
    assert(nativeSessionObserve(&state, bad) == expected);
    assert(nativeSessionObserve(&state, eligible()) == expected);
    assert(nativeSessionStart(&state, eligible()) == NativeSessionNotStarted);
}
int main() {
    auto good = eligible(); NativeUserSessionState state {};
    assert(nativeSessionObserve(&state, good) == NativeSessionNotStarted);
    assert(!nativeSessionStart(&state, good));
    assert(!nativeSessionObserve(&state, good));
    assert(nativeSessionStart(&state, good) == NativeSessionNotStarted);
    auto bad = good; bad.consoleKnown = false; rejected(bad, NativeSessionNoConsole);
    bad = good; bad.consoleUser = 502; rejected(bad, NativeSessionOtherUser);
    bad = good; bad.guiKnown = false; rejected(bad, NativeSessionNoGUI);
    bad = good; bad.guiUser = 502; rejected(bad, NativeSessionNoGUI);
    bad = good; bad.loginDone = false; rejected(bad, NativeSessionInactiveGUI);
    bad = good; bad.onConsole = false; rejected(bad, NativeSessionInactiveGUI);
    bad = good; bad.securityKnown = false; rejected(bad, NativeSessionNoSecuritySession);
    bad = good; bad.graphicAccess = false; rejected(bad, NativeSessionNoSecuritySession);
    bad = good; bad.securitySession = 0; rejected(bad, NativeSessionNoSecuritySession);
    bad = good; bad.securitySession++; rejected(bad, NativeSessionSecurityChanged);
    bad = good; bad.coreauth.pid = 0; rejected(bad, NativeSessionNoCoreAuth);
    assert(!nativeSessionAdmission(bad, false));
    bad = good; bad.coreauth.pid++; rejected(bad, NativeSessionCoreAuthChanged);
    bad = good; bad.coreauth.seconds++; rejected(bad, NativeSessionCoreAuthChanged);
    bad = good; bad.coreauth.microseconds++; rejected(bad, NativeSessionCoreAuthChanged);
    state = {}; bad = good; bad.loginDone = false;
    assert(nativeSessionStart(&state, bad) == NativeSessionInactiveGUI && !state.started);
    assert(nativeSessionObserve(&state, good) == NativeSessionInactiveGUI);
    assert(nativeConsoleUserAllowed(true, 501));
    assert(!nativeConsoleUserAllowed(false, 501) && !nativeConsoleUserAllowed(true, 0) && !nativeConsoleUserAllowed(true, 502));
    puts("user session: console ownership, completed GUI login, own security session, coreauth lifetime and latched cancellation passed");
}
