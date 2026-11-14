#include "native-settings-session.h"
#include <assert.h>
#include <stdio.h>
#include <vector>

struct Fixture {
    std::vector<int> events;
    int enableStatus = 0, restoreStatus = 0;
    static int enable(void *raw, int32_t pid) {
        auto &self = *static_cast<Fixture *>(raw); self.events.push_back(pid); return self.enableStatus;
    }
    static int restore(void *raw) {
        auto &self = *static_cast<Fixture *>(raw); self.events.push_back(-1); return self.restoreStatus;
    }
    static void changed(void *raw) { static_cast<Fixture *>(raw)->events.push_back(-2); }
    NativeSettingsSessionAPI api() { return {this, enable, restore, changed}; }
};
int main() {
    Fixture test; NativeSettingsSession state {};
    NativeSettingsIdentity first {1234, 10, 20}, reopened {4321, 11, 21}, reused {4321, 12, 22}, none {};
    assert(!nativeSettingsSessionObserve(&state, test.api(), none, true, false));
    assert(!nativeSettingsSessionObserve(&state, test.api(), first, false, false));
    assert(!nativeSettingsSessionObserve(&state, test.api(), first, true, true));
    assert(test.events.empty());
    assert(!nativeSettingsSessionObserve(&state, test.api(), first, true, false));
    assert((test.events == std::vector<int>{1234, -2}));
    assert(!nativeSettingsSessionObserve(&state, test.api(), first, true, false));
    assert(!nativeSettingsSessionObserve(&state, test.api(), none, false, false));
    assert(test.events.size() == 2);
    assert(!nativeSettingsSessionObserve(&state, test.api(), reopened, true, false));
    assert((test.events == std::vector<int>{1234, -2, -1, 4321, -2}));
    assert(!nativeSettingsSessionObserve(&state, test.api(), reused, true, false));
    assert((test.events == std::vector<int>{1234, -2, -1, 4321, -2, -1, 4321, -2}));
    assert(!nativeSettingsSessionObserve(&state, test.api(), none, true, false));
    assert(!state.active.pid && test.events.back() == -1);
    test.events.clear(); test.enableStatus = -51;
    assert(nativeSettingsSessionObserve(&state, test.api(), first, true, false) == -51);
    assert(!state.active.pid && test.events == std::vector<int>{1234});
    assert(nativeSettingsSessionObserve(&state, test.api(), first, true, false) == -51);
    assert(test.events.size() == 1);
    state = {}; test = {}; test.restoreStatus = -52;
    assert(!nativeSettingsSessionObserve(&state, test.api(), first, true, false));
    assert(nativeSettingsSessionObserve(&state, test.api(), reopened, true, false) == -52);
    assert(state.active.pid == first.pid && (test.events == std::vector<int>{1234, -2, -1}));
    assert(nativeSettingsSessionObserve(&state, test.api(), reopened, true, false) == -52);
    assert(test.events.size() == 3);
    state = {}; test = {};
    assert(nativeSettingsSessionObserve(&state, test.api(), {1, 10, 20}, true, false));
    assert(test.events.empty());
    puts("settings session: deferred capture, one attach per lifetime, close/reopen, PID reuse, restore-before-attach, refresh-after-success and failure stop passed");
}
