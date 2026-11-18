#include "NativeSettingsRecovery.h"
#include <assert.h>
#include <stdio.h>
#include <vector>
struct Fake {
    NativeSettingsRecoveryState &s;
    explicit Fake(NativeSettingsRecoveryState &state) : s(state) {}
    int fail = 0, rollbackFailure = 0;
    bool effectBeforeFailure = false;
    std::vector<int> calls;
    unsigned boundMap = 7;
    int operation(int phase) {
        assert(boundMap == 7); calls.push_back(phase);
        if (phase == fail && !effectBeforeFailure) return -phase;
        if (phase == 4) s.platform.restorePending = true;
        if (phase == 5) s.connection.restartRequired = true;
        if (phase == 6) s.settings.restartRequired = true;
        return phase == fail ? -phase : 0;
    }
    int inspect() { return operation(1); }
    int prepareOuter() { return operation(2); }
    int prepareInner() { return operation(3); }
    int enablePlatform() { return operation(4); }
    int retryInner() { return operation(5); }
    int retryOuter() { return operation(6); }
    int restorePlatform() {
        assert(boundMap == 7); calls.push_back(7);
        if (!rollbackFailure) s.platform.restorePending = false;
        return rollbackFailure;
    }
};
int main() {
    static_assert(!NativeSettingsRecoveryRuntimeReady, "unfinished runtime backend must stay disabled");
    NativeSettingsRecoveryState state{}; Fake success{state};
    assert(!nativeSettingsRecoveryExecute(success,state));
    assert((success.calls==std::vector<int>{1,2,3,4,5,6}));
    assert(state.phase==NativeSettingsRecoveryPhase::Complete && nativeSettingsRecoveryPending(state));
    assert(nativeSettingsRecoveryRetirement(state));
    assert(nativeSettingsRecoveryExecute(success,state)==NativePlatformInvalid);
    for(int failure=1;failure<=6;failure++) for(bool effect:{false,true}) {
        state={}; Fake test{state}; test.fail=failure;test.effectBeforeFailure=effect;
        assert(nativeSettingsRecoveryExecute(test,state)==-failure);
        assert(test.calls.back()==7 && test.calls.size()==static_cast<size_t>(failure+1));
        assert(state.status==-failure && !state.platform.restorePending);
        bool dirty=failure>5 || (effect&&failure>=5);
        assert(nativeSettingsRecoveryRetirement(state)==dirty);
        assert(nativeSettingsRecoveryPending(state)==dirty);
    }
    state={};Fake rollback{state};rollback.fail=5;rollback.rollbackFailure=-99;
    assert(nativeSettingsRecoveryExecute(rollback,state)==-5 && state.rollbackStatus==-99);
    assert(state.platform.restorePending && nativeSettingsRecoveryPending(state));
    // Same PID with a different map (exit/exec/PID reuse) must not invoke writes.
    unsigned before=rollback.calls.size();
    assert(!nativeSettingsRecoveryCleanup(state,false));
    assert(rollback.calls.size()==before && !nativeSettingsRecoveryPending(state));
    state={};Fake dirty{state};assert(!nativeSettingsRecoveryExecute(dirty,state));
    before=dirty.calls.size();
    assert(nativeSettingsRecoveryCleanup(state,true)==NativeSettingsRecoveryRestartRequired);
    assert(state.platform.restorePending && nativeSettingsRecoveryRetirement(state));
    assert(dirty.calls.size()==before);
    dirty.rollbackFailure=-98;
    assert(nativeSettingsRecoveryCleanup(state,true)==NativeSettingsRecoveryRestartRequired);
    assert(dirty.calls.size()==before && state.platform.restorePending);
    assert(!nativeSettingsRecoveryCleanup(state,false));
    assert(dirty.calls.size()==before && !nativeSettingsRecoveryPending(state));
    for(bool connectionOnly:{false,true}) for(bool platformPending:{false,true}) {
        state={};Fake oneDirty{state};
        state.connection.restartRequired=connectionOnly;
        state.settings.restartRequired=!connectionOnly;
        state.platform.restorePending=platformPending;
        oneDirty.rollbackFailure=-98;
        for(unsigned attempt=0;attempt<3;++attempt) {
            assert(nativeSettingsRecoveryCleanup(state,true)==NativeSettingsRecoveryRestartRequired);
            assert(oneDirty.calls.empty() && nativeSettingsRecoveryPending(state));
            assert(state.platform.restorePending==platformPending);
        }
        assert(!nativeSettingsRecoveryCleanup(state,false));
        assert(oneDirty.calls.empty() && !nativeSettingsRecoveryPending(state));
    }
    state={};state.platform.restorePending=true;
    for(unsigned attempt=0;attempt<3;++attempt) {
        assert(nativeSettingsRecoveryCleanup(state,true)==NativeSettingsRecoveryRestartRequired);
        assert(state.platform.restorePending && nativeSettingsRecoveryPending(state));
        assert(!nativeSettingsRecoveryRetirement(state));
    }
    assert(!nativeSettingsRecoveryCleanup(state,false) && !nativeSettingsRecoveryPending(state));
    state.phase=NativeSettingsRecoveryPhase::Complete;
    assert(!nativeSettingsRecoveryCleanup(state,true) && state.phase==NativeSettingsRecoveryPhase::Idle);
    puts("settings recovery: single-map ordering, six-stage failures, partial writes, rollback failure and retirement passed");
}
