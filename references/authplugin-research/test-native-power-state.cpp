#include "native-power-state.h"
#include <cassert>
#include <cstdio>

int main() {
    NativePowerState state = {}; state.awake = true;
    assert(nativePowerReady(state, true, 15));
    assert(!nativePowerReady(state, false, 15));
    assert(!nativePowerReady(state, true, 1));
    auto ack = nativePowerEvent(&state, NativePowerIdle, 10, 0, true);
    assert(ack.count == 1 && ack.tokens[0] == 10 && !state.stop && state.awake);
    ack = nativePowerEvent(&state, NativePowerSleepCancelled, 0, 1, true);
    assert(!ack.count && !state.stop && state.awake);
    ack = nativePowerEvent(&state, NativePowerSleep, 11, 2, true);
    assert(!ack.count && state.stop && !state.awake && state.pending && state.epoch == 1);
    assert(!nativePowerReady(state, true, 15));
    ack = nativePowerEvent(&state, NativePowerSleep, 11, 3, true);
    assert(!ack.count && state.epoch == 1 && state.pendingSince == 2);
    assert(!nativePowerDeadline(&state, 21.999).count);
    ack = nativePowerDrain(&state);
    assert(ack.count == 1 && ack.tokens[0] == 11 && state.drained && !state.pending);
    assert(!nativePowerDrain(&state).count && !nativePowerDeadline(&state, 30).count);
    ack = nativePowerEvent(&state, NativePowerWakeStarting, 0, 31, true);
    assert(!ack.count && state.stop && !state.awake && state.epoch == 2);
    ack = nativePowerEvent(&state, NativePowerWakeComplete, 0, 32, true);
    assert(!ack.count && state.awake && state.stop && state.epoch == 3);
    assert(nativePowerReady(state, true, 15));

    state = {}; state.awake = true;
    nativePowerEvent(&state, NativePowerSleep, 21, 4, true);
    ack = nativePowerDeadline(&state, 24);
    assert(ack.count == 1 && ack.tokens[0] == 21 && ack.expired && state.stop && !state.awake);
    assert(!nativePowerDeadline(&state, 25).count && !nativePowerDrain(&state).count);

    state = {}; state.awake = true;
    nativePowerEvent(&state, NativePowerSleep, 31, 0, true);
    ack = nativePowerEvent(&state, NativePowerSleep, 32, 1, true);
    assert(ack.count == 1 && ack.tokens[0] == 31 && state.token == 32 && state.pending);
    nativePowerEvent(&state, NativePowerWakeComplete, 0, 2, true);
    assert(!nativePowerDrain(&state).count); // Never acknowledge a stale token after wake.

    state = {}; state.awake = true;
    ack = nativePowerEvent(&state, NativePowerSleep, 41, 0, false);
    assert(ack.count == 1 && ack.tokens[0] == 41 && !state.pending);
    assert(!nativePowerDrain(&state).count);
    puts("POWER_STATE idle_allow sleep_cancel drain_ack deadline_ack wake_gate old_generation_stopped passed=1");
}
