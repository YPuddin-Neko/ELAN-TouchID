#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum { NativePowerIdle, NativePowerSleep, NativePowerWakeStarting,
    NativePowerWakeComplete, NativePowerSleepCancelled } NativePowerEvent;
typedef struct {
    bool awake, stop, pending, drained;
    intptr_t token;
    double pendingSince;
    uint64_t epoch;
} NativePowerState;
typedef struct {
    unsigned count;
    intptr_t tokens[2];
    bool expired;
} NativePowerAcknowledgement;

static inline void nativePowerAcknowledgePending(NativePowerState *state, NativePowerAcknowledgement *ack) {
    if (state->pending) {
        ack->tokens[ack->count++] = state->token;
        state->pending = false;
    }
}

static inline NativePowerAcknowledgement nativePowerEvent(NativePowerState *state,
        NativePowerEvent event, intptr_t token, double now, bool deferSleep) {
    NativePowerAcknowledgement ack = {};
    switch (event) {
        case NativePowerIdle:
            ack.tokens[ack.count++] = token;
            break;
        case NativePowerSleep:
            if (state->pending && state->token == token) break;
            nativePowerAcknowledgePending(state, &ack);
            state->awake = false; state->stop = true; state->epoch++;
            if (deferSleep && !state->drained) {
                state->pending = true; state->token = token; state->pendingSince = now;
            } else ack.tokens[ack.count++] = token;
            break;
        case NativePowerWakeStarting:
            state->awake = false; state->stop = true; state->epoch++;
            break;
        case NativePowerWakeComplete:
            // A sleep token is no longer valid after wake completion.
            state->pending = false;
            state->awake = true; state->stop = true; state->epoch++;
            break;
        case NativePowerSleepCancelled:
            break;
    }
    return ack;
}

static inline NativePowerAcknowledgement nativePowerDrain(NativePowerState *state) {
    NativePowerAcknowledgement ack = {};
    state->drained = true;
    nativePowerAcknowledgePending(state, &ack);
    return ack;
}

static inline NativePowerAcknowledgement nativePowerDeadline(NativePowerState *state, double now) {
    NativePowerAcknowledgement ack = {};
    if (state->pending && now - state->pendingSince >= 20) {
        nativePowerAcknowledgePending(state, &ack);
        ack.expired = true;
    }
    return ack;
}

static inline bool nativePowerReady(NativePowerState state, bool known, uint64_t capabilities) {
    // Public IOPM capability bits: CPU=1, graphics=2.
    return state.awake && known && (capabilities & 3) == 3;
}
