#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t pid;
    uint64_t seconds;
    uint64_t microseconds;
} NativeSettingsIdentity;

typedef struct {
    NativeSettingsIdentity active;
    int failure;
} NativeSettingsSession;

typedef struct {
    void *context;
    int (*enable)(void *, int32_t);
    int (*restore)(void *);
    void (*changed)(void *);
} NativeSettingsSessionAPI;

static inline bool nativeSettingsSameIdentity(NativeSettingsIdentity left, NativeSettingsIdentity right) {
    return left.pid == right.pid && left.seconds == right.seconds && left.microseconds == right.microseconds;
}

// The caller serializes these operations with matching and catalog publication.
static inline int nativeSettingsSessionObserve(NativeSettingsSession *state, NativeSettingsSessionAPI api,
                                               NativeSettingsIdentity observed, bool reliable, bool busy) {
    if (state->failure) return state->failure;
    if (!reliable || busy || nativeSettingsSameIdentity(state->active, observed)) return 0;
    if (observed.pid < 0 || observed.pid == 1 || (observed.pid && !observed.seconds)) return state->failure = -33012;
    if (state->active.pid) {
        int status = api.restore(api.context);
        if (status) return state->failure = status;
        state->active = (NativeSettingsIdentity){0, 0, 0};
    }
    if (observed.pid) {
        int status = api.enable(api.context, observed.pid);
        if (status) return state->failure = status;
        state->active = observed;
        api.changed(api.context);
    }
    return 0;
}
