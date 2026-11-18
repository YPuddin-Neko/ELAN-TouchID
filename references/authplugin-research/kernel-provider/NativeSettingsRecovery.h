#pragma once
#include "NativeConnectionImage.h"
#include "NativeSettingsCache.h"

// Enable only after the owned-pause and identity-bound retirement backends are integrated.
static constexpr bool NativeSettingsRecoveryRuntimeReady = false;
static constexpr int NativeSettingsRecoveryUnavailable = -31004;

enum class NativeSettingsRecoveryPhase : uint32_t {
    Idle, Inspect, PrepareOuter, PrepareInner, EnablePlatform, RetryInner, RetryOuter, Complete
};
struct NativeSettingsRecoveryState {
    NativePlatformCacheState platform;
    NativeConnectionCacheState connection;
    NativeSettingsCacheState settings;
    NativeSettingsRecoveryPhase phase;
    int status;
    int rollbackStatus;
};
static inline bool nativeSettingsRecoveryRetirement(const NativeSettingsRecoveryState &s) {
    return s.connection.restartRequired || s.settings.restartRequired;
}
static inline bool nativeSettingsRecoveryPending(const NativeSettingsRecoveryState &s) {
    return s.platform.restorePending || nativeSettingsRecoveryRetirement(s);
}

// All operations use one caller-owned suspended-process map. No operation reattaches by PID.
template <typename Operations>
static inline int nativeSettingsRecoveryExecute(Operations &ops, NativeSettingsRecoveryState &state) {
    if (state.phase != NativeSettingsRecoveryPhase::Idle) return NativePlatformInvalid;
    state.phase = NativeSettingsRecoveryPhase::Inspect;
    int result = ops.inspect();
    if (!result) { state.phase = NativeSettingsRecoveryPhase::PrepareOuter; result = ops.prepareOuter(); }
    if (!result) { state.phase = NativeSettingsRecoveryPhase::PrepareInner; result = ops.prepareInner(); }
    if (!result) { state.phase = NativeSettingsRecoveryPhase::EnablePlatform; result = ops.enablePlatform(); }
    if (!result) { state.phase = NativeSettingsRecoveryPhase::RetryInner; result = ops.retryInner(); }
    if (!result) { state.phase = NativeSettingsRecoveryPhase::RetryOuter; result = ops.retryOuter(); }
    state.status = result;
    if (result) state.rollbackStatus = ops.restorePlatform();
    else state.phase = NativeSettingsRecoveryPhase::Complete;
    // Never restore once tokens after a process can resume. Dirty caches require process retirement.
    return result;
}

static constexpr int NativeSettingsRecoveryRestartRequired = -31003;
// Cleanup may run after resume; unlike in-transaction rollback it has no memory writer.
static inline int nativeSettingsRecoveryCleanup(NativeSettingsRecoveryState &state, bool sameMap) {
    if (sameMap && nativeSettingsRecoveryPending(state)) return NativeSettingsRecoveryRestartRequired;
    state = {};
    return 0;
}

struct NativeSettingsRecoveryOperations {
    const NativePlatformCacheAPI &api;
    uint64_t platformFunction;
    uint64_t settingsImage;
    bool (*executable)(void *, uint64_t, size_t);
    NativeSettingsRecoveryState &state;
    uint64_t getter = 0;
    int inspect() {
        NativeConnectionImageReport report {};
        int status = nativeConnectionImageInspect(api, platformFunction, executable, report, getter);
        if (status) return status;
        // This entry point is only for the confirmed completed-empty case.
        return report.imageMatched && report.observation == NativeConnectionObservation::CompletedEmpty ? 0 : NativePlatformChanged;
    }
    int prepareOuter() { return nativeSettingsCachePrepare(api, settingsImage, state.settings); }
    int prepareInner() {
        int status = nativeConnectionCachePrepare(api, getter, state.connection);
        return status ? status : state.connection.originalOnce == UINT64_MAX ? 0 : NativePlatformChanged;
    }
    int enablePlatform() { return nativePlatformEnable(api, platformFunction, state.platform, true); }
    int retryInner() { return nativeConnectionCacheRetry(api, state.connection); }
    int retryOuter() { return nativeSettingsCacheRetry(api, state.settings); }
    int restorePlatform() { return nativePlatformRestore(api, state.platform); }
};
static inline int nativeSettingsRecoveryEnable(const NativePlatformCacheAPI &api, uint64_t platform,
    uint64_t image, bool (*executable)(void *, uint64_t, size_t), NativeSettingsRecoveryState &state) {
    NativeSettingsRecoveryOperations ops {api, platform, image, executable, state, 0};
    return nativeSettingsRecoveryExecute(ops, state);
}
