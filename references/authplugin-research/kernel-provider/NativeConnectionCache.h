#pragma once
#include "NativePlatformCache.h"

// The caller must pin the framework image/build and suspend all target threads.
// This prototype is not wired into the system-process path.
struct NativeConnectionCacheState {
    uint64_t once;
    uint64_t object;
    uint64_t originalOnce;
    bool restartRequired;
};

static inline int nativeConnectionCachePrepare(const NativePlatformCacheAPI &api, uint64_t getter,
                                               NativeConnectionCacheState &state) {
    if (state.once || getter < 0x1000 || getter > 0x00007fffffffffffULL - 0x59)
        return NativePlatformInvalid;
    uint8_t code[0x59] = {};
    int status = api.read(api.context, getter, code, sizeof(code));
    if (status) return status;
    // 24H32 Intel: completed-token test, initialization branch, then cached-object load.
    if (code[0x46] != 0x48 || code[0x47] != 0x83 || code[0x48] != 0x3d ||
        code[0x4d] != 0xff || code[0x4e] != 0x75 || code[0x4f] != 0x62 ||
        code[0x50] != 0x48 || code[0x51] != 0x8d || code[0x52] != 0x05)
        return NativePlatformInvalid;
    int32_t onceDelta = 0, objectDelta = 0;
    memcpy(&onceDelta, code + 0x49, 4); memcpy(&objectDelta, code + 0x53, 4);
    int64_t once = static_cast<int64_t>(getter) + 0x4e + onceDelta;
    int64_t object = static_cast<int64_t>(getter) + 0x57 + objectDelta;
    if (object < 0x1000 || once != object + 8 || once > 0x00007fffffffffffLL - 8 ||
        (object & 7) || !api.writable(api.context, static_cast<uint64_t>(object), 16))
        return NativePlatformInvalid;
    uint64_t values[2] = {};
    status = api.read(api.context, static_cast<uint64_t>(object), values, sizeof(values));
    if (status) return status;
    // Never touch a live object or a dispatch_once initialization in flight.
    if (values[0] || (values[1] && values[1] != UINT64_MAX)) return NativePlatformChanged;
    state = {static_cast<uint64_t>(once), static_cast<uint64_t>(object), values[1], false};
    return 0;
}

static inline int nativeConnectionCacheRetry(const NativePlatformCacheAPI &api,
                                             NativeConnectionCacheState &state) {
    if (!state.once || state.restartRequired) return NativePlatformInvalid;
    uint64_t values[2] = {};
    int status = api.read(api.context, state.object, values, sizeof(values));
    if (status) return status;
    if (values[0] || values[1] != state.originalOnce) return NativePlatformChanged;
    // After resumption the framework owns any new object; cleanup must retire the process.
    state.restartRequired = true;
    if (!state.originalOnce) return 0;
    uint64_t reset = 0;
    status = api.write(api.context, state.once, &reset, sizeof(reset));
    int read = api.read(api.context, state.object, values, sizeof(values));
    if (!status && !read && !values[0] && !values[1]) return 0;
    int failure = status ? status : read ? read : NativePlatformChanged;
    api.write(api.context, state.once, &state.originalOnce, sizeof(state.originalOnce));
    read = api.read(api.context, state.object, values, sizeof(values));
    if (!read && !values[0] && values[1] == state.originalOnce) state.restartRequired = false;
    return failure;
}
