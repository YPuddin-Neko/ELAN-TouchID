#pragma once
#include "NativePlatformCache.h"

struct NativeLACRetryRequest {
    uint64_t instanceGetter;
    uint64_t faultGetter;
    uint64_t permanentGetter;
    uint64_t helperClass;
};
struct NativeLACRetryState {
    uint64_t object;
    uint64_t original[2];
    bool restartRequired;
};
static constexpr int NativePlatformRestartRequired = -31003;
static inline bool nativeUserPointer(uint64_t value) {
    return value >= 0x1000 && value <= 0x00007fffffffff00ULL && !(value & 7);
}

// The caller stops all target threads before this one-time ownership transfer.
// A successful transfer is retired by process exit, never by restoring a stale NSError pointer.
static inline int nativeLACRetryPrepare(const NativePlatformCacheAPI &api,
                                        const NativeLACRetryRequest &request, NativeLACRetryState &state) {
    if (state.object || !nativeUserPointer(request.helperClass)) return NativePlatformInvalid;
    const uint64_t functions[] = {request.instanceGetter, request.faultGetter, request.permanentGetter};
    for (uint64_t function : functions)
        if (function < 0x1000 || function > 0x00007fffffffff00ULL) return NativePlatformInvalid;
    uint8_t instance[17] = {}, fault[10] = {}, permanent[10] = {};
    int status = api.read(api.context, request.instanceGetter, instance, sizeof(instance));
    if (!status) status = api.read(api.context, request.faultGetter, fault, sizeof(fault));
    if (!status) status = api.read(api.context, request.permanentGetter, permanent, sizeof(permanent));
    if (status) return status;
    const uint8_t faultCode[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x47, 0x48, 0x5d, 0xc3};
    const uint8_t permanentCode[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x47, 0x50, 0x5d, 0xc3};
    if (memcmp(fault, faultCode, 10) || memcmp(permanent, permanentCode, 10) ||
        instance[0] != 0x48 || instance[1] != 0x83 || instance[2] != 0x3d || instance[7] != 0xff ||
        instance[8] != 0x75 || instance[9] != 0x0c || instance[10] != 0x48 ||
        instance[11] != 0x8b || instance[12] != 0x3d) return NativePlatformInvalid;
    int32_t onceDelta = 0, objectDelta = 0;
    memcpy(&onceDelta, instance + 3, 4); memcpy(&objectDelta, instance + 13, 4);
    uint64_t onceAddress = request.instanceGetter + 8 + onceDelta;
    uint64_t objectAddress = request.instanceGetter + 17 + objectDelta;
    if (!nativeUserPointer(onceAddress) || !nativeUserPointer(objectAddress)) return NativePlatformInvalid;
    uint64_t once = 0, object = 0;
    status = api.read(api.context, onceAddress, &once, sizeof(once));
    if (!status) status = api.read(api.context, objectAddress, &object, sizeof(object));
    if (status) return status;
    if (once != UINT64_MAX || !nativeUserPointer(object) || !api.writable(api.context, object + 0x48, 16))
        return NativePlatformInvalid;
    uint64_t snapshot[12] = {};
    status = api.read(api.context, object, snapshot, sizeof(snapshot));
    if (status) return status;
    if ((snapshot[0] & 0x00007ffffffffff8ULL) != request.helperClass || snapshot[6] || snapshot[9] ||
        !nativeUserPointer(snapshot[10]) || snapshot[11] != 1) return NativePlatformChanged;
    state.object = object;
    state.original[0] = snapshot[9]; state.original[1] = snapshot[10];
    return 0;
}

static inline int nativeLACRetryTransfer(const NativePlatformCacheAPI &api, NativeLACRetryState &state) {
    if (!state.object || state.restartRequired) return NativePlatformInvalid;
    uint64_t before[2] = {};
    int status = api.read(api.context, state.object + 0x48, before, sizeof(before));
    if (status || memcmp(before, state.original, sizeof(before))) return status ? status : NativePlatformChanged;
    const uint64_t retry[2] = {state.original[1], 0};
    state.restartRequired = true;
    status = api.write(api.context, state.object + 0x48, retry, sizeof(retry));
    uint64_t after[2] = {};
    int read = api.read(api.context, state.object + 0x48, after, sizeof(after));
    if (!status && !read && !memcmp(after, retry, sizeof(after))) return 0;
    int failure = status ? status : read ? read : NativePlatformChanged;
    api.write(api.context, state.object + 0x48, state.original, sizeof(state.original));
    read = api.read(api.context, state.object + 0x48, after, sizeof(after));
    if (!read && !memcmp(after, state.original, sizeof(after))) state.restartRequired = false;
    return failure;
}
