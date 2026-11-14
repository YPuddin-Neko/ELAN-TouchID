#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct NativePlatformCacheLocation {
    uint64_t checked;
    uint64_t result;
};

// Instruction layout from BiometricKit in macOS build 24H32, x86_64.
static inline bool nativePlatformCacheLocation(const uint8_t *code, size_t length,
                                               uint64_t function, NativePlatformCacheLocation &out) {
    out = {};
    if (!code || length < 0x245 || function < 0x1000 || function > 0x00007fffffffffffull - 0x245)
        return false;
    if (code[0x43] != 0x80 || code[0x44] != 0x3d || code[0x49] != 0 ||
        code[0x9d] != 0xc6 || code[0x9e] != 0x05 || code[0xa3] != 1 ||
        code[0x23f] != 0x8a || code[0x240] != 0x1d) return false;
    int32_t readChecked, writeChecked, readResult;
    memcpy(&readChecked, code + 0x45, 4);
    memcpy(&writeChecked, code + 0x9f, 4);
    memcpy(&readResult, code + 0x241, 4);
    int64_t checked = static_cast<int64_t>(function) + 0x4a + readChecked;
    int64_t written = static_cast<int64_t>(function) + 0xa4 + writeChecked;
    int64_t result = static_cast<int64_t>(function) + 0x245 + readResult;
    if (checked != written || result != checked + 1 || checked < 0x1000 ||
        result > 0x00007fffffffffffLL) return false;
    out = {static_cast<uint64_t>(checked), static_cast<uint64_t>(result)};
    return true;
}

struct NativePlatformCacheAPI {
    void *context;
    int (*read)(void *, uint64_t, void *, size_t);
    int (*write)(void *, uint64_t, const void *, size_t);
    bool (*writable)(void *, uint64_t, size_t);
};

struct NativePlatformCacheState {
    NativePlatformCacheLocation location;
    uint8_t original[2];
    bool restorePending;
};

static constexpr int NativePlatformInvalid = -31001;
static constexpr int NativePlatformChanged = -31002;

static inline int nativePlatformRestore(const NativePlatformCacheAPI &api, NativePlatformCacheState &state) {
    if (!state.restorePending) return 0;
    int status = api.write(api.context, state.location.checked, state.original, sizeof(state.original));
    uint8_t after[2] = {0xff, 0xff};
    int read = api.read(api.context, state.location.checked, after, sizeof(after));
    // A failed write can still have changed memory. Readback determines whether restoration completed.
    if (!read && !memcmp(after, state.original, sizeof(after))) {
        state.restorePending = false;
        return 0;
    }
    return status ? status : read ? read : NativePlatformChanged;
}

static inline int nativePlatformEnable(const NativePlatformCacheAPI &api, uint64_t function,
                                      NativePlatformCacheState &state, bool allowUnchecked = false) {
    if (state.restorePending) return NativePlatformInvalid;
    uint8_t code[0x245] = {};
    int status = api.read(api.context, function, code, sizeof(code));
    if (status) return status;
    NativePlatformCacheLocation location {};
    if (!nativePlatformCacheLocation(code, sizeof(code), function, location) ||
        !api.writable(api.context, location.checked, 2)) return NativePlatformInvalid;
    uint8_t before[2] = {};
    status = api.read(api.context, location.checked, before, sizeof(before));
    if (status) return status;
    if (before[1] != 0 || (before[0] != 1 && !(allowUnchecked && before[0] == 0))) return NativePlatformChanged;
    state.location = location;
    state.original[0] = before[0];
    state.original[1] = before[1];
    state.restorePending = true;
    const uint8_t enabled[2] = {1, 1};
    status = api.write(api.context, location.checked, enabled, sizeof(enabled));
    uint8_t after[2] = {};
    int read = api.read(api.context, location.checked, after, sizeof(after));
    if (!status && (read || memcmp(after, enabled, sizeof(after)))) status = read ? read : NativePlatformChanged;
    if (status) nativePlatformRestore(api, state);
    return status;
}
