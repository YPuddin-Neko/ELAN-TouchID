#pragma once
#include "NativePlatformCache.h"

static constexpr uint64_t NativeSettingsDeviceFunctionOffset = 0x6fb1;
static constexpr uint8_t NativeSettingsImageUUID[16] = {
    0x41, 0x8e, 0xcd, 0x95, 0xe7, 0x42, 0x38, 0x47, 0x96, 0x21, 0x84, 0x13, 0x5a, 0x94, 0xb6, 0x34
};
struct NativeSettingsCacheState {
    uint64_t once;
    uint64_t object;
    uint64_t originalOnce;
    bool restartRequired;
};

// Both platform initialization and this reset run while the selected extension is stopped.
static inline int nativeSettingsCachePrepare(const NativePlatformCacheAPI &api, uint64_t image,
                                             NativeSettingsCacheState &state) {
    if (state.once || image < 0x1000 || image > 0x00007fffffffffffULL - 0x7b868 || (image & 0xfff)) return NativePlatformInvalid;
    uint32_t header[8] = {};
    int status = api.read(api.context, image, header, sizeof(header));
    if (status) return status;
    if (header[0] != 0xfeedfacf || header[1] != 0x01000007 || header[3] != 2 ||
        !header[4] || header[4] > 128 || header[5] > 0x10000 || header[5] < header[4] * 8) return NativePlatformInvalid;
    uint64_t cursor = image + sizeof(header), end = cursor + header[5];
    bool uuidMatched = false;
    for (unsigned index = 0; index < header[4]; index++) {
        uint32_t command[2] = {};
        if (cursor > end - sizeof(command)) return NativePlatformInvalid;
        status = api.read(api.context, cursor, command, sizeof(command));
        if (status) return status;
        if (command[1] < 8 || command[1] % 8 || command[1] > end - cursor) return NativePlatformInvalid;
        if (command[0] == 0x1b) {
            uint8_t uuid[16] = {};
            if (uuidMatched || command[1] != 24) return NativePlatformInvalid;
            status = api.read(api.context, cursor + 8, uuid, sizeof(uuid));
            if (status) return status;
            if (memcmp(uuid, NativeSettingsImageUUID, sizeof(uuid))) return NativePlatformChanged;
            uuidMatched = true;
        }
        cursor += command[1];
    }
    if (!uuidMatched || cursor != end) return NativePlatformInvalid;
    uint64_t function = image + NativeSettingsDeviceFunctionOffset;
    uint8_t code[17] = {};
    status = api.read(api.context, function, code, sizeof(code));
    if (status) return status;
    if (code[0] != 0x48 || code[1] != 0x83 || code[2] != 0x3d || code[7] != 0xff ||
        code[8] != 0x75 || code[9] != 0x0c || code[10] != 0x48 || code[11] != 0x8b || code[12] != 0x3d)
        return NativePlatformInvalid;
    int32_t onceDelta = 0, objectDelta = 0;
    memcpy(&onceDelta, code + 3, sizeof(onceDelta)); memcpy(&objectDelta, code + 13, sizeof(objectDelta));
    uint64_t once = function + 8 + onceDelta, object = function + 17 + objectDelta;
    if (once != image + 0x7b858 || object != once + 8 || !api.writable(api.context, once, 16)) return NativePlatformInvalid;
    uint64_t values[2] = {};
    status = api.read(api.context, once, values, sizeof(values));
    if (status) return status;
    if ((values[0] && values[0] != UINT64_MAX) || values[1]) return NativePlatformChanged;
    state = {once, object, values[0], false};
    return 0;
}

static inline int nativeSettingsCacheRetry(const NativePlatformCacheAPI &api, NativeSettingsCacheState &state) {
    if (!state.once || state.restartRequired) return NativePlatformInvalid;
    uint64_t before[2] = {};
    int status = api.read(api.context, state.once, before, sizeof(before));
    if (status) return status;
    if (before[0] != state.originalOnce || before[1]) return NativePlatformChanged;
    // The next device object belongs to this extension process; cleanup retires that process.
    state.restartRequired = true;
    if (!before[0]) return 0;
    uint64_t reset = 0;
    status = api.write(api.context, state.once, &reset, sizeof(reset));
    uint64_t after[2] = {};
    int read = api.read(api.context, state.once, after, sizeof(after));
    if (!status && !read && !after[0] && !after[1]) return 0;
    int failure = status ? status : read ? read : NativePlatformChanged;
    api.write(api.context, state.once, &state.originalOnce, sizeof(state.originalOnce));
    read = api.read(api.context, state.once, after, sizeof(after));
    if (!read && after[0] == state.originalOnce && !after[1]) state.restartRequired = false;
    return failure;
}
