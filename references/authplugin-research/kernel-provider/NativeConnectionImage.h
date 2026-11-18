#pragma once
#include "NativeConnectionCache.h"

static constexpr uint8_t NativeConnectionImageUUID[16] = {
    0x52,0xcd,0x95,0x93,0x4f,0xdd,0x3b,0x45,0x8e,0x36,0x19,0x1f,0x00,0x8a,0x4e,0x3e
};
enum class NativeConnectionObservation : uint32_t {
    Unknown, NotStarted, CompletedEmpty, LiveObject, Initializing
};
enum class NativeConnectionImageStage : uint32_t { Address = 1, Header, LoadCommands, UUID, TextSegment, Execution, Accessor, CacheRead, Complete };
struct NativeConnectionImageReport {
    NativeConnectionObservation observation;
    bool imageMatched;
    NativeConnectionImageStage stage;
};

// Reads only. Does not expose pointers, inspect object contents, or reset either cache.
static inline int nativeConnectionImageInspect(const NativePlatformCacheAPI &api, uint64_t platform,
    bool (*executable)(void *, uint64_t, size_t), NativeConnectionImageReport &report,
    uint64_t &getter) {
    report = {}; getter = 0; report.stage = NativeConnectionImageStage::Address;
    constexpr uint64_t platformOffset = 0x238d1, getterOffset = 0x183f;
    if (!executable || platform < platformOffset + 0x1000) return NativePlatformInvalid;
    const uint64_t image = platform - platformOffset;
    if ((image & 0xfff) || image > 0x00007fffffffffffULL - 0x38b0daa8) return NativePlatformInvalid;
    report.stage = NativeConnectionImageStage::Header;
    uint32_t h[8] = {};
    int status = api.read(api.context, image, h, sizeof(h));
    if (status) return status;
    if (h[0] != 0xfeedfacf || h[1] != 0x01000007 || h[3] != 6 ||
        !h[4] || h[4] > 128 || h[5] > 0x10000 || h[5] < h[4] * 8) return NativePlatformInvalid;
    uint64_t cursor = image + sizeof(h), end = cursor + h[5];
    bool uuid = false, text = false;
    for (unsigned i = 0; i < h[4]; ++i) {
        report.stage = NativeConnectionImageStage::LoadCommands;
        uint32_t cmd[2] = {};
        if (cursor > end - 8) return NativePlatformInvalid;
        status = api.read(api.context, cursor, cmd, sizeof(cmd)); if (status) return status;
        if (cmd[1] < 8 || cmd[1] % 8 || cmd[1] > end - cursor) return NativePlatformInvalid;
        if (cmd[0] == 0x1b) {
            report.stage = NativeConnectionImageStage::UUID;
            uint8_t value[16] = {};
            if (uuid || cmd[1] != 24) return NativePlatformInvalid;
            status = api.read(api.context, cursor + 8, value, sizeof(value)); if (status) return status;
            if (memcmp(value, NativeConnectionImageUUID, sizeof(value))) return NativePlatformChanged;
            uuid = true;
        } else if (cmd[0] == 0x19) {
            uint8_t segment[72] = {};
            if (cmd[1] < sizeof(segment)) return NativePlatformInvalid;
            status = api.read(api.context, cursor, segment, sizeof(segment)); if (status) return status;
            const char textName[16] = "__TEXT";
            if (!memcmp(segment + 8, textName, sizeof(textName))) {
                report.stage = NativeConnectionImageStage::TextSegment;
                uint64_t size = 0, offset = 0; uint32_t protection = 0;
                memcpy(&size, segment + 32, 8); memcpy(&offset, segment + 40, 8);
                memcpy(&protection, segment + 60, 4);
                // The pinned Intel image is normally mapped from the dyld shared cache.
                // Its cache file offset is not the standalone Mach-O file offset.
                const uint64_t expectedOffset = (h[6] & 0x80000000U) ? 0x0a5b0000 : 0;
                if (text || offset != expectedOffset || size < platformOffset + 0x245 || size > 0x10000000 ||
                    !(protection & 4) || (protection & 2)) return NativePlatformInvalid;
                text = true;
            }
        }
        cursor += cmd[1];
    }
    report.stage = NativeConnectionImageStage::Execution;
    if (!uuid || !text || cursor != end || !executable(api.context, image + getterOffset, 0x59) ||
        !executable(api.context, platform, 0x245)) return NativePlatformInvalid;
    // Validate the accessor independently of the current state, including pinned data offsets.
    report.stage = NativeConnectionImageStage::Accessor;
    uint8_t code[0x59] = {};
    status = api.read(api.context, image + getterOffset, code, sizeof(code)); if (status) return status;
    if (code[0x46] != 0x48 || code[0x47] != 0x83 || code[0x48] != 0x3d || code[0x4d] != 0xff ||
        code[0x4e] != 0x75 || code[0x4f] != 0x62 || code[0x50] != 0x48 || code[0x51] != 0x8d || code[0x52] != 5)
        return NativePlatformInvalid;
    int32_t onceDelta = 0, objectDelta = 0;
    memcpy(&onceDelta, code+0x49,4); memcpy(&objectDelta, code+0x53,4);
    if (static_cast<int64_t>(getterOffset+0x4e)+onceDelta != 0x38b0daa0 ||
        static_cast<int64_t>(getterOffset+0x57)+objectDelta != 0x38b0da98) return NativePlatformInvalid;
    report.stage = NativeConnectionImageStage::CacheRead;
    uint64_t values[2] = {};
    status = api.read(api.context, image+0x38b0da98, values, sizeof(values)); if (status) return status;
    report.imageMatched = true;
    report.observation = values[0] ? NativeConnectionObservation::LiveObject :
        !values[1] ? NativeConnectionObservation::NotStarted :
        values[1] == UINT64_MAX ? NativeConnectionObservation::CompletedEmpty : NativeConnectionObservation::Initializing;
    getter = image + getterOffset;
    report.stage = NativeConnectionImageStage::Complete;
    return 0;
}
