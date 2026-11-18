#pragma once
#include "NativeSettingsRoute.h"
#include "../agent-integration-candidate/settings-fresh-observation/SettingsSample.h"

namespace NativeCoreAuthSample {
using Copy = int(*)(void*, uint64_t, void*, size_t);
struct Local {
    unsigned reads = 0, bytes = 0;
};
struct Reader {
    Copy copy;
    void *context;
    Local &local;
    bool read(uint64_t address, void *out, size_t size) {
        if (!copy || !out || !size || size > 32 || address < 4096 || address > 0x7fffffffffffULL ||
            size - 1 > 0x7fffffffffffULL - address || local.reads >= 99 || local.bytes + size > 890)
            return false;
        ++local.reads;
        local.bytes += static_cast<unsigned>(size);
        return copy(context, address, out, size) == 0;
    }
    bool equal(uint64_t address, const void *pin, size_t size) {
        uint8_t bytes[32];
        return read(address, bytes, size) && !memcmp(bytes, pin, size);
    }
};

constexpr uint8_t header[] = {
    0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0xe8, 0x12, 0x00, 0x00, 0x85, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
};
constexpr uint32_t commands[][3] = {
    {0x20, 0x19, 0x48}, {0x68, 0x19, 0x458}, {0x4c0, 0x19, 0x408}, {0x8c8, 0x19, 0x278},
    {0xb40, 0x19, 0x48}, {0xb88, 0x80000034, 0x10}, {0xb98, 0x80000033, 0x10}, {0xba8, 0x2, 0x18},
    {0xbc0, 0xb, 0x50}, {0xc10, 0xe, 0x20}, {0xc30, 0x1b, 0x18}, {0xc48, 0x32, 0x20},
    {0xc68, 0x2a, 0x10}, {0xc78, 0x80000028, 0x18}
};
constexpr uint64_t uuidOffset = 0xc38;
constexpr uint8_t uuid[] = {
    0x1d, 0xa8, 0x41, 0x5c, 0xbe, 0x1a, 0x35, 0x30, 0x85, 0xeb, 0x58, 0x17, 0x00, 0x25, 0xbe, 0x1f
};
constexpr uint64_t entryOffset = 0xade1;
constexpr uint8_t entryBytes[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x81, 0xec
};

inline SettingsSample::Result inspect(Copy copy, void *context, uint64_t image) {
    SettingsSample::Result out{};
    Local local{};
    Reader r{copy, context, local};
    if (image < 4096 || (image & 4095) || image > 0x7fffffffffffULL - 0x20000) return out;
    out.stage = SettingsSample::Stage::Header;
    if (!r.equal(image, header, sizeof(header))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Commands;
    for (const auto &cmd : commands) {
        if (!r.equal(image + cmd[0], cmd + 1, 8)) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    }
    out.stage = SettingsSample::Stage::UUID;
    if (!r.equal(image + uuidOffset, uuid, sizeof(uuid))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Getter;
    if (!r.equal(image + entryOffset, entryBytes, sizeof(entryBytes))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Changed;
    if (!r.equal(image, header, sizeof(header)) ||
        !r.equal(image + uuidOffset, uuid, sizeof(uuid)) ||
        !r.equal(image + entryOffset, entryBytes, sizeof(entryBytes))) {
        out.reads = local.reads; out.bytes = local.bytes; return out;
    }
    out.reads = local.reads;
    out.bytes = local.bytes;
    out.stage = SettingsSample::Stage::Complete;
    out.state = SettingsSample::State::Cold;
    return out;
}
} // namespace NativeCoreAuthSample
