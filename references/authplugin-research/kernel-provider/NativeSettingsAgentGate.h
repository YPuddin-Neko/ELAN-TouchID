#pragma once
#include "NativeSettingsRoute.h"
#include "../agent-integration-candidate/settings-fresh-observation/SettingsSample.h"

namespace NativeSettingsAgentSample {
using Copy = int(*)(void*, uint64_t, void*, size_t);
enum class Stage : uint8_t { Argument, Header, Commands, UUID, Code, Changed, Complete };
struct Result {
    Stage stage = Stage::Argument;
    unsigned reads = 0, bytes = 0;
};
struct Reader {
    Copy copy;
    void *context;
    Result &result;
    bool read(uint64_t address, void *out, size_t size) {
        if (!copy || !out || !size || size > 32 || address < 4096 || address > 0x7fffffffffffULL ||
            size - 1 > 0x7fffffffffffULL - address || result.reads >= 99 || result.bytes + size > 890)
            return false;
        ++result.reads;
        result.bytes += static_cast<unsigned>(size);
        return copy(context, address, out, size) == 0;
    }
    bool equal(uint64_t address, const void *pin, size_t size) {
        uint8_t bytes[32];
        return read(address, bytes, size) && !memcmp(bytes, pin, size);
    }
};

constexpr uint8_t header[] = {
    0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x3d, 0x00, 0x00, 0x00, 0xf8, 0x1a, 0x00, 0x00, 0x85, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
};
constexpr uint32_t commands[][3] = {
    {0x20, 0x19, 0x48}, {0x68, 0x19, 0x6d8}, {0x740, 0x19, 0x2c8}, {0xa08, 0x19, 0x228},
    {0xc30, 0x19, 0x48}, {0xc78, 0x80000034, 0x10}, {0xc88, 0x80000033, 0x10}, {0xc98, 0x2, 0x18},
    {0xcb0, 0xb, 0x50}, {0xd00, 0xe, 0x20}, {0xd20, 0x1b, 0x18}, {0xd38, 0x32, 0x20},
    {0xd58, 0x2a, 0x10}, {0xd68, 0x80000028, 0x18}
};
constexpr uint64_t uuidOffset = 0xd28;
constexpr uint8_t uuid[] = {
    0x67, 0xb7, 0x6a, 0x48, 0xd3, 0x0e, 0x3d, 0xaa, 0x9c, 0x63, 0xc6, 0xbc, 0x27, 0xbb, 0xd1, 0xda
};
constexpr uint64_t codeOffset = 0x1bd0;
constexpr uint8_t codeOriginal[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48
};
constexpr uint8_t codePatched[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48
};

inline SettingsSample::Result inspect(Copy copy, void *context, uint64_t image) {
    SettingsSample::Result out{};
    Result local{};
    Reader r{copy, context, local};
    if (image < 4096 || (image & 4095) || image > 0x7fffffffffffULL - 0x36000) return out;
    out.stage = SettingsSample::Stage::Header;
    if (!r.equal(image, header, sizeof(header))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Commands;
    for (const auto &cmd : commands) {
        if (!r.equal(image + cmd[0], cmd + 1, 8)) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    }
    out.stage = SettingsSample::Stage::UUID;
    if (!r.equal(image + uuidOffset, uuid, sizeof(uuid))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Getter;
    if (!r.equal(image + codeOffset, codeOriginal, sizeof(codeOriginal))) { out.reads = local.reads; out.bytes = local.bytes; return out; }
    out.stage = SettingsSample::Stage::Changed;
    if (!r.equal(image, header, sizeof(header)) ||
        !r.equal(image + uuidOffset, uuid, sizeof(uuid)) ||
        !r.equal(image + codeOffset, codeOriginal, sizeof(codeOriginal))) {
        out.reads = local.reads; out.bytes = local.bytes; return out;
    }
    out.reads = local.reads;
    out.bytes = local.bytes;
    out.stage = SettingsSample::Stage::Complete;
    out.state = SettingsSample::State::Cold;
    return out;
}
} // namespace NativeSettingsAgentSample

namespace NativeSettingsAgentGate {
enum class Stage : uint8_t { None, Arguments, ReadCode, CodeRegion, CopyPage, Write, SealCode, Route, Restore, Complete };

template<class Memory>
NativeSettingsRoute::Result apply(Memory &memory, uint64_t image, uint64_t cache, Stage *diagnostic = nullptr) {
    auto at = [&](Stage s) { if (diagnostic) *diagnostic = s; };
    at(Stage::Arguments);
    using Result = NativeSettingsRoute::Result;
    constexpr uint64_t limit = 0x00007fffffffffffULL;
    constexpr uint64_t target = NativeSettingsAgentSample::codeOffset;
    if (image < 4096 || (image & 4095) || image > limit - 0x36000 || !memory.permitted())
        return Result::Skipped;
    auto reader = memory.reader();
    at(Stage::ReadCode);
    if (!reader.equal(image + target, NativeSettingsAgentSample::codeOriginal, sizeof(NativeSettingsAgentSample::codeOriginal)))
        return Result::Skipped;
    const uint64_t page = (image + target) & ~uint64_t{4095};
    at(Stage::CodeRegion);
    if (!memory.executablePage(page)) return Result::Skipped;
    at(Stage::CopyPage);
    if (!memory.makeCopyWritable(page)) {
        const bool restored = memory.executablePage(page) || memory.protectExecutablePage(page);
        return restored ? Result::Skipped : Result::Incomplete;
    }
    uint64_t originalWord = 0, patchedWord = 0, actualWord = 0;
    memcpy(&originalWord, NativeSettingsAgentSample::codeOriginal, sizeof(originalWord));
    memcpy(&patchedWord, NativeSettingsAgentSample::codePatched, sizeof(patchedWord));
    at(Stage::Write);
    const bool written = memory.permitted() &&
        reader.read(image + target, &actualWord, sizeof(actualWord)) && actualWord == originalWord &&
        memory.storePointer(image + target, patchedWord);
    at(Stage::SealCode);
    const bool sealed = memory.protectExecutablePage(page) && memory.executablePage(page);
    if (written && sealed && reader.equal(image + target, NativeSettingsAgentSample::codePatched, sizeof(NativeSettingsAgentSample::codePatched)) &&
        memory.permitted()) {
        at(Stage::Route);
        auto routed = NativeSettingsRoute::apply(memory, cache);
        if (routed == Result::Routed) {
            at(Stage::Complete);
            return routed;
        }
    }
    at(Stage::Restore);
    if (!reader.read(image + target, &actualWord, sizeof(actualWord))) return Result::Incomplete;
    if (actualWord != originalWord) {
        if (!memory.makeCopyWritable(page)) return Result::Incomplete;
        memory.storePointer(image + target, originalWord);
    }
    const bool rxAgain = memory.protectExecutablePage(page) && memory.executablePage(page);
    if (!rxAgain || !reader.equal(image + target, NativeSettingsAgentSample::codeOriginal, sizeof(NativeSettingsAgentSample::codeOriginal)))
        return Result::Incomplete;
    return written ? Result::Restored : Result::Skipped;
}
} // namespace NativeSettingsAgentGate
