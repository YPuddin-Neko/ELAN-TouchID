#include "NativeCoreAuthSample.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {
constexpr uint64_t targetImage = 0x104000000ULL;
struct SampleImage {
    std::vector<uint8_t> bytes;
    SampleImage() : bytes(0x10000, 0) {
        memcpy(bytes.data(), NativeCoreAuthSample::header, sizeof(NativeCoreAuthSample::header));
        for (const auto &cmd : NativeCoreAuthSample::commands)
            memcpy(bytes.data() + cmd[0], cmd + 1, 8);
        memcpy(bytes.data() + NativeCoreAuthSample::uuidOffset, NativeCoreAuthSample::uuid, sizeof(NativeCoreAuthSample::uuid));
        memcpy(bytes.data() + NativeCoreAuthSample::entryOffset, NativeCoreAuthSample::entryBytes, sizeof(NativeCoreAuthSample::entryBytes));
    }
    static int copy(void *ctx, uint64_t addr, void *out, size_t n) {
        auto &m = *static_cast<SampleImage *>(ctx);
        if (addr < targetImage || n > m.bytes.size() || addr - targetImage > m.bytes.size() - n) return 14;
        memcpy(out, m.bytes.data() + (addr - targetImage), n);
        return 0;
    }
};
} // namespace

int main() {
    SampleImage image;
    auto ok = NativeCoreAuthSample::inspect(SampleImage::copy, &image, targetImage);
    assert(ok.stage == SettingsSample::Stage::Complete && ok.state == SettingsSample::State::Cold);

    assert(NativeCoreAuthSample::inspect(SampleImage::copy, &image, targetImage + 1).stage == SettingsSample::Stage::Argument);

    SampleImage badUUID;
    badUUID.bytes[NativeCoreAuthSample::uuidOffset] ^= 1;
    assert(NativeCoreAuthSample::inspect(SampleImage::copy, &badUUID, targetImage).stage == SettingsSample::Stage::UUID);

    SampleImage badEntry;
    badEntry.bytes[NativeCoreAuthSample::entryOffset] ^= 1;
    assert(NativeCoreAuthSample::inspect(SampleImage::copy, &badEntry, targetImage).stage == SettingsSample::Stage::Getter);

    puts("CoreAuth image sample passed");
}
