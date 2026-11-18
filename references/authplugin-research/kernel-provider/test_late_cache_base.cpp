#include "NativeLateCacheBase.h"
#include <cassert>
#include <cstdio>
#include <initializer_list>

int main() {
    using namespace NativeLateCacheBase;
    CallerEvidence::Result caller{};
    caller.stage = CallerEvidence::Stage::Matched;
    caller.profile = CallerEvidence::Profile::Cached;
    caller.lateBoundary = true;
    for (uint64_t slide : {uint64_t(0), uint64_t(4096), maximumSlide}) {
        caller.imageBase = cacheStart + slide + dyldOffset;
        uint64_t base = UINT64_MAX;
        assert(derive(caller, base) && base == cacheStart + slide);
    }
    caller.imageBase = cacheStart + dyldOffset;
    {
        auto early = caller; early.lateBoundary = false;
        uint64_t base = UINT64_MAX;
        assert(!derive(early, base) && base == 0);
    }
    for (auto stage : {CallerEvidence::Stage::Registers, CallerEvidence::Stage::Header,
                       CallerEvidence::Stage::UUID, CallerEvidence::Stage::Code,
                       CallerEvidence::Stage::Stack}) {
        auto rejected = caller; rejected.stage = stage;
        uint64_t base = UINT64_MAX;
        assert(!derive(rejected, base) && base == 0);
    }
    for (auto profile : {CallerEvidence::Profile::Unknown, CallerEvidence::Profile::Disk}) {
        auto rejected = caller; rejected.profile = profile;
        uint64_t base = UINT64_MAX;
        assert(!derive(rejected, base) && base == 0);
    }
    for (uint64_t image : {uint64_t(0), dyldOffset - 4096, cacheStart + dyldOffset - 4096,
                           cacheStart + dyldOffset - 1, cacheStart + dyldOffset + 1,
                           cacheStart + dyldOffset + maximumSlide + 4096,
                           uint64_t(0x7ffffffff000ULL), UINT64_MAX - 4095, UINT64_MAX}) {
        auto rejected = caller; rejected.imageBase = image;
        uint64_t base = UINT64_MAX;
        assert(!derive(rejected, base) && base == 0);
    }
    puts("Late cached-dyld base derivation boundaries passed");
}
