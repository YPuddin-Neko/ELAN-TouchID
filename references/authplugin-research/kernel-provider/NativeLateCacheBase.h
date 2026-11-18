#pragma once
#include "../agent-integration-candidate/early-boundary-observation/CallerEvidence.h"

namespace NativeLateCacheBase {
constexpr uint64_t cacheStart = 0x7ff800000000ULL;
constexpr uint64_t maximumSlide = 0x1ae68000ULL;
// cached-dyld-evidence.json records dyld_vm 0x7ff801b28000 for cache
// UUID 42EC2890-BC40-317E-BB27-45142BFF7F26. This is a VM delta, not a file offset.
constexpr uint64_t dyldOffset = 0x1b28000ULL;

// This only derives a candidate. The caller must validate the complete cache
// header/layout, BiometricKit pins and cold state before admitting any write.
inline bool derive(const CallerEvidence::Result &caller, uint64_t &base) {
    base = 0;
    if (caller.stage != CallerEvidence::Stage::Matched ||
        caller.profile != CallerEvidence::Profile::Cached || !caller.lateBoundary ||
        caller.imageBase < cacheStart + dyldOffset || (caller.imageBase & 4095))
        return false;
    const uint64_t candidate = caller.imageBase - dyldOffset;
    if (candidate - cacheStart > maximumSlide) return false;
    base = candidate;
    return true;
}
}
