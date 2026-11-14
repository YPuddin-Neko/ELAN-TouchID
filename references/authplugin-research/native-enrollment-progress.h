#pragma once
#include <stdint.h>

// BiometricKit converts 100...355 into floor((status - 100) * 100 / 255).
static inline unsigned nativeEnrollmentProgress(unsigned accepted, unsigned target) {
    if (!target) return 100;
    if (accepted >= target) return 355;
    return 100 + (unsigned)(((uint64_t)accepted * 255 + target - 1) / target);
}
