#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

using NativeMapProtectionCodeReader = size_t (*)(void *, uintptr_t, void *, size_t);
static constexpr size_t NativeMapProtectionUseraccSize = 53;

static inline bool nativeMapProtectionRelative(uintptr_t next, const uint8_t *displacement,
                                              uintptr_t &result) {
    uint32_t raw = 0;
    for (unsigned i = 0; i < 4; ++i) raw |= static_cast<uint32_t>(displacement[i]) << (8 * i);
    if (raw & 0x80000000U) {
        const uint32_t magnitude = ~raw + 1U;
        if (next < magnitude) return false;
        result = next - magnitude;
    } else {
        if (next > UINTPTR_MAX - raw) return false;
        result = next + raw;
    }
    return result != 0;
}

// https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/vm/vm_unix.c#L577-L593
// XNU useracc supplies a kernel-owned vm_sanitize_caller_t
// as vm_map_check_protection's fifth argument. Its pointer symbol is absent
// on 24H32 xnu-11417.140.69.712.69~1/RELEASE_X86_64; use the pinned LEA target.
// Full 53-byte _useracc SHA256: 5c97036f3e3464d2b316a1a865bccf7260ac9bd1b3a60f852897f54ab45093b3.
static inline uintptr_t nativeMapProtectionCaller(uintptr_t useracc, uintptr_t protection,
                                                  NativeMapProtectionCodeReader read, void *context) {
    static constexpr uint8_t expected[NativeMapProtectionUseraccSize] = {
        0x55,0x48,0x89,0xe5,0x48,0x89,0xf8,0x65,0x48,0x8b,0x0c,0x25,0x10,0x00,0x00,0x00,
        0x48,0x8b,0xb9,0x28,0x06,0x00,0x00,0x31,0xc9,0x83,0xfa,0x01,0x0f,0x95,0xc1,0xff,
        0xc1,0x48,0x8d,0x14,0x06,0x4c,0x8d,0x05,0x3c,0xcd,0x5d,0x00,0x48,0x89,0xc6,0x5d,
        0xe9,0x5b,0x81,0xaf,0xff
    };
    if (!useracc || !protection || !read || useracc > UINTPTR_MAX - sizeof(expected)) return 0;
    uint8_t code[sizeof(expected)] = {};
    if (read(context, useracc, code, sizeof(code)) != sizeof(code)) return 0;
    // 24H32 BootKernelExtensions.kc relocates the sanitizer constant into the
    // collection's shared data. Both complete 53-byte bodies are pinned; this
    // does not mask or accept an arbitrary LEA displacement.
    uint8_t collection[sizeof(expected)]; memcpy(collection, expected, sizeof(expected));
    collection[40]=0x3c; collection[41]=0xdd; collection[42]=0x86; collection[43]=0xff;
    if (memcmp(code, expected, sizeof(code)) && memcmp(code, collection, sizeof(code))) return 0;
    uintptr_t caller = 0, tailTarget = 0;
    if (!nativeMapProtectionRelative(useracc + 0x2c, code + 0x28, caller) ||
        !nativeMapProtectionRelative(useracc + 0x35, code + 0x31, tailTarget) ||
        tailTarget != protection) return 0;
    return caller;
}
