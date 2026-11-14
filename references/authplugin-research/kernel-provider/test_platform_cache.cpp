#include "NativePlatformCache.h"
#include <assert.h>
#include <stdio.h>

static uint8_t memory[0x1000];
static constexpr uint64_t base = 0x100000000ULL;
static bool writable, failRead, failWriteAfterEffect, failRestore, corruptWrite;
static unsigned writes;
static int readMemory(void *, uint64_t address, void *bytes, size_t length) {
    if (failRead) return -42;
    if (address < base || address - base > sizeof(memory) || length > sizeof(memory) - (address - base)) return -40;
    memcpy(bytes, memory + (address - base), length);
    return 0;
}
static int writeMemory(void *, uint64_t address, const void *bytes, size_t length) {
    assert(address == base + 0x800 && length == 2);
    writes++;
    bool restore = static_cast<const uint8_t *>(bytes)[1] == 0;
    if (restore && failRestore) return -44;
    memcpy(memory + 0x800, bytes, length);
    if (!restore && corruptWrite) memory[0x801] = 0;
    return !restore && failWriteAfterEffect ? -43 : 0;
}
static bool isWritable(void *, uint64_t address, size_t length) {
    return writable && address == base + 0x800 && length == 2;
}
static NativePlatformCacheAPI api {nullptr, readMemory, writeMemory, isWritable};
static void reset() {
    memset(memory, 0, sizeof(memory));
    memory[0x43] = 0x80; memory[0x44] = 0x3d;
    memory[0x9d] = 0xc6; memory[0x9e] = 0x05; memory[0xa3] = 1;
    memory[0x23f] = 0x8a; memory[0x240] = 0x1d;
    int32_t checked = 0x800 - 0x4a, written = 0x800 - 0xa4, result = 0x801 - 0x245;
    memcpy(memory + 0x45, &checked, 4); memcpy(memory + 0x9f, &written, 4);
    memcpy(memory + 0x241, &result, 4);
    memory[0x800] = 1;
    writable = true;
    failRead = failWriteAfterEffect = failRestore = corruptWrite = false;
    writes = 0;
}
int main() {
    NativePlatformCacheState state {};
    reset();
    assert(!nativePlatformEnable(api, base, state));
    assert(state.restorePending && memory[0x801] == 1);
    assert(nativePlatformEnable(api, base, state) == NativePlatformInvalid && writes == 1);
    assert(!nativePlatformRestore(api, state) && !state.restorePending && memory[0x801] == 0);
    assert(!nativePlatformRestore(api, state) && writes == 2);
    reset(); memory[0x800] = 0;
    assert(nativePlatformEnable(api, base, state) == NativePlatformChanged && !writes);
    assert(!nativePlatformEnable(api, base, state, true) && state.restorePending && memory[0x800] == 1 && memory[0x801] == 1);
    assert(!nativePlatformRestore(api, state) && !memory[0x800] && !memory[0x801] && !state.restorePending);
    reset(); failWriteAfterEffect = true;
    assert(nativePlatformEnable(api, base, state) == -43);
    assert(!state.restorePending && !memory[0x801] && writes == 2);
    reset(); failWriteAfterEffect = failRestore = true;
    assert(nativePlatformEnable(api, base, state) == -43 && state.restorePending && memory[0x801] == 1);
    assert(nativePlatformRestore(api, state) == -44 && state.restorePending);
    failRestore = false;
    assert(!nativePlatformRestore(api, state) && !state.restorePending && !memory[0x801]);
    reset(); corruptWrite = true;
    assert(nativePlatformEnable(api, base, state) == NativePlatformChanged && !state.restorePending);
    reset(); failRead = true;
    assert(nativePlatformEnable(api, base, state) == -42 && !writes);
    reset(); writable = false;
    assert(nativePlatformEnable(api, base, state) == NativePlatformInvalid && !writes);
    const unsigned offsets[] = {0x43U, 0x44U, 0x49U, 0x9dU, 0x9eU, 0xa3U, 0x23fU, 0x240U, 0x45U, 0x9fU, 0x241U};
    for (unsigned offset : offsets) {
        reset(); memory[offset] ^= 1;
        assert(nativePlatformEnable(api, base, state) == NativePlatformInvalid && !writes);
    }
    for (unsigned value = 1; value < 256; value++) {
        reset(); memory[0x801] = value;
        assert(nativePlatformEnable(api, base, state) == NativePlatformChanged && !writes);
    }
    NativePlatformCacheLocation location {};
    assert(!nativePlatformCacheLocation(nullptr, 0x245, base, location));
    assert(!nativePlatformCacheLocation(memory, 0x244, base, location));
    assert(!nativePlatformCacheLocation(memory, sizeof(memory), UINT64_MAX, location));
    reset();
    int32_t negative = INT32_MIN;
    memcpy(memory + 0x45, &negative, 4);
    assert(!nativePlatformCacheLocation(memory, sizeof(memory), 0x1000, location));
    puts("platform cache: layout, process range, failed writes, rollback retry and ownership tests passed");
}
