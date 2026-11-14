#include "NativeLACRetry.h"
#include <assert.h>
#include <stdio.h>
static uint8_t memory[0x1000];
static constexpr uint64_t base = 0x100000000ULL;
static bool writeAllowed, failRead, failWriteAfterEffect, failRollback, partialWrite;
static unsigned writes;
static int readMemory(void *, uint64_t address, void *bytes, size_t length) {
    if (failRead) return -42;
    if (address < base || address - base > sizeof(memory) || length > sizeof(memory) - (address - base)) return -40;
    memcpy(bytes, memory + (address - base), length); return 0;
}
static int writeMemory(void *, uint64_t address, const void *bytes, size_t length) {
    assert(address == base + 0x648 && length == 16);
    writes++;
    if (writes == 2 && failRollback) return -44;
    memcpy(memory + 0x648, bytes, writes == 1 && partialWrite ? 8 : length);
    return writes == 1 && failWriteAfterEffect ? -43 : 0;
}
static bool writable(void *, uint64_t address, size_t length) {
    return writeAllowed && address == base + 0x648 && length == 16;
}
static NativePlatformCacheAPI api {nullptr, readMemory, writeMemory, writable};
static NativeLACRetryRequest request {base, base + 0x100, base + 0x200, base + 0x900};
static void put64(unsigned offset, uint64_t value) { memcpy(memory + offset, &value, 8); }
static uint64_t get64(unsigned offset) { uint64_t value; memcpy(&value, memory + offset, 8); return value; }
static void reset() {
    memset(memory, 0, sizeof(memory));
    const uint8_t instance[] = {0x48,0x83,0x3d,0,0,0,0,0xff,0x75,0x0c,0x48,0x8b,0x3d};
    const uint8_t fault[] = {0x55,0x48,0x89,0xe5,0x48,0x8b,0x47,0x48,0x5d,0xc3};
    memcpy(memory, instance, sizeof(instance));
    memcpy(memory + 0x100, fault, 10); memcpy(memory + 0x200, fault, 10); memory[0x207] = 0x50;
    int32_t once = 0x400 - 8, object = 0x408 - 17;
    memcpy(memory + 3, &once, 4); memcpy(memory + 13, &object, 4);
    put64(0x400, UINT64_MAX); put64(0x408, base + 0x600);
    put64(0x600, base + 0x900); put64(0x650, base + 0xa00); put64(0x658, 1);
    writeAllowed = true; failRead = failWriteAfterEffect = failRollback = partialWrite = false; writes = 0;
}
int main() {
    NativeLACRetryState state {};
    reset(); assert(!nativeLACRetryPrepare(api, request, state));
    assert(!nativeLACRetryTransfer(api, state) && state.restartRequired);
    assert(get64(0x648) == base + 0xa00 && !get64(0x650));
    assert(nativeLACRetryTransfer(api, state) == NativePlatformInvalid && writes == 1);
    const unsigned offsets[] = {0,1,2,7,8,9,10,11,12,0x100,0x107,0x207,0x400,0x408,0x601,0x630,0x648,0x650,0x658};
    for (unsigned offset : offsets) {
        reset(); state = {}; memory[offset] ^= 1;
        assert(nativeLACRetryPrepare(api, request, state) && !writes);
    }
    reset(); state = {}; writeAllowed = false;
    assert(nativeLACRetryPrepare(api, request, state) && !writes);
    reset(); state = {}; failRead = true;
    assert(nativeLACRetryPrepare(api, request, state) == -42 && !writes);
    reset(); state = {}; assert(!nativeLACRetryPrepare(api, request, state));
    memory[0x650] ^= 8;
    assert(nativeLACRetryTransfer(api, state) == NativePlatformChanged && !writes);
    reset(); state = {}; assert(!nativeLACRetryPrepare(api, request, state)); failWriteAfterEffect = true;
    assert(nativeLACRetryTransfer(api, state) == -43 && !state.restartRequired);
    assert(!get64(0x648) && get64(0x650) == base + 0xa00);
    reset(); state = {}; assert(!nativeLACRetryPrepare(api, request, state)); partialWrite = true;
    assert(nativeLACRetryTransfer(api, state) == NativePlatformChanged && !state.restartRequired);
    assert(!get64(0x648) && get64(0x650) == base + 0xa00);
    reset(); state = {}; assert(!nativeLACRetryPrepare(api, request, state));
    failWriteAfterEffect = failRollback = true;
    assert(nativeLACRetryTransfer(api, state) == -43 && state.restartRequired);
    puts("LAC retry: singleton/getter/instance gates, ownership transfer, partial write and failed rollback passed");
}
