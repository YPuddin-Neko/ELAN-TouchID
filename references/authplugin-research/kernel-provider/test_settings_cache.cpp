#include "NativeSettingsCache.h"
#include <assert.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

alignas(uint64_t) static uint8_t memory[0x80000];
static constexpr uint64_t base = 0x100000000ULL;
static bool writable, failRead, failWriteAfterEffect, failRestore;
static unsigned writes;
static uint64_t &once() { return *reinterpret_cast<uint64_t *>(memory + 0x7b858); }
static uint64_t &object() { return *reinterpret_cast<uint64_t *>(memory + 0x7b860); }
static int readMemory(void *, uint64_t address, void *bytes, size_t length) {
    if (failRead) return -42;
    if (address < base || address - base > sizeof(memory) || length > sizeof(memory) - (address - base)) return -40;
    memcpy(bytes, memory + (address - base), length); return 0;
}
static int writeMemory(void *, uint64_t address, const void *bytes, size_t length) {
    assert(address == base + 0x7b858 && length == 8); writes++;
    uint64_t value = 0; memcpy(&value, bytes, sizeof(value));
    if (value == UINT64_MAX && failRestore) return -44;
    once() = value;
    return !value && failWriteAfterEffect ? -43 : 0;
}
static bool isWritable(void *, uint64_t address, size_t length) {
    return writable && address == base + 0x7b858 && length == 16;
}
static NativePlatformCacheAPI api {nullptr, readMemory, writeMemory, isWritable};
static void reset(uint64_t original = UINT64_MAX) {
    memset(memory, 0, sizeof(memory));
    uint32_t header[] = {0xfeedfacf, 0x01000007, 3, 2, 1, 24, 0, 0, 0x1b, 24};
    memcpy(memory, header, sizeof(header)); memcpy(memory + 40, NativeSettingsImageUUID, 16);
    uint8_t code[17] = {0x48, 0x83, 0x3d, 0, 0, 0, 0, 0xff, 0x75, 0x0c, 0x48, 0x8b, 0x3d};
    int32_t onceDelta = 0x7b858 - (NativeSettingsDeviceFunctionOffset + 8);
    int32_t objectDelta = 0x7b860 - (NativeSettingsDeviceFunctionOffset + 17);
    memcpy(code + 3, &onceDelta, 4); memcpy(code + 13, &objectDelta, 4);
    memcpy(memory + NativeSettingsDeviceFunctionOffset, code, sizeof(code));
    once() = original; writable = true;
    failRead = failWriteAfterEffect = failRestore = false; writes = 0;
}
#if defined(__x86_64__)
static void initializeNil(void *context) { ++*static_cast<unsigned *>(context); }
#endif
int main() {
    NativeSettingsCacheState state {};
    reset();
    assert(!nativeSettingsCachePrepare(api, base, state) && state.originalOnce == UINT64_MAX && !writes);
    assert(!nativeSettingsCacheRetry(api, state) && !once() && !object() && state.restartRequired && writes == 1);
    assert(nativeSettingsCacheRetry(api, state) == NativePlatformInvalid && writes == 1);
    state = {}; reset(0);
    assert(!nativeSettingsCachePrepare(api, base, state));
    assert(!nativeSettingsCacheRetry(api, state) && state.restartRequired && !writes);
    state = {}; reset(); failWriteAfterEffect = true;
    assert(!nativeSettingsCachePrepare(api, base, state));
    assert(nativeSettingsCacheRetry(api, state) == -43 && !state.restartRequired && once() == UINT64_MAX && writes == 2);
    state = {}; reset(); failWriteAfterEffect = failRestore = true;
    assert(!nativeSettingsCachePrepare(api, base, state));
    assert(nativeSettingsCacheRetry(api, state) == -43 && state.restartRequired && !once() && writes == 2);
    state = {}; reset();
    assert(!nativeSettingsCachePrepare(api, base, state)); object() = 0x1234;
    assert(nativeSettingsCacheRetry(api, state) == NativePlatformChanged && !writes && object() == 0x1234);
    state = {}; reset(); object() = 0x1234;
    assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformChanged && !writes && !state.once);
    state = {}; reset(42);
    assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformChanged && !writes);
    state = {}; reset(); memory[40] ^= 1;
    assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformChanged && !writes);
    const unsigned offsets[] = {0, 1, 2, 7, 8, 9, 10, 11, 12, 3, 13};
    for (unsigned offset : offsets) {
        state = {}; reset(); memory[NativeSettingsDeviceFunctionOffset + offset] ^= 1;
        assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformInvalid && !writes);
    }
    const unsigned headerWords[] = {0U, 1U, 3U, 4U, 5U, 8U, 9U};
    for (unsigned index : headerWords) {
        state = {}; reset();
        uint32_t value = 0; memcpy(memory + index * 4, &value, 4);
        assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformInvalid && !writes);
    }
    state = {}; reset(); writable = false;
    assert(nativeSettingsCachePrepare(api, base, state) == NativePlatformInvalid && !writes);
    state = {}; reset(); failRead = true;
    assert(nativeSettingsCachePrepare(api, base, state) == -42 && !writes);
    state = {}; reset();
    assert(nativeSettingsCachePrepare(api, base + 1, state) == NativePlatformInvalid);
    assert(nativeSettingsCachePrepare(api, 0x7ffffffff000ULL, state) == NativePlatformInvalid);
    // The pinned completion-token representation belongs to the Intel target.
#if defined(__x86_64__)
    state = {}; reset(0);
    unsigned calls = 0;
    auto *token = reinterpret_cast<dispatch_once_t *>(&once());
    dispatch_once_f(token, &calls, initializeNil);
    dispatch_once_f(token, &calls, initializeNil);
    assert(calls == 1 && once() == UINT64_MAX && !object());
    assert(!nativeSettingsCachePrepare(api, base, state));
    assert(!nativeSettingsCacheRetry(api, state));
    dispatch_once_f(token, &calls, initializeNil);
    dispatch_once_f(token, &calls, initializeNil);
    assert(calls == 2 && once() == UINT64_MAX && state.restartRequired);
    puts("settings cache: own Intel libdispatch retry passed");
#endif
    puts("settings cache: UUID/layout pinning, cold and cached-nil states, existing object preservation, partial writes and retirement ownership passed");
}
