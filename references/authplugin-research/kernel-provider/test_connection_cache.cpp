#include "NativeConnectionCache.h"
#include <assert.h>
#include <stdio.h>
#include <initializer_list>
#include <dispatch/dispatch.h>
alignas(uint64_t) static uint8_t memory[0x200];
static constexpr uint64_t base = 0x100000000ULL;
static bool permitted, readFailure, writeFailure, restoreFailure;
static unsigned writes;
static uint64_t &object() { return *reinterpret_cast<uint64_t *>(memory + 0x100); }
static uint64_t &once() { return *reinterpret_cast<uint64_t *>(memory + 0x108); }
static int readMemory(void *, uint64_t a, void *b, size_t n) {
    if (readFailure) return -42;
    if (a < base || a-base > sizeof(memory) || n > sizeof(memory)-(a-base)) return -40;
    memcpy(b, memory+(a-base), n); return 0;
}
static int writeMemory(void *, uint64_t a, const void *b, size_t n) {
    assert(a == base+0x108 && n == 8); ++writes;
    uint64_t v; memcpy(&v,b,8);
    if (v == UINT64_MAX && restoreFailure) return -44;
    once() = v; return !v && writeFailure ? -43 : 0;
}
static bool writable(void *, uint64_t a, size_t n) { return permitted && a == base+0x100 && n == 16; }
static NativePlatformCacheAPI api {nullptr,readMemory,writeMemory,writable};
static void reset(uint64_t token=UINT64_MAX) {
    memset(memory,0,sizeof(memory));
    uint8_t fixed[] = {0x48,0x83,0x3d,0,0,0,0,0xff,0x75,0x62,0x48,0x8d,0x05,0,0,0,0};
    memcpy(memory+0x46,fixed,sizeof(fixed));
    int32_t a=0x108-0x4e, b=0x100-0x57;
    memcpy(memory+0x49,&a,4); memcpy(memory+0x53,&b,4);
    once()=token; permitted=true; readFailure=writeFailure=restoreFailure=false; writes=0;
}
#if defined(__x86_64__)
static bool platform;
static void initialize(void *context) { ++*static_cast<unsigned *>(context); if (platform) object()=1; }
#endif
int main() {
    NativeConnectionCacheState s{}; reset();
    assert(!nativeConnectionCachePrepare(api,base,s) && !writes);
    assert(!nativeConnectionCacheRetry(api,s) && !once() && s.restartRequired && writes==1);
    assert(nativeConnectionCacheRetry(api,s)==NativePlatformInvalid && writes==1);
    s={};reset(0); assert(!nativeConnectionCachePrepare(api,base,s));
    assert(!nativeConnectionCacheRetry(api,s) && !writes && s.restartRequired);
    s={};reset();object()=1;assert(nativeConnectionCachePrepare(api,base,s)==NativePlatformChanged && !writes);
    s={};reset(42);assert(nativeConnectionCachePrepare(api,base,s)==NativePlatformChanged && !writes);
    s={};reset();assert(!nativeConnectionCachePrepare(api,base,s));object()=1;
    assert(nativeConnectionCacheRetry(api,s)==NativePlatformChanged && !writes && !s.restartRequired);
    s={};reset();assert(!nativeConnectionCachePrepare(api,base,s));once()=42;
    assert(nativeConnectionCacheRetry(api,s)==NativePlatformChanged && !writes);
    for (unsigned i : {0x46U,0x47U,0x48U,0x4dU,0x4eU,0x4fU,0x50U,0x51U,0x52U,0x49U,0x53U}) {
        s={};reset();memory[i]^=1;assert(nativeConnectionCachePrepare(api,base,s)==NativePlatformInvalid && !writes);
    }
    s={};reset();permitted=false;assert(nativeConnectionCachePrepare(api,base,s)==NativePlatformInvalid && !writes);
    s={};reset();readFailure=true;assert(nativeConnectionCachePrepare(api,base,s)==-42 && !writes);
    s={};reset();assert(nativeConnectionCachePrepare(api,0,s)==NativePlatformInvalid);
    assert(nativeConnectionCachePrepare(api,0x7fffffffffffULL,s)==NativePlatformInvalid);
    s={};reset();assert(!nativeConnectionCachePrepare(api,base,s));writeFailure=true;
    assert(nativeConnectionCacheRetry(api,s)==-43 && once()==UINT64_MAX && !s.restartRequired && writes==2);
    s={};reset();assert(!nativeConnectionCachePrepare(api,base,s));writeFailure=restoreFailure=true;
    assert(nativeConnectionCacheRetry(api,s)==-43 && !once() && s.restartRequired && writes==2);
#if defined(__x86_64__)
    s={};reset(0);unsigned calls=0;platform=false;
    auto *token=reinterpret_cast<dispatch_once_t *>(&once());
    dispatch_once_f(token,&calls,initialize); platform=true;
    dispatch_once_f(token,&calls,initialize);
    assert(calls==1 && !object() && once()==UINT64_MAX);
    assert(!nativeConnectionCachePrepare(api,base,s)); assert(!nativeConnectionCacheRetry(api,s));
    dispatch_once_f(token,&calls,initialize); dispatch_once_f(token,&calls,initialize);
    assert(calls==2 && object()==1 && s.restartRequired);
    puts("own Intel libdispatch late-enable recovery passed");
#endif
    puts("connection cache: layout, cold/nil/live/in-flight states, stale reads, rollback and retirement passed");
}
