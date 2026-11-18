#include "NativeConnectionImage.h"
#include "NativeSettingsRecovery.h"
#include <assert.h>
#include <stdio.h>
#include <initializer_list>
static constexpr uint64_t base=0x100000000ULL;
static uint8_t header[128], code[0x59];
static uint64_t values[2];
static uint8_t platformCode[0x245], platformFlags[2];
alignas(uint64_t) static uint8_t settingsMemory[0x80000];
static constexpr uint64_t settingsBase=base+0x100000;
static bool execute, fail, recoveryWritable, writeFailure, restoreFailure;
static unsigned writes;
static int readMemory(void *, uint64_t a, void *b, size_t n) {
    if (fail) return -42;
    const uint8_t *source=nullptr; size_t size=0; uint64_t start=0;
    if (a>=base && a<base+sizeof(header)) {source=header;size=sizeof(header);start=base;}
    else if (a>=base+0x183f && a<base+0x183f+sizeof(code)) {source=code;size=sizeof(code);start=base+0x183f;}
    else if (a>=base+0x38b0da98 && a<base+0x38b0daa8) {source=reinterpret_cast<uint8_t *>(values);size=16;start=base+0x38b0da98;}
    else if (a>=base+0x238d1 && a<base+0x238d1+sizeof(platformCode)) {source=platformCode;size=sizeof(platformCode);start=base+0x238d1;}
    else if (a>=base+0x40000 && a<base+0x40002) {source=platformFlags;size=sizeof(platformFlags);start=base+0x40000;}
    else if (a>=settingsBase && a<settingsBase+sizeof(settingsMemory)) {source=settingsMemory;size=sizeof(settingsMemory);start=settingsBase;}
    if (!source || n>size-(a-start)) return -40;
    memcpy(b,source+(a-start),n);return 0;
}
static int writeMemory(void *, uint64_t a, const void *b, size_t n) {
    if(a==base+0x40000 && n==2) {++writes;memcpy(platformFlags,b,n);return 0;}
    if(a==settingsBase+0x7b858 && n==8) {++writes;memcpy(settingsMemory+0x7b858,b,n);return 0;}
    assert(a==base+0x38b0daa0 && n==8); ++writes;
    uint64_t value=0;memcpy(&value,b,8);
    if(value==UINT64_MAX && restoreFailure) return -44;
    values[1]=value; return !value && writeFailure ? -43 : 0;
}
static bool writable(void *,uint64_t a,size_t n) {return recoveryWritable && ((a==base+0x38b0da98 && n==16)||(a==base+0x40000 && n==2)||(a==settingsBase+0x7b858 && n==16));}
static bool executable(void *,uint64_t a,size_t n) {
    return execute && ((a==base+0x183f && n==0x59)||(a==base+0x238d1 && n==0x245));
}
static NativePlatformCacheAPI api{nullptr,readMemory,writeMemory,writable};
static void reset() {
    memset(header,0,sizeof(header));memset(code,0,sizeof(code));values[0]=0;values[1]=UINT64_MAX;
    uint32_t h[]={0xfeedfacf,0x01000007,3,6,2,96,0,0,0x1b,24};
    memcpy(header,h,sizeof(h));memcpy(header+40,NativeConnectionImageUUID,16);
    uint32_t segment[]={0x19,72};memcpy(header+56,segment,8);memcpy(header+64,"__TEXT",6);
    uint64_t size=0x40000;memcpy(header+88,&size,8);uint32_t prot=5;memcpy(header+116,&prot,4);
    uint8_t fixed[]={0x48,0x83,0x3d,0,0,0,0,0xff,0x75,0x62,0x48,0x8d,5,0,0,0,0};
    memcpy(code+0x46,fixed,sizeof(fixed));
    int32_t a=0x38b0daa0-(0x183f+0x4e),b=0x38b0da98-(0x183f+0x57);
    memcpy(code+0x49,&a,4);memcpy(code+0x53,&b,4);
    memset(platformCode,0,sizeof(platformCode));memset(platformFlags,0,sizeof(platformFlags));
    platformCode[0x43]=0x80;platformCode[0x44]=0x3d;platformCode[0x9d]=0xc6;platformCode[0x9e]=0x05;platformCode[0xa3]=1;platformCode[0x23f]=0x8a;platformCode[0x240]=0x1d;
    int32_t checkedRead=0x40000-(0x238d1+0x4a),checkedWrite=0x40000-(0x238d1+0xa4),resultRead=0x40001-(0x238d1+0x245);
    memcpy(platformCode+0x45,&checkedRead,4);memcpy(platformCode+0x9f,&checkedWrite,4);memcpy(platformCode+0x241,&resultRead,4);
    memset(settingsMemory,0,sizeof(settingsMemory));
    uint32_t sh[]={0xfeedfacf,0x01000007,3,2,1,24,0,0,0x1b,24};memcpy(settingsMemory,sh,sizeof(sh));memcpy(settingsMemory+40,NativeSettingsImageUUID,16);
    uint8_t sc[]={0x48,0x83,0x3d,0,0,0,0,0xff,0x75,0x0c,0x48,0x8b,0x3d,0,0,0,0};
    int32_t so=0x7b858-(NativeSettingsDeviceFunctionOffset+8),sv=0x7b860-(NativeSettingsDeviceFunctionOffset+17);
    memcpy(sc+3,&so,4);memcpy(sc+13,&sv,4);memcpy(settingsMemory+NativeSettingsDeviceFunctionOffset,sc,sizeof(sc));
    uint64_t completed=UINT64_MAX;memcpy(settingsMemory+0x7b858,&completed,8);
    execute=true;fail=recoveryWritable=writeFailure=restoreFailure=false;writes=0;
}
int main() {
    NativeConnectionImageReport r{};uint64_t getter=0;
    auto inspect=[&](){return nativeConnectionImageInspect(api,base+0x238d1,executable,r,getter);};
    reset();assert(!inspect() && r.imageMatched && getter==base+0x183f && r.observation==NativeConnectionObservation::CompletedEmpty && !writes);
    values[1]=0;assert(!inspect() && r.observation==NativeConnectionObservation::NotStarted);
    values[1]=42;assert(!inspect() && r.observation==NativeConnectionObservation::Initializing);
    values[0]=1;assert(!inspect() && r.observation==NativeConnectionObservation::LiveObject && !writes);
    for(unsigned i:{0U,4U,12U,16U,20U,32U,36U,56U,60U,64U,96U}) {
        reset();header[i]^=0x80;assert(inspect()!=0 && !r.imageMatched && !getter && !writes);
    }
    reset();memset(header+88,0,8);assert(inspect()==NativePlatformInvalid && !writes);
    reset();header[116]|=2;assert(inspect()==NativePlatformInvalid && !writes);
    reset();header[40]^=1;assert(inspect()==NativePlatformChanged && !getter && !writes);
    for(unsigned i:{0x46U,0x47U,0x48U,0x49U,0x4dU,0x4eU,0x4fU,0x50U,0x51U,0x52U,0x53U}) {
        reset();code[i]^=1;assert(inspect()==NativePlatformInvalid && !getter && !writes);
    }
    reset();execute=false;assert(inspect()==NativePlatformInvalid && !writes);
    reset();fail=true;assert(inspect()==-42 && !writes);
    reset();assert(nativeConnectionImageInspect(api,0,executable,r,getter)==NativePlatformInvalid);
    assert(nativeConnectionImageInspect(api,base+0x238d2,executable,r,getter)==NativePlatformInvalid);
    assert(nativeConnectionImageInspect(api,base+0x238d1,nullptr,r,getter)==NativePlatformInvalid);
    reset();uint32_t flags=0x80000000;uint64_t offset=0x0a5b0000;
    memcpy(header+24,&flags,4);memcpy(header+96,&offset,8);
    assert(!inspect() && r.imageMatched && r.stage==NativeConnectionImageStage::Complete && !writes);
    offset++;memcpy(header+96,&offset,8);
    assert(inspect()==NativePlatformInvalid && r.stage==NativeConnectionImageStage::TextSegment && !writes);
    offset=0;memcpy(header+96,&offset,8);
    assert(inspect()==NativePlatformInvalid && r.stage==NativeConnectionImageStage::TextSegment && !writes);
    // Full isolated read-only identification -> preparation -> retry/rollback pipeline.
    reset();recoveryWritable=true;assert(!inspect() && !writes);
    NativeConnectionCacheState recovery {};
    assert(!nativeConnectionCachePrepare(api,getter,recovery));
    assert(!nativeConnectionCacheRetry(api,recovery) && !values[1] && recovery.restartRequired);
    reset();recoveryWritable=true;writeFailure=true;assert(!inspect());recovery={};
    assert(!nativeConnectionCachePrepare(api,getter,recovery));
    assert(nativeConnectionCacheRetry(api,recovery)==-43 && values[1]==UINT64_MAX && !recovery.restartRequired && writes==2);
    reset();recoveryWritable=true;writeFailure=restoreFailure=true;assert(!inspect());recovery={};
    assert(!nativeConnectionCachePrepare(api,getter,recovery));
    assert(nativeConnectionCacheRetry(api,recovery)==-43 && !values[1] && recovery.restartRequired && writes==2);
    reset();recoveryWritable=true;assert(!inspect());values[0]=1;recovery={};
    assert(nativeConnectionCachePrepare(api,getter,recovery)==NativePlatformChanged && !writes);
    // Execute the actual two-cache/platform transaction on one isolated mapped fixture.
    reset();recoveryWritable=true;NativeSettingsRecoveryState transaction{};
    assert(!nativeSettingsRecoveryEnable(api,base+0x238d1,settingsBase,executable,transaction));
    assert(!values[1] && platformFlags[0]==1 && platformFlags[1]==1 && !settingsMemory[0x7b858]);
    assert(nativeSettingsRecoveryRetirement(transaction));
    unsigned afterEnable=writes;
    assert(nativeSettingsRecoveryCleanup(transaction,true)==NativeSettingsRecoveryRestartRequired);
    assert(platformFlags[0]==1 && platformFlags[1]==1 && writes==afterEnable);
    assert(transaction.platform.restorePending && nativeSettingsRecoveryRetirement(transaction));
    assert(!nativeSettingsRecoveryCleanup(transaction,false));
    assert(writes==afterEnable && !nativeSettingsRecoveryPending(transaction));
    reset();recoveryWritable=true;writeFailure=true;transaction={};
    assert(nativeSettingsRecoveryEnable(api,base+0x238d1,settingsBase,executable,transaction)==-43);
    assert(values[1]==UINT64_MAX && !platformFlags[0] && !nativeSettingsRecoveryPending(transaction));
    reset();recoveryWritable=true;writeFailure=restoreFailure=true;transaction={};
    assert(nativeSettingsRecoveryEnable(api,base+0x238d1,settingsBase,executable,transaction)==-43);
    assert(!values[1] && !platformFlags[0] && nativeSettingsRecoveryRetirement(transaction));
    reset();recoveryWritable=true;values[0]=1;transaction={};
    assert(nativeSettingsRecoveryEnable(api,base+0x238d1,settingsBase,executable,transaction)==NativePlatformChanged && !writes);
    reset();recoveryWritable=true;values[1]=42;transaction={};
    assert(nativeSettingsRecoveryEnable(api,base+0x238d1,settingsBase,executable,transaction)==NativePlatformChanged && !writes);
    puts("connection image: UUID/header/layout/permissions pinned; four read-only states; rejection paths passed");
}
