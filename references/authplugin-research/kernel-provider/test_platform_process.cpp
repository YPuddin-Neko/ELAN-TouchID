#include "NativePlatformProcess.h"
#include <assert.h>
#include <stdio.h>
#include <initializer_list>

struct NativeTestMap { unsigned references = 0; } originalMap, replacementMap;
struct NativeTestProcess {
    bool alive = true, suspended = true, taskAvailable = true, mapAvailable = true;
    unsigned references = 0, credentials = 0;
    const char *name = "Touch ID & Password";
    NativeTestMap *map = &originalMap;
} process;
static constexpr int targetPID = 42;
static constexpr uint64_t base = 0x100000000ULL;
static constexpr unsigned platformCode = 0x1000, platformBytes = 0x1800;
static uint8_t memory[0x80000];
static unsigned reads, writes, protections, retryWrites, processLookups;
static bool failEnable, failRestore, failRetry;
static const char *missingSymbol;
static int changedCodeByte = -1;
static size_t codeReadLimit = NativeMapProtectionUseraccSize;
static bool wrongProtectionTarget;
static unsigned codeReads;
static uint8_t codeReaderContext;

proc_t proc_find(int pid) { ++processLookups; if (pid != targetPID || !process.alive) return nullptr; ++process.references; return &process; }
void proc_rele(proc_t p) { assert(p == &process && p->references); --p->references; }
int proc_name(int pid, void *out, int size) { assert(pid == targetPID); return static_cast<int>(strlcpy(static_cast<char *>(out), process.name, size)); }
kauth_cred_t kauth_cred_proc_ref(proc_t p) { ++p->credentials; return p; }
uid_t kauth_cred_getuid(kauth_cred_t) { return 501; }
void kauth_cred_unref(kauth_cred_t *p) { assert((*p)->credentials); --(*p)->credentials; *p = nullptr; }
static void *task(proc_t p) { return p->taskAvailable ? p : nullptr; }
static void *reference(void *p) { auto &t = *static_cast<proc_t>(p); if (!t.mapAvailable) return nullptr; ++t.map->references; return t.map; }
static void release(void *p) { auto &m = *static_cast<NativeTestMap *>(p); assert(m.references); --m.references; }
static int suspended(void *p) { return static_cast<proc_t>(p)->suspended; }
static bool range(uint64_t address, uint64_t length) { return address >= base && address - base <= sizeof(memory) && length <= sizeof(memory) - (address - base); }
static int readMemory(void *map, uint64_t address, void *out, uint64_t length) {
    assert(map == &originalMap); ++reads;
    if (!range(address, length)) return -40;
    memcpy(out, memory + (address - base), length); return 0;
}
static int writeMemory(void *map, const void *in, uint64_t address, uint64_t length) {
    assert(map == &originalMap); ++writes;
    if (!range(address, length)) return -40;
    bool platform = address == base + platformBytes && length == 2;
    bool restoring = platform && static_cast<const uint8_t *>(in)[1] == 0;
    if (restoring && failRestore) return -44;
    if (failRetry && ((address == base + 0x648 && length == 16) || (address == base + 0x7b858 && length == 8))) {
        if (++retryWrites > 1) return -46;
        memcpy(memory + (address - base), in, length); return -45;
    }
    memcpy(memory + (address - base), in, length);
    return platform && !restoring && failEnable ? -43 : 0;
}
static int protection(void *map, uint64_t start, uint64_t end, vm_prot_t, const void *caller) {
    assert(reinterpret_cast<uintptr_t>(caller) == reinterpret_cast<uintptr_t>(&protection) + 0x507e70 + 0x5dcd68);
    assert(map == &originalMap); ++protections; return end >= start && range(start, end - start);
}
static uintptr_t useraccAddress() { return reinterpret_cast<uintptr_t>(&protection) + 0x507e70; }
static size_t readKernelCode(void *context, uintptr_t address, void *out, size_t length) {
    assert(context == &codeReaderContext && address == useraccAddress() && length == 53);
    ++codeReads;
    uint8_t code[] = {
        0x55,0x48,0x89,0xe5,0x48,0x89,0xf8,0x65,0x48,0x8b,0x0c,0x25,0x10,0x00,0x00,0x00,
        0x48,0x8b,0xb9,0x28,0x06,0x00,0x00,0x31,0xc9,0x83,0xfa,0x01,0x0f,0x95,0xc1,0xff,
        0xc1,0x48,0x8d,0x14,0x06,0x4c,0x8d,0x05,0x3c,0xcd,0x5d,0x00,0x48,0x89,0xc6,0x5d,
        0xe9,0x5b,0x81,0xaf,0xff
    };
    if (changedCodeByte >= 0) { assert(changedCodeByte < 53); code[changedCodeByte] ^= 1; }
    assert(codeReadLimit <= length);
    memcpy(out, code, codeReadLimit);
    return codeReadLimit;
}
static void resetCodeReader() {
    missingSymbol = nullptr; changedCodeByte = -1; codeReadLimit = 53;
    wrongProtectionTarget = false; codeReads = 0;
}
uintptr_t nativePlatformTestResolve(const char *name) {
    if (missingSymbol && !strcmp(missingSymbol, name)) return 0;
    if (!strcmp(name, "_useracc")) return useraccAddress();
    if (wrongProtectionTarget && !strcmp(name, "_vm_map_check_protection")) return reinterpret_cast<uintptr_t>(&protection) + 1;
#define SYMBOL(n, f) if (!strcmp(name, n)) return reinterpret_cast<uintptr_t>(&f)
    SYMBOL("_proc_task", task); SYMBOL("_get_task_map_reference", reference);
    SYMBOL("_vm_map_deallocate", release); SYMBOL("_vm_map_read_user", readMemory);
    SYMBOL("_vm_map_write_user", writeMemory); SYMBOL("_vm_map_check_protection", protection);
    SYMBOL("_get_task_suspended", suspended);
#undef SYMBOL
    return 0;
}
namespace RetirementRuntime {
static bool failRetirement;
static unsigned retirementCalls;
static void releaseMock(void*, void*) {}
bool retainRemote(void *task, ExactTaskRetirement::RemoteTicket &ticket) {
    ExactTaskRetirement::Ticket source {}; source.task=task; source.generation=1; source.retained=true;
    return ticket.adoptCurrent(source);
}
bool releaseRemoteClean(ExactTaskRetirement::RemoteTicket &ticket) {
    ExactTaskRetirement::API api {}; api.release=releaseMock; return ticket.releaseClean(api);
}
ExactTaskRetirement::Result retireRemote(ExactTaskRetirement::RemoteTicket &ticket) {
    ++retirementCalls;
    if (failRetirement) return {ExactTaskRetirement::Outcome::UnsafeUnresolved, ExactTaskRetirement::Reason::StillActive};
    releaseRemoteClean(ticket); return {ExactTaskRetirement::Outcome::NoUserResumeVerified, ExactTaskRetirement::Reason::None};
}
}
static void put64(unsigned at, uint64_t value) { memcpy(memory + at, &value, 8); }
static void reset(bool core = false) {
    assert(!originalMap.references && !replacementMap.references && !process.references && !process.credentials);
    process = {}; process.name = core ? "coreauthd" : "Touch ID & Password";
    memset(memory, 0, sizeof(memory)); reads = writes = protections = retryWrites = processLookups = 0;
    failEnable = failRestore = failRetry = false;
    auto *code = memory + platformCode;
    code[0x43] = 0x80; code[0x44] = 0x3d;
    code[0x9d] = 0xc6; code[0x9e] = 0x05; code[0xa3] = 1;
    code[0x23f] = 0x8a; code[0x240] = 0x1d;
    int32_t checked = platformBytes - platformCode - 0x4a;
    int32_t written = platformBytes - platformCode - 0xa4;
    int32_t result = platformBytes + 1 - platformCode - 0x245;
    memcpy(code + 0x45, &checked, 4); memcpy(code + 0x9f, &written, 4); memcpy(code + 0x241, &result, 4);
    memory[platformBytes] = 1;
    const uint8_t getter[] = {0x48,0x83,0x3d,0,0,0,0,0xff,0x75,0x0c,0x48,0x8b,0x3d};
    if (core) {
        memcpy(memory, getter, sizeof(getter));
        const uint8_t fault[] = {0x55,0x48,0x89,0xe5,0x48,0x8b,0x47,0x48,0x5d,0xc3};
        memcpy(memory + 0x100, fault, 10); memcpy(memory + 0x200, fault, 10); memory[0x207] = 0x50;
        int32_t once = 0x400 - 8, object = 0x408 - 17;
        memcpy(memory + 3, &once, 4); memcpy(memory + 13, &object, 4);
        put64(0x400, UINT64_MAX); put64(0x408, base + 0x600);
        put64(0x600, base + 0x900); put64(0x650, base + 0xa00); put64(0x658, 1);
    } else {
        uint32_t header[] = {0xfeedfacf,0x01000007,3,2,1,24,0,0,0x1b,24};
        memcpy(memory, header, sizeof(header)); memcpy(memory + 40, NativeSettingsImageUUID, 16);
        auto *device = memory + NativeSettingsDeviceFunctionOffset;
        memcpy(device, getter, sizeof(getter));
        int32_t once = 0x7b858 - (NativeSettingsDeviceFunctionOffset + 8);
        int32_t object = 0x7b860 - (NativeSettingsDeviceFunctionOffset + 17);
        memcpy(device + 3, &once, 4); memcpy(device + 13, &object, 4); put64(0x7b858, UINT64_MAX);
    }
}
static NativeSettingsProcessRequest settingsRequest {1,501,targetPID,0,base + platformCode,base};
static NativePlatformProcessRequest coreRequest {1,501,targetPID,0,base + platformCode,base,base + 0x100,base + 0x200,base + 0x900};
static void unchanged(unsigned beforeReads, unsigned beforeWrites, unsigned beforeProtections) {
    assert(reads == beforeReads && writes == beforeWrites && protections == beforeProtections);
}
static void initializationClosed() {
    NativePlatformProcess owner; NativePlatformProcessReport report {}; NativeSettingsInspectionReport inspection {};
    owner.report(0, report);
    assert(!report.kernelReady && !report.attached && !report.restorePending);
    assert(owner.enable(coreRequest) == NativePlatformInvalid);
    assert(owner.enableSettings(settingsRequest) == NativePlatformInvalid);
    assert(owner.inspectSettings(settingsRequest, inspection) == NativePlatformInvalid);
    assert(!owner.restore() && !owner.pending() && !owner.attached());
    unchanged(0,0,0); assert(!processLookups && !originalMap.references && !process.references && !process.credentials);
}
static unsigned initializationScenarios(KernelPatcher &patcher) {
    unsigned scenarios = 0;
    const char *symbols[] = {"_proc_task", "_get_task_map_reference", "_vm_map_deallocate", "_vm_map_read_user",
        "_vm_map_write_user", "_vm_map_check_protection", "_get_task_suspended", "_useracc"};
    for (const char *symbol : symbols) {
        reset(); resetCodeReader();
        assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
        missingSymbol = symbol; codeReads = 0;
        assert(!NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext) && !codeReads);
        initializationClosed(); ++scenarios;
    }
    for (int byte = 0; byte < 53; ++byte) {
        reset(); resetCodeReader();
        assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
        changedCodeByte = byte; codeReads = 0;
        assert(!NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext) && codeReads == 1);
        initializationClosed(); ++scenarios;
    }
    for (size_t length = 0; length < 53; ++length) {
        reset(); resetCodeReader();
        assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
        codeReadLimit = length; codeReads = 0;
        assert(!NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext) && codeReads == 1);
        initializationClosed(); ++scenarios;
    }
    reset(); resetCodeReader();
    assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
    wrongProtectionTarget = true;
    assert(!NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
    initializationClosed(); ++scenarios;
    resetCodeReader();
    assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext));
    codeReads = 0;
    assert(!NativePlatformProcess::initialize(patcher, nullptr, &codeReaderContext) && !codeReads);
    initializationClosed(); ++scenarios;
    resetCodeReader();
    assert(NativePlatformProcess::initialize(patcher, readKernelCode, &codeReaderContext) && codeReads == 1);
    return scenarios;
}
int main() {
    KernelPatcher patcher;
    unsigned scenarios = initializationScenarios(patcher);
    for (bool core : {false, true}) for (bool exec : {false, true}) {
        reset(core); NativePlatformProcess owner;
        assert(!(core ? owner.enable(coreRequest) : owner.enableSettings(settingsRequest)));
        assert(owner.attached() && owner.pending() && originalMap.references == 1);
        process.suspended = false;
        const unsigned r = reads, w = writes, p = protections;
        for (unsigned i = 0; i < 3; ++i) {
            assert(owner.restore() == NativePlatformRestartRequired); unchanged(r,w,p);
            NativePlatformProcessReport report {}; owner.report(NativePlatformRestartRequired, report);
            assert(report.attached && report.restorePending && report.restartRequired && report.pid == targetPID);
            assert(memory[platformBytes + 1] == 1 && originalMap.references == 1);
        }
        if (exec) process.map = &replacementMap; else process.alive = false;
        assert(!owner.restore() && !owner.pending() && !owner.attached()); unchanged(r,w,p);
        assert(!owner.restore() && !originalMap.references && !replacementMap.references); ++scenarios;
    }
    for (bool missingTask : {false, true}) {
        reset(); NativePlatformProcess owner; assert(!owner.enableSettings(settingsRequest));
        unsigned r = reads, w = writes, p = protections;
        if (missingTask) process.taskAvailable = false; else process.mapAvailable = false;
        assert(owner.restore() == NativePlatformChanged && owner.attached() && owner.pending()); unchanged(r,w,p);
        NativePlatformProcessReport report {}; owner.report(NativePlatformChanged, report);
        assert(report.status == NativePlatformChanged && report.attached && report.restorePending && report.restartRequired && report.pid == targetPID);
        assert(originalMap.references == 1);
        process.taskAvailable = process.mapAvailable = true;
        assert(owner.restore() == NativePlatformRestartRequired); unchanged(r,w,p);
        process.alive = false; assert(!owner.restore() && !owner.attached()); unchanged(r,w,p); ++scenarios;
    }
    for (bool core : {false, true}) {
        reset(core); NativePlatformProcess owner; failRetry = true;
        assert((core ? owner.enable(coreRequest) : owner.enableSettings(settingsRequest)) == -45);
        assert(owner.pending() && owner.attached() && !memory[platformBytes + 1] && retryWrites == 2);
        process.suspended = false;
        unsigned r = reads, w = writes, p = protections;
        for (unsigned i = 0; i < 3; ++i) {
            assert(owner.restore() == NativePlatformRestartRequired); unchanged(r,w,p);
            NativePlatformProcessReport report {}; owner.report(NativePlatformRestartRequired, report);
            assert(report.attached && report.restorePending && report.restartRequired);
        }
        process.alive = false; assert(!owner.restore() && !owner.pending() && !owner.attached()); unchanged(r,w,p); ++scenarios;
    }
    for (bool core : {false, true}) for (bool exec : {false, true}) {
        reset(core); NativePlatformProcess owner; failEnable = failRestore = true;
        assert((core ? owner.enable(coreRequest) : owner.enableSettings(settingsRequest)) == -43);
        assert(owner.attached() && owner.pending() && retryWrites == 0);
        unsigned r = reads, w = writes, p = protections;
        // A sampled suspension is not a caller-owned pause lease for a later restore.
        for (bool paused : {true, false}) {
            process.suspended = paused;
            assert(owner.restore() == NativePlatformRestartRequired); unchanged(r,w,p);
            NativePlatformProcessReport report {}; owner.report(NativePlatformRestartRequired, report);
            assert(report.attached && report.restorePending && report.restartRequired && report.pid == targetPID);
            failRestore = false;
        }
        if (exec) process.map = &replacementMap; else process.alive = false;
        assert(!owner.restore() && !owner.attached() && !owner.pending()); unchanged(r,w,p);
        NativePlatformProcessReport report {}; owner.report(0, report);
        assert(!report.attached && !report.restorePending && !report.restartRequired && !report.pid); ++scenarios;
    }
    reset(); {
        NativePlatformProcess owner; NativeSettingsRecoveryReport report {};
        assert(owner.recoverSettingsConnection(settingsRequest, &report) == NativeSettingsRecoveryUnavailable);
        assert(!owner.attached() && !owner.pending()); unchanged(0,0,0); ++scenarios;
    }
    reset(); {
        // Reach the real executable-range callback with a deliberately writable text segment.
        uint32_t header[] = {0xfeedfacf,0x01000007,3,6,2,96,0,0,0x1b,24};
        memcpy(memory, header, sizeof(header)); memcpy(memory + 40, NativeConnectionImageUUID, 16);
        uint32_t segment[] = {0x19,72}; memcpy(memory + 56, segment, sizeof(segment));
        memcpy(memory + 64, "__TEXT", 7); put64(56 + 32, 0x30000); put64(56 + 40, 0);
        uint32_t execute = VM_PROT_EXECUTE; memcpy(memory + 56 + 60, &execute, sizeof(execute));
        NativePlatformProcess owner; NativeSettingsInspectionReport report {};
        NativeSettingsProcessRequest request {1,501,targetPID,0,base + 0x238d1,base};
        assert(owner.inspectSettings(request, report) == NativePlatformInvalid);
        assert(report.stage == static_cast<uint32_t>(NativeConnectionImageStage::Execution));
        assert(protections == 2 && !writes && !owner.attached() && !owner.pending()); ++scenarios;
    }
    reset(true); {
        NativePlatformProcess owner;
        assert(!owner.enable(coreRequest) && owner.attached());
        unsigned lookups=processLookups, r=reads,w=writes,p=protections;
        RetirementRuntime::failRetirement=true;
        assert(owner.retireExact()==NativePlatformRestartRequired && owner.attached());
        assert(processLookups==lookups); unchanged(r,w,p); ++scenarios;
        process.map=&replacementMap;
        RetirementRuntime::failRetirement=false;
        assert(!owner.retireExact() && !owner.attached() && !owner.pending());
        assert(processLookups==lookups); unchanged(r,w,p); ++scenarios;
        auto calls=RetirementRuntime::retirementCalls;
        assert(!owner.retireExact() && RetirementRuntime::retirementCalls==calls); ++scenarios;
    }
    assert(codeReads == 1);
    assert(!originalMap.references && !replacementMap.references && !process.references && !process.credentials);
    printf("platform process: %u production-path ABI and lifecycle scenarios passed\n", scenarios);
}
