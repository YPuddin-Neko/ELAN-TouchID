#include <Headers/kern_api.hpp>
#include <libkern/copyio.h>
#include "NativeSettingsHardwareGate.h"
#include "NativeSettingsMemoryPolicy.h"
#include "NativeSettingsStartupDiagnostics.h"
#include "SettingsVM24H32.h"
// The permit helper admits a pinned ad-hoc worker. Keep the Apple-only identity
// implementation in a separate namespace even when both are linked into this kext.
#define NativePinnedBinaryIdentity AppleSettingsBinary
#include "../agent-integration-candidate/startup-fresh-writer/runtime/KernelRuntime.h"
#undef NativePinnedBinaryIdentity
#include "NativeSettingsAgentGate.h"
#include "NativeCoreAuthSample.h"
#include "../agent-integration-candidate/startup-writer-009/OwnerValidation.h"
#include "../agent-integration-candidate/map-cow-observation/LeafCowSample.h"

uint32_t elanStartupAuditSession(void *task);
bool elanStartupAuditMatches(void *task, uint32_t sessionAsid);

namespace {
constexpr AppleSettingsBinary::Policy settings = {
    true,{0x41,0x8e,0xcd,0x95,0xe7,0x42,0x38,0x47,0x96,0x21,0x84,0x13,0x5a,0x94,0xb6,0x34},
    {0xe3,0xfe,0xc5,0x23,0xfc,0x8a,0xfc,0x4e,0x82,0xb0,0xe7,0x4d,0xf6,0x26,0x67,0xb0,0x56,0xa0,0xbf,0x27},2,501,
    "/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password"
};
constexpr AppleSettingsBinary::Policy settingsAgent = {
    true,{0x67,0xb7,0x6a,0x48,0xd3,0x0e,0x3d,0xaa,0x9c,0x63,0xc6,0xbc,0x27,0xbb,0xd1,0xda},
    {0xc0,0x11,0xcc,0xcc,0xec,0xba,0x64,0x21,0x43,0x36,0x9b,0x72,0x44,0xa3,0x86,0x1c,0x2a,0x79,0xc1,0x89},2,501,
    "/System/Applications/System Settings.app/Contents/Resources/systemsettingsagent"
};
constexpr AppleSettingsBinary::Policy coreauth = {
    true,{0x1d,0xa8,0x41,0x5c,0xbe,0x1a,0x35,0x30,0x85,0xeb,0x58,0x17,0x00,0x25,0xbe,0x1f},
    {0x69,0x82,0x84,0x36,0xa4,0x85,0x0c,0x9b,0x85,0x6c,0x51,0xc6,0xf9,0xb0,0x67,0x2c,0x2a,0x50,0x39,0x74},2,501,
    "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd"
};
struct Functions {
    void *(*map)();
    int (*allocate)(void *,uint64_t *,uint64_t,int);
    int (*release)(void *,uint64_t,uint64_t);
    int (*protect)(void *,uint64_t,uint64_t,int,int);
    int (*store)(uint64_t,uint64_t);
    LeafCowSample::Query region;
};
Functions functions{};
AppleSettingsBinary::API identity{};
mach_vm_address_t original;
uint32_t enabled;
NativeSettingsStartupDiagnostics::State diagnostics;

int readCurrent(void *, uint64_t address, void *out, size_t size) { return copyin(address,out,size); }
struct CurrentMap {
    void *map, *task;
    uint32_t sessionAsid;
    const StartupAdmission::API &admission;
    const StartupAdmission::Receipt &receipt;
    CurrentCopyinSample::Reader reader() const { return {nullptr,readCurrent}; }
    bool permitted() const {
        return map && functions.map() == map && identity.currentTask() == task &&
               elanStartupAuditMatches(task,sessionAsid) &&
               admission.currentThread(admission.threadContext)==receipt.thread &&
               ExecGeneration::revalidate(admission.generation,receipt.generation)==ExecGeneration::Outcome::Stable;
    }
    bool region(uint64_t address, size_t bytes, int protection, int maximum, bool cow, bool dataMaximum=false) const {
        uint64_t start=address, size=0;
        unsigned depth=8, count=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        vm_region_submap_short_info_data_64_t info{};
        return !functions.region(map,&start,&size,&depth,reinterpret_cast<vm_region_submap_info_64_t>(&info),&count) &&
               depth<=8 && count==VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 && !info.is_submap &&
               start<=address && size>=bytes && address-start<=size-bytes &&
               (dataMaximum ? NativeSettingsMemoryPolicy::writableData(info.protection,info.max_protection,info.share_mode==SM_COW) :
                (info.protection==protection && info.max_protection==maximum && (!cow || info.share_mode==SM_COW)));
    }
    bool readOnlySelector(uint64_t address,size_t bytes) const {
        uint64_t start=address, size=0;
        unsigned depth=8, count=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        vm_region_submap_short_info_data_64_t info{};
        return permitted() && bytes &&
               !functions.region(map,&start,&size,&depth,reinterpret_cast<vm_region_submap_info_64_t>(&info),&count) &&
               depth<=8 && count==VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 && !info.is_submap &&
               start<=address && size>=bytes && address-start<=size-bytes &&
               (info.protection==VM_PROT_READ || info.protection==(VM_PROT_READ|VM_PROT_EXECUTE)) &&
               !(info.max_protection&~VM_PROT_ALL) && (info.max_protection&info.protection)==info.protection;
    }
    bool privateMethodSlot(uint64_t slot) const {
        uint64_t start=slot, size=0;
        unsigned depth=8, count=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        vm_region_submap_short_info_data_64_t info{};
        return permitted() && !(slot & 7) &&
               !functions.region(map,&start,&size,&depth,reinterpret_cast<vm_region_submap_info_64_t>(&info),&count) &&
               depth<=8 && count==VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 && !info.is_submap &&
               start<=slot && size>=8 && slot-start<=size-8 &&
               info.protection==(VM_PROT_READ|VM_PROT_WRITE) &&
               info.max_protection==(VM_PROT_READ|VM_PROT_WRITE) &&
               (info.share_mode==SM_COW || info.share_mode==SM_PRIVATE);
    }
    bool executablePage(uint64_t page) const {
        uint64_t start=page, size=0;
        unsigned depth=8, count=VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        vm_region_submap_short_info_data_64_t info{};
        return permitted() && !(page & 4095) &&
               !functions.region(map,&start,&size,&depth,reinterpret_cast<vm_region_submap_info_64_t>(&info),&count) &&
               depth<=8 && count==VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 && !info.is_submap &&
               start<=page && size>=4096 && page-start<=size-4096 &&
               info.protection==(VM_PROT_READ|VM_PROT_EXECUTE) &&
               (info.max_protection&(VM_PROT_READ|VM_PROT_EXECUTE))==(VM_PROT_READ|VM_PROT_EXECUTE);
    }
    bool cowSlot(uint64_t slot) const { return region(slot,8,VM_PROT_READ,VM_PROT_READ|VM_PROT_WRITE,true); }
    bool readOnlySlot(uint64_t slot) const { return region(slot,8,VM_PROT_READ,VM_PROT_READ|VM_PROT_WRITE,false); }
    bool writableData(uint64_t address) const { return region(address,2,3,3,true,true); }
    bool allocate(uint64_t &slot) const { return !functions.allocate(map,&slot,4096,VM_FLAGS_ANYWHERE); }
    bool release(uint64_t slot) const { return !functions.release(map,slot,4096); }
    bool write(uint64_t address,const uint8_t *in,size_t bytes) const { return !copyout(in,address,bytes); }
    bool seal(uint64_t page) const {
        return !functions.protect(map,page,4096,1,VM_PROT_READ) && region(page,4096,VM_PROT_READ,VM_PROT_READ,false);
    }
    bool makeCopyWritable(uint64_t page) const {
        return !functions.protect(map,page,4096,0,VM_PROT_COPY|VM_PROT_READ|VM_PROT_WRITE);
    }
    bool protectSlot(uint64_t page) const { return !functions.protect(map,page,4096,0,VM_PROT_READ); }
    bool protectExecutablePage(uint64_t page) const {
        return !functions.protect(map,page,4096,0,VM_PROT_READ|VM_PROT_EXECUTE);
    }
    bool storePointer(uint64_t destination,uint64_t value) const { return !functions.store(value,destination); }
};

struct Attempt { uint64_t output; uint32_t sessionAsid; };
bool routeTarget(void *context, void *proc, void *task) {
    auto &attempt = *static_cast<Attempt *>(context);
    if (!elanStartupAuditMatches(task,attempt.sessionAsid)) {
        diagnostics.record(NativeSettingsStartupDiagnostics::Event::AuditRejected);return false;
    }
    StartupAdmission::API api{};
    if (!StartupWriteBinding::admissionAPI(readCurrent,nullptr,api)) {
        diagnostics.record(NativeSettingsStartupDiagnostics::Event::APIMissing);return false;
    }
    StartupAdmission::Receipt receipt{};
    auto admission = StartupAdmission::inspect(api,proc,task,attempt.output,receipt);
    if (!receipt.accepted) {
        diagnostics.record(NativeSettingsStartupDiagnostics::Event::AdmissionRejected,
            uint8_t(admission.stage),uint8_t(admission.callerResult.caller.stage),uint8_t(admission.settingsResult.stage),
            uint8_t(admission.outerResult.stage),255,admission.jointlyCold,false,admission.callerResult.caller.lateBoundary);
        static uint32_t reports=0;
        if (__atomic_fetch_add(&reports,1U,__ATOMIC_RELAXED)<8)
            SYSLOG("settings","startup admission stage=%u caller=%u settings=%u outer=%u cold=%u",
                   static_cast<unsigned>(admission.stage), static_cast<unsigned>(admission.callerResult.caller.stage),
                   static_cast<unsigned>(admission.settingsResult.stage), static_cast<unsigned>(admission.outerResult.stage),
                   static_cast<unsigned>(admission.jointlyCold));
        return false;
    }
    CurrentMap memory{functions.map(),task,attempt.sessionAsid,api,receipt};
    NativeSettingsHardwareGate::Stage gateStage{};
    auto result = NativeSettingsHardwareGate::apply(memory,receipt.mainBase,receipt.cacheBase,true,&gateStage);
    static_assert(static_cast<unsigned>(NativeSettingsRoute::Result::Routed)==1,"diagnostic routed code");
    diagnostics.record(NativeSettingsStartupDiagnostics::Event::RouteReturned,
        uint8_t(admission.stage),uint8_t(admission.callerResult.caller.stage),uint8_t(admission.settingsResult.stage),
        uint8_t(admission.outerResult.stage),uint8_t(result),admission.jointlyCold,true,admission.callerResult.caller.lateBoundary,uint8_t(gateStage));
    SYSLOG("settings","startup route result %u",static_cast<unsigned>(result));
    return result == NativeSettingsRoute::Result::Routed;
}
bool routeAgentTarget(void *context, void *proc, void *task) {
    auto &attempt = *static_cast<Attempt *>(context);
    if (!elanStartupAuditMatches(task,attempt.sessionAsid)) return false;
    StartupAdmission::API api{};
    if (!StartupWriteBinding::admissionAPI(readCurrent,nullptr,api)) return false;
    api.settings = NativeSettingsAgentSample::inspect;
    StartupAdmission::Receipt receipt{};
    StartupAdmission::inspect(api,proc,task,attempt.output,receipt);
    if (!receipt.accepted) return false;
    CurrentMap memory{functions.map(),task,attempt.sessionAsid,api,receipt};
    auto result = NativeSettingsAgentGate::apply(memory,receipt.mainBase,receipt.cacheBase);
    SYSLOG("settings","agent startup route result %u",static_cast<unsigned>(result));
    return result == NativeSettingsRoute::Result::Routed;
}
bool routeCoreAuthTarget(void *context, void *proc, void *task) {
    auto &attempt = *static_cast<Attempt *>(context);
    if (!elanStartupAuditMatches(task,attempt.sessionAsid)) return false;
    StartupAdmission::API api{};
    if (!StartupWriteBinding::admissionAPI(readCurrent,nullptr,api)) return false;
    api.settings = NativeCoreAuthSample::inspect;
    StartupAdmission::Receipt receipt{};
    StartupAdmission::inspect(api,proc,task,attempt.output,receipt);
    if (!receipt.accepted) return false;
    CurrentMap memory{functions.map(),task,attempt.sessionAsid,api,receipt};
    auto result = NativeSettingsRoute::apply(memory,receipt.cacheBase);
    SYSLOG("settings","coreauth startup route result %u",static_cast<unsigned>(result));
    return result == NativeSettingsRoute::Result::Routed;
}
struct Args { uint64_t output; };
int wrapper(void *proc, Args *args, int *retval) {
    int status = reinterpret_cast<int (*)(void *,Args *,int *)>(original)(proc,args,retval);
    // Only the verified post-fixup boundary may modify Settings metadata.
    if (status || !args || args->output != UINT64_MAX ||
        !__atomic_load_n(&enabled,__ATOMIC_ACQUIRE)) return status;
    uint32_t sessionAsid = identity.currentTask ? elanStartupAuditSession(identity.currentTask()) : 0;
    if (sessionAsid) {
        Attempt attempt{args->output,sessionAsid};
        AppleSettingsBinary::Result result{};
        if (!AppleSettingsBinary::capture(identity,settings,result,routeTarget,&attempt) &&
            !AppleSettingsBinary::capture(identity,settingsAgent,result,routeAgentTarget,&attempt)) {
            AppleSettingsBinary::capture(identity,coreauth,result,routeCoreAuthTarget,&attempt);
        }
    }
    return status;
}
uintptr_t resolve(void *owner,const char *name) {
    auto &patcher=*static_cast<KernelPatcher *>(owner);
    patcher.clearError();
    auto address=patcher.solveSymbol(KernelPatcher::KernelID,name);
    return patcher.getError()==KernelPatcher::Error::NoError ? address : 0;
}
bool readKernel(void *,uint64_t address,void *out,size_t bytes) {
    memcpy(out,reinterpret_cast<const void *>(address),bytes);
    return true;
}
void loaded(void *,KernelPatcher &patcher) {
    auto entry=resolve(&patcher,"_shared_region_check_np");
    OwnerValidation::Validated verified{};
    if (!entry || !OwnerValidation::preflight({&patcher,resolve,readKernel},entry,verified)) return;
    const uint64_t slide=verified.header-Exact24H32::Symbols[0].address;
    uintptr_t ops[6]{};
    for (unsigned i=0;i<arrsize(ops);i++) {
        const auto &pin=SettingsVM24H32::symbols[i];
        ops[i]=resolve(&patcher,pin.name);
        if (ops[i]!=pin.address+slide || memcmp(reinterpret_cast<const void *>(ops[i]),pin.bytes,sizeof(pin.bytes))) return;
    }
    functions={reinterpret_cast<decltype(functions.map)>(ops[0]),reinterpret_cast<decltype(functions.allocate)>(ops[1]),
               reinterpret_cast<decltype(functions.release)>(ops[2]),reinterpret_cast<decltype(functions.protect)>(ops[3]),
               reinterpret_cast<decltype(functions.store)>(ops[4]),reinterpret_cast<decltype(functions.region)>(ops[5])};
    auto thread=resolve(&patcher,"_current_thread"), state=resolve(&patcher,"_thread_get_state");
    if (thread!=0xffffff8000530b00ULL+slide || state!=0xffffff80004304c0ULL+slide ||
        !CurrentThreadCapture::configurePinned(thread,state) ||
        !AppleSettingsBinary::bind(resolve,&patcher,true,identity) ||
        !StartupWriteBinding::configure(resolve,&patcher,slide,Exact24H32::KernelUUID)) return;
    KernelPatcher::RouteRequest request("_shared_region_check_np",reinterpret_cast<void *>(wrapper),original);
    if (patcher.routeMultipleLong(KernelPatcher::KernelID,&request,1,0,0,true,false) &&
        patcher.getError()==KernelPatcher::Error::NoError && original && original!=entry &&
        original!=reinterpret_cast<uint64_t>(wrapper) &&
        OwnerValidation::readback({nullptr,nullptr,readKernel},verified,reinterpret_cast<uint64_t>(wrapper))) {
        __atomic_store_n(&enabled,1U,__ATOMIC_RELEASE);
    }
}
}
bool elanRegisterSettingsStartup() { return lilu.onPatcherLoad(loaded,nullptr)==LiluAPI::Error::NoError; }
bool elanSettingsStartupAvailable() { return __atomic_load_n(&enabled,__ATOMIC_ACQUIRE)!=0; }
uint64_t elanSettingsStartupDiagnostic(){return diagnostics.snapshot();}
uint32_t elanSettingsStartupAttempts(){return diagnostics.count();}
uint32_t elanSettingsStartupRouted(){return diagnostics.successes();}
