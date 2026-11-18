#pragma once
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include "../NativeCredentialStudy.h"
#include "../NativeProviderABI.h"
#include "../NativeOperationGate.h"
#include "../NativeStartupTrialState.h"

using IOReturn = int;
static constexpr IOReturn kIOReturnSuccess = 0, kIOReturnBusy = -1, kIOReturnNotOpen = -2,
    kIOReturnNotAttached = -3, kIOReturnNotReady = -4, kIOReturnBadArgument = -5,
    kIOReturnNoMemory = -6, kIOReturnAborted = -7;
#define ADDPR(name) name
#define OSDynamicCast(type, object) dynamic_cast<type *>(object)
#define OSDeclareDefaultStructors(type)
#define SYSLOG(...) do {} while (0)

static bool stateAccessAllowed = true;
static thread_local bool lockHeld;
static std::function<void(const std::string &)> callback;
static std::map<std::string, unsigned> events;
static void event(const std::string &name) {
    assert(!lockHeld);
    ++events[name];
    if (callback) callback(name);
}
struct IOLock { std::mutex mutex; } stateMutex;
static IOLock *providerLock = &stateMutex;
static NativeOperationGate providerGate;
static NativeStartupTrialState startupTrial;
static bool startupTrialCommitted;
static int nativeRetireCommittedSettings(NativeStartupTrialReport &report) { startupTrialCommitted=false; report={1,0,0,0,0,0,0}; return 0; }
class OSObject;
static OSObject *startupRecoveryOwner;
static OSObject *startupLeaseOwner;
static bool startupTrialRecoveryPending;
static int startupAvailability = 1;
static void IOLockLock(IOLock *lock) { assert(!lockHeld); lock->mutex.lock(); lockHeld = true; }
static void IOLockUnlock(IOLock *lock) {
    assert(lockHeld); lockHeld = false; lock->mutex.unlock(); event("unlock");
}

template <typename T> struct Guarded {
    T value {};
    operator T() const { assert(stateAccessAllowed); return value; }
    Guarded &operator=(T next) { assert(stateAccessAllowed); value = next; return *this; }
};
struct ProviderState { Guarded<bool> active, restorePending, quarantined; uint32_t user = 501, identityCount = 0; uint64_t lastSequence = 0; } providerState;
static bool providerReady = true, studyReady = true, startSuccess = true;
static volatile uint32_t symbolsReady = 1;
static uint32_t uuidMatched = 1, symbolMask = 15, initializationStages = 0;
static int getPermissions(unsigned, unsigned, uint64_t *value) { assert(!lockHeld); *value = 0; return 0; }
static int getAvailability(uint64_t, unsigned, uint8_t *value, bool) { assert(!lockHeld); *value = 0; return 0; }
static int createContext(void **value) { assert(!lockHeld); *value = &symbolMask; return 0; }
static int deleteContext(void *, bool) { assert(!lockHeld); return 0; }
static bool stopFails, mapFails, enableFails, recoverLeavesPending, missingMatching, missingService, missingWorkLoop;
static int acmFailureSelector = -1;
static bool availabilityRestorePending, studyRestoreFails;
static unsigned acmCalls, stopCalls, mapCalls, studyCalls;

class OSObject {
public:
    int references = 1;
    unsigned retains = 0, releases = 0;
    bool heap = false;
    std::string label = "object";
    virtual ~OSObject() = default;
    void retain() { assert(references > 0); ++references; ++retains; }
    void release() {
        assert(!lockHeld && references > 0);
        ++releases; --references;
        event("release-" + label);
        if (!references) { assert(heap); delete this; }
    }
};
static Guarded<OSObject *> providerOwner;
struct IOExternalMethodArguments {};
struct IOExternalMethodDispatch {};
class IOWorkLoop {
public:
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    IOReturn runAction(Action action, OSObject *owner, void *selector, void *report) {
        assert(!lockHeld);
        event("work-loop");
        return action(owner, selector, report, nullptr, nullptr);
    }
} workLoop;
class IOService : public OSObject {
public:
    IOWorkLoop *getWorkLoop() { assert(!lockHeld); return missingWorkLoop ? nullptr : &workLoop; }
    static OSObject *serviceMatching(const char *) {
        event("service-matching");
        if (missingMatching) return nullptr;
        auto *object = new OSObject; object->heap = true; object->label = "dictionary"; return object;
    }
    static IOService *copyMatchingService(OSObject *) {
        event("service-copy");
        if (missingService) return nullptr;
        auto *service = new IOService; service->heap = true; service->label = "acm"; return service;
    }
    void setProperty(const char *key, bool) {
        assert(providerGate.snapshot().active && references >= 2);
        event(std::string("property-") + key);
    }
};
class IOUserClient : public OSObject {
public:
    IOService *provider = nullptr;
    unsigned terminations = 0;
    IOService *getProvider() { return provider; }
    void terminate() { assert(!lockHeld); ++terminations; event("terminate"); }
    virtual IOReturn clientClose() { return 0; }
    virtual IOReturn externalMethod(uint32_t, IOExternalMethodArguments *, IOExternalMethodDispatch *, OSObject *, void *) { return 0; }
};
class TestPlatform {
    bool attached_ = false;
public:
    const char *name;
    explicit TestPlatform(const char *n) : name(n) {}
    bool attached() const { assert(stateAccessAllowed); return attached_; }
    bool pending() const { return attached(); }
    void seed(bool value) { attached_ = value; }
    void call(const char *operation) {
        assert(!lockHeld && providerGate.snapshot().active);
        ++mapCalls; event(std::string(name) + operation);
    }
    int restore() { call("-restore"); if (!mapFails) attached_ = false; return attached_ ? -31003 : 0; }
    int retireExact() { attached_=false; return 0; }
    int enable(const NativePlatformProcessRequest &) { call("-enable"); attached_ = true; return enableFails ? -42 : 0; }
    int enableSettings(const NativeSettingsProcessRequest &) { call("-enable"); attached_ = true; return enableFails ? -42 : 0; }
    int inspectSettings(const NativeSettingsProcessRequest &, NativeSettingsInspectionReport &out) {
        call("-inspect"); out = {2,0,1,1,9,{0,0,0}}; return 0;
    }
    int recoverSettingsConnection(const NativeSettingsProcessRequest &, NativeSettingsRecoveryReport *) {
        call("-recover"); if (recoverLeavesPending) attached_ = true; return -31004;
    }
    void report(int status, NativePlatformProcessReport &out) {
        assert(stateAccessAllowed);
        out = {1,status,1,attached_,42,attached_,attached_,0};
    }
};
static TestPlatform providerPlatform("platform"), settingsPlatform("settings");

class ELANNativeProbe : public IOService {
public:
    IOReturn providerOperation(OSObject *, uint32_t, const void *, void *);
    IOReturn collectReport(uint32_t, ElanNativeProbeReport *);
    IOReturn collectStudy(OSObject *, uint32_t, NativeCredentialStudyReport *);
    void providerClosed(OSObject *);
    IOReturn startupTrialLease(NativeStartupTrialLeaseRequest &);
    IOReturn startupTrialArm(OSObject *, const NativeStartupTrialRequest &, NativeStartupTrialReport &);
    IOReturn startupTrialCancel(OSObject *, const NativeStartupTrialRequest &, NativeStartupTrialReport &);
private:
    static IOReturn collectGated(OSObject *, void *, void *, void *, void *);
    IOReturn providerRun(OSObject *, uint32_t, const void *, void *, bool);
    IOReturn providerDispatch(OSObject *, uint32_t, const void *, void *);
    IOReturn providerStudy(uint32_t, NativeCredentialStudyReport *);
    void providerCleanup();
    void providerPublish();
    IOReturn providerACM(uint32_t selector, const void *, void *output) {
        assert(!lockHeld && providerGate.snapshot().active);
        ++acmCalls;
        if (selector == ElanProviderEnd) ++stopCalls;
        event("acm-" + std::to_string(selector));
        if (static_cast<int>(selector) == acmFailureSelector) return kIOReturnNotReady;
        if (selector == ElanProviderStartupTrialArm) {
            auto &report = *static_cast<NativeStartupTrialReport *>(output);
            report = {1, startupAvailability == 1 ? 0 : NativeProviderNotActive, 0, 0, 0, 0, 0};
        } else if (selector == ElanProviderBegin || selector == ElanProviderCatalogBegin) {
            providerState.active = true; providerState.restorePending = true;
        } else if (selector == ElanProviderEnd) {
            providerState.active = false;
            providerState.restorePending = stopFails;
            providerState.quarantined = stopFails;
            auto &report = *static_cast<NativeProviderReport *>(output);
            report.abi = 1; report.restoreStatus = stopFails ? -99 : 0;
        }
        return 0;
    }
    static IOReturn studyGated(OSObject *, void *selector, void *, void *, void *) {
        assert(!lockHeld && providerGate.snapshot().active);
        ++studyCalls;
        event("study-" + std::to_string(reinterpret_cast<uintptr_t>(selector)));
        if (reinterpret_cast<uintptr_t>(selector) == ElanProbeRestoreAvailability && !studyRestoreFails) availabilityRestorePending = false;
        return 0;
    }
};
