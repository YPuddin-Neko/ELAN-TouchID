#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <mach-o/loader.h>
#include <sys/kauth.h>
#include "ElanNativeProbe.h"
#include "NativeCredentialStudy.h"
#include "NativeEnvironmentSlot.h"
#include "NativeProviderABI.h"
#include "NativePlatformProcess.h"

static const char *acmPaths[] = {
    "/System/Library/Extensions/AppleCredentialManager.kext/Contents/MacOS/AppleCredentialManager"
};
static KernelPatcher::KextInfo acmInfo {
    "com.apple.driver.AppleCredentialManager", acmPaths, arrsize(acmPaths), {true}
};
static const uint8_t expectedUUID[16] = {
    0x38, 0xeb, 0xfc, 0x61, 0x0b, 0xf9, 0x30, 0x89,
    0x99, 0x6b, 0x3f, 0x6b, 0x2a, 0x32, 0xf2, 0x0c
};
static int (*getPermissions)(unsigned, unsigned, uint64_t *);
static int (*getAvailability)(uint64_t, unsigned, uint8_t *, bool);
static int (*createContext)(void **);
static int (*deleteContext)(void *, bool);
static volatile uint32_t symbolsReady;
static uint32_t uuidMatched;
static uint32_t symbolMask;
static uint32_t initializationStages;
static NativeCredentialStudyAPI studyAPI {};
static bool availabilityRestorePending;
static bool studyReady;
static NativeProviderState providerState {};
static NativeProviderAPI providerAPI {};
static NativeEnrollmentAPI enrollmentAPI {};
static OSObject *providerOwner;
static IOLock *providerLock;
static NativePlatformProcess providerPlatform;
static NativePlatformProcess settingsPlatform;
static const uint8_t *globalContextHandle;
static const uint8_t *nullContextHandle;
static bool providerReady;

static const NativeEnvironmentSlot *availabilitySlot;
static const void *availabilityValidation;
static int (*findStudyCredential)(const void *, unsigned, void **);
static int (*getStudyProperty)(const void *, unsigned, const void **, size_t *);

static int emptyPrivateContext(const uint8_t *handle) {
    if (!globalContextHandle || !nullContextHandle || !memcmp(handle, globalContextHandle, 16) ||
        !memcmp(handle, nullContextHandle, 16)) return NativeProviderInvalid;
    void *borrowed = nullptr;
    int status = findStudyCredential(handle, 3, &borrowed);
    // On the pinned ACM image, -7 means an existing context has no credential of this type.
    return status == -7 && !borrowed ? 0 : status ? status : NativeProviderBusy;
}

static int privatePasswordContext(const uint8_t *handle, uint32_t *types) {
    *types = 0;
    if (!globalContextHandle || !nullContextHandle || !memcmp(handle, globalContextHandle, 16) ||
        !memcmp(handle, nullContextHandle, 16)) return NativeProviderInvalid;
    const unsigned credentials[] = {1, 10};
    for (unsigned i = 0; i < arrsize(credentials); i++) {
        void *borrowed = nullptr;
        int status = findStudyCredential(handle, credentials[i], &borrowed);
        if (status == -7 && !borrowed) continue;
        if (status) return status;
        if (!borrowed) return NativeStudyUnexpected;
        *types |= 1U << i;
    }
    return 0;
}

static int studyPreflight(bool withAvailability, uint32_t *valueWasPresent) {
    if (!studyReady || !availabilitySlot) return NativeStudyUnexpected;
    *valueWasPresent = availabilitySlot->data != nullptr;
    if (!withAvailability) return 0;
    uint32_t mismatches = nativeEnvironmentMismatches(*availabilitySlot, availabilityValidation, NativeBiometryProvider);
    return mismatches ? -static_cast<int>(30000U + mismatches) : 0;
}

static int studyReadProperty(void *context, unsigned type, unsigned property, void *output, size_t *length) {
    if (!context || type != 3 || !output || !length) return NativeStudyUnexpected;
    size_t expectedLength = property == 100 ? 16 : (property == 5 || property == 101) ? 4 : 0;
    if (!expectedLength || *length < expectedLength) return NativeStudyUnexpected;
    void *credential = nullptr;
    int status = findStudyCredential(context, type, &credential);
    if (status) return status;
    if (!credential) return NativeStudyUnexpected;
    const void *value = nullptr;
    size_t actual = 0;
    status = getStudyProperty(credential, property, &value, &actual);
    if (status) return status;
    if (!value || actual != expectedLength) return NativeStudyUnexpected;
    // The context owns this credential; copy while holding ACM's work loop.
    memcpy(output, value, actual);
    *length = actual;
    return 0;
}

static bool matchesUUID(mach_vm_address_t address, size_t size) {
    if (size < sizeof(mach_header_64)) return false;
    const auto *header = reinterpret_cast<const mach_header_64 *>(address);
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > size - sizeof(*header)) return false;
    size_t offset = sizeof(*header), end = offset + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (offset > end || end - offset < sizeof(load_command)) return false;
        const auto *command = reinterpret_cast<const load_command *>(address + offset);
        if (command->cmdsize < sizeof(*command) || command->cmdsize > end - offset) return false;
        if (command->cmd == LC_UUID && command->cmdsize == sizeof(uuid_command))
            return !memcmp(reinterpret_cast<const uuid_command *>(command)->uuid, expectedUUID, sizeof(expectedUUID));
        offset += command->cmdsize;
    }
    return false;
}

static void acmLoaded(void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
    if (index != acmInfo.loadIndex || __atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE)) return;
    __atomic_fetch_or(&initializationStages, ElanStageCallbackSeen, __ATOMIC_RELAXED);
    bool supported = matchesUUID(address, size);
    __atomic_store_n(&uuidMatched, supported ? 1U : 0U, __ATOMIC_RELAXED);
    if (!supported) { SYSLOG("native", "unsupported ACM image; probe disabled"); return; }
    const char *names[] = {"_Cred_GetPermissions", "_Env_GetVariableByte", "_ACMKernContextCreate", "_ACMKernContextDelete"};
    mach_vm_address_t functions[4] = {};
    for (unsigned i = 0; i < arrsize(names); i++) {
        functions[i] = patcher.solveSymbol(index, names[i]);
        patcher.clearError();
        if (functions[i] < address || functions[i] - address >= size) {
            SYSLOG("native", "required symbol %u unavailable", i);
            return;
        }
        __atomic_fetch_or(&symbolMask, 1U << i, __ATOMIC_RELAXED);
    }
    getPermissions = reinterpret_cast<decltype(getPermissions)>(functions[0]);
    getAvailability = reinterpret_cast<decltype(getAvailability)>(functions[1]);
    createContext = reinterpret_cast<decltype(createContext)>(functions[2]);
    deleteContext = reinterpret_cast<decltype(deleteContext)>(functions[3]);
    const char *studyNames[] = {
        "_LibCall_ACMCredentialCreate", "_LibCall_ACMCredentialDelete", "_LibCall_ACMCredentialSetProperty",
        "_addCredential", "_findCredentialHelper", "_ACMKernContextVerifyPolicyAndCopyRequirementEx",
        "_ACMKernRequirementDelete", "_Env_SetVariable", "__envTable", "_DataValidation_BiometryPresent",
        "_LibCall_ACMCredentialGetPropertyData"
    };
    mach_vm_address_t studyFunctions[arrsize(studyNames)] = {};
    bool complete = true;
    for (unsigned i = 0; i < arrsize(studyNames); i++) {
        studyFunctions[i] = patcher.solveSymbol(index, studyNames[i]);
        patcher.clearError();
        size_t required = i == 8 ? 7 * sizeof(NativeEnvironmentSlot) : 1;
        if (studyFunctions[i] < address || studyFunctions[i] - address > size ||
            required > size - (studyFunctions[i] - address)) complete = false;
    }
    if (complete) {
        findStudyCredential = reinterpret_cast<decltype(findStudyCredential)>(studyFunctions[4]);
        getStudyProperty = reinterpret_cast<decltype(getStudyProperty)>(studyFunctions[10]);
        studyAPI = {studyPreflight, getAvailability, reinterpret_cast<decltype(studyAPI.setAvailability)>(studyFunctions[7]),
                    createContext, deleteContext,
                    reinterpret_cast<decltype(studyAPI.createCredential)>(studyFunctions[0]),
                    reinterpret_cast<decltype(studyAPI.deleteCredential)>(studyFunctions[1]),
                    reinterpret_cast<decltype(studyAPI.setProperty)>(studyFunctions[2]),
                    reinterpret_cast<decltype(studyAPI.addCredential)>(studyFunctions[3]),
                    studyReadProperty,
                    reinterpret_cast<decltype(studyAPI.verifyPolicy)>(studyFunctions[5]),
                    reinterpret_cast<decltype(studyAPI.deleteRequirement)>(studyFunctions[6])};
        availabilitySlot = reinterpret_cast<const NativeEnvironmentSlot *>(studyFunctions[8]) + 6;
        availabilityValidation = reinterpret_cast<const void *>(studyFunctions[9]);
        studyReady = true;
        auto global = patcher.solveSymbol(index, "__globalCredSet"); patcher.clearError();
        auto nullHandle = patcher.solveSymbol(index, "__nullHandle"); patcher.clearError();
        if (global >= address && global - address <= size && size - (global - address) >= 16 &&
            nullHandle >= address && nullHandle - address <= size && size - (nullHandle - address) >= 16) {
            globalContextHandle = reinterpret_cast<const uint8_t *>(global);
            nullContextHandle = reinterpret_cast<const uint8_t *>(nullHandle);
            providerAPI = {studyAPI, emptyPrivateContext};
            enrollmentAPI = {studyAPI, privatePasswordContext};
            providerReady = NativePlatformProcess::initialize(patcher);
        }
    }
    __atomic_store_n(&symbolsReady, 1U, __ATOMIC_RELEASE);
    SYSLOG("native", "ACM diagnostic entrypoints ready");
}

class ELANNativeProbe : public IOService {
    OSDeclareDefaultStructors(ELANNativeProbe)
public:
    bool start(IOService *provider) override;
    IOReturn newUserClient(task_t task, void *securityID, UInt32 type, IOUserClient **handler) override;
    IOReturn collectReport(uint32_t selector, ElanNativeProbeReport *report);
    IOReturn collectStudy(uint32_t selector, NativeCredentialStudyReport *report);
    IOReturn providerOperation(OSObject *client, uint32_t selector, const void *input, void *output);
    void providerClosed(OSObject *client);
private:
    static IOReturn collectGated(OSObject *owner, void *selector, void *report, void *, void *);
    static IOReturn studyGated(OSObject *owner, void *selector, void *report, void *, void *);
    static IOReturn providerGated(OSObject *, void *selector, void *input, void *output, void *);
    IOReturn providerACM(uint32_t selector, const void *input, void *report);
};

class ELANNativeProbeClient : public IOUserClient {
    OSDeclareDefaultStructors(ELANNativeProbeClient)
public:
    IOReturn clientClose() override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                           IOExternalMethodDispatch *, OSObject *, void *) override;
};

OSDefineMetaClassAndStructors(ELANNativeProbe, IOService)
OSDefineMetaClassAndStructors(ELANNativeProbeClient, IOUserClient)

bool ELANNativeProbe::start(IOService *provider) {
    if (!IOService::start(provider)) return false;
    providerLock = IOLockAlloc();
    if (!providerLock) return false;
    setProperty("ProbeABI", ELAN_NATIVE_PROBE_ABI, 32);
    setProperty("ProbeVersion", xStringify(MODULE_VERSION));
    setProperty("LiluStarted", ADDPR(startSuccess));
    setProperty("AuthenticationEnabled", false);
    setProperty("ProviderSessionActive", false);
    registerService();
    SYSLOG("native", "diagnostic service published; Lilu started=%d", ADDPR(startSuccess));
    return true;
}

IOReturn ELANNativeProbeClient::clientClose() {
    auto *provider = OSDynamicCast(ELANNativeProbe, getProvider());
    if (provider) provider->providerClosed(this);
    terminate();
    return kIOReturnSuccess;
}

IOReturn ELANNativeProbe::newUserClient(task_t task, void *securityID, UInt32 type, IOUserClient **handler) {
    if (!handler || type != 0) return kIOReturnBadArgument;
    *handler = nullptr;
    if (kauth_cred_getuid(kauth_cred_get()) != 0) return kIOReturnNotPrivileged;
    auto *client = new ELANNativeProbeClient;
    if (!client) return kIOReturnNoMemory;
    if (!client->initWithTask(task, securityID, type)) { client->release(); return kIOReturnError; }
    if (!client->attach(this)) { client->release(); return kIOReturnError; }
    if (!client->start(this)) { client->detach(this); client->release(); return kIOReturnError; }
    *handler = client;
    return kIOReturnSuccess;
}

IOReturn ELANNativeProbeClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                             IOExternalMethodDispatch *, OSObject *, void *) {
    if (kauth_cred_getuid(kauth_cred_get()) != 0) return kIOReturnNotPrivileged;
    if (nativeProviderIsSelector(selector)) {
        size_t inputSize = nativeProviderInputSize(selector);
        size_t outputSize = nativeProviderOutputSize(selector);
        if (!arguments || arguments->scalarInputCount || arguments->scalarOutputCount ||
            arguments->structureInputDescriptor || arguments->structureOutputDescriptor ||
            arguments->structureInputSize != inputSize || (inputSize && !arguments->structureInput) ||
            !arguments->structureOutput || arguments->structureOutputSize != outputSize) return kIOReturnBadArgument;
        auto *provider = OSDynamicCast(ELANNativeProbe, getProvider());
        if (!provider || isInactive()) return kIOReturnNotAttached;
        // Copy input before acquiring either work-loop or process-map state.
        NativeProviderInput input {};
        NativeProviderOutput output {};
        if (inputSize) memcpy(&input, arguments->structureInput, inputSize);
        IOReturn status = provider->providerOperation(this, selector, inputSize ? &input : nullptr, &output);
        memcpy(arguments->structureOutput, &output, outputSize);
        arguments->structureOutputSize = static_cast<uint32_t>(outputSize);
        return status;
    }
    bool study = selector >= ElanProbeCredentialStudy && selector <= ElanProbeRestoreAvailability;
    size_t outputSize = study ? sizeof(NativeCredentialStudyReport) : sizeof(ElanNativeProbeReport);
    if (selector > ElanProbeRestoreAvailability || !arguments || arguments->scalarInputCount ||
        arguments->structureInputSize || arguments->structureInputDescriptor || arguments->scalarOutputCount ||
        arguments->structureOutputDescriptor || !arguments->structureOutput ||
        arguments->structureOutputSize != outputSize) return kIOReturnBadArgument;
    auto *provider = OSDynamicCast(ELANNativeProbe, getProvider());
    if (!provider || isInactive()) return kIOReturnNotAttached;
    if (study) {
        NativeCredentialStudyReport report {};
        IOReturn status = provider->collectStudy(selector, &report);
        memcpy(arguments->structureOutput, &report, sizeof(report));
        arguments->structureOutputSize = sizeof(report);
        return status;
    }
    ElanNativeProbeReport report {};
    IOReturn status = provider->collectReport(selector, &report);
    memcpy(arguments->structureOutput, &report, sizeof(report));
    arguments->structureOutputSize = sizeof(report);
    return status;
}

IOReturn ELANNativeProbe::collectReport(uint32_t selector, ElanNativeProbeReport *report) {
    report->abi = ELAN_NATIVE_PROBE_ABI;
    report->ready = __atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE);
    report->uuidMatched = __atomic_load_n(&uuidMatched, __ATOMIC_RELAXED);
    report->symbols = __atomic_load_n(&symbolMask, __ATOMIC_RELAXED);
    report->stages = __atomic_load_n(&initializationStages, __ATOMIC_RELAXED);
    if (ADDPR(startSuccess)) report->stages |= ElanStageLiluStarted;
    report->permissionsStatus = report->availabilityStatus = report->createStatus = report->deleteStatus = INT32_MIN;
    auto *matching = serviceMatching("AppleCredentialManager");
    if (!matching) return kIOReturnNoMemory;
    IOService *acm = copyMatchingService(matching);
    matching->release();
    if (acm) report->stages |= ElanStageACMPresent;
    IOWorkLoop *workLoop = acm ? acm->getWorkLoop() : nullptr;
    if (workLoop) report->stages |= ElanStageWorkLoopPresent;
    IOReturn status = kIOReturnNotReady;
    if (report->ready && workLoop && ADDPR(startSuccess))
        status = workLoop->runAction(collectGated, this, reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), report);
    else if (selector == ElanProbeStatus) status = kIOReturnSuccess;
    if (acm) acm->release();
    return status;
}

IOReturn ELANNativeProbe::collectGated(OSObject *, void *rawSelector, void *rawReport, void *, void *) {
    auto *report = static_cast<ElanNativeProbeReport *>(rawReport);
    report->permissionsStatus = getPermissions(3, 1, &report->requiredPermissions);
    uint8_t availability = 0;
    report->availabilityStatus = getAvailability(0x2000000000000000ULL, 6, &availability, false);
    report->availability = availability;
    if (reinterpret_cast<uintptr_t>(rawSelector) == ElanProbeContextLifecycle) {
        void *context = nullptr;
        report->createStatus = createContext(&context);
        if (!report->createStatus && context) {
            report->contextsCreated = 1;
            report->deleteStatus = deleteContext(context, true);
            report->contextsDeleted = report->deleteStatus == 0;
        }
    }
    return kIOReturnSuccess;
}

IOReturn ELANNativeProbe::collectStudy(uint32_t selector, NativeCredentialStudyReport *report) {
    if (!__atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE) || !studyReady || !ADDPR(startSuccess))
        return kIOReturnNotReady;
    IOLockLock(providerLock);
    if (providerOwner || providerState.restorePending || providerState.quarantined || providerPlatform.attached() || settingsPlatform.attached()) {
        IOLockUnlock(providerLock); return kIOReturnBusy;
    }
    auto *matching = serviceMatching("AppleCredentialManager");
    if (!matching) { IOLockUnlock(providerLock); return kIOReturnNoMemory; }
    IOService *acm = copyMatchingService(matching);
    matching->release();
    IOWorkLoop *workLoop = acm ? acm->getWorkLoop() : nullptr;
    IOReturn status = workLoop ? workLoop->runAction(studyGated, this,
        reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), report) : kIOReturnNotReady;
    if (acm) acm->release();
    IOLockUnlock(providerLock);
    return status;
}

IOReturn ELANNativeProbe::providerACM(uint32_t selector, const void *input, void *report) {
    auto *matching = serviceMatching("AppleCredentialManager");
    if (!matching) return kIOReturnNoMemory;
    IOService *acm = copyMatchingService(matching);
    matching->release();
    IOWorkLoop *workLoop = acm ? acm->getWorkLoop() : nullptr;
    IOReturn status = workLoop ? workLoop->runAction(providerGated, this,
        reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), const_cast<void *>(input), report) : kIOReturnNotReady;
    if (acm) acm->release();
    return status;
}

IOReturn ELANNativeProbe::providerGated(OSObject *, void *rawSelector, void *input, void *output, void *) {
    uint32_t selector = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(rawSelector));
    if (selector == ElanProviderCatalogBegin || selector == ElanProviderCatalogReplace) {
        auto &report = *static_cast<NativeProviderCatalogReport *>(output);
        const auto &request = *static_cast<const NativeProviderCatalogRequest *>(input);
        report.provider.operationStatus = selector == ElanProviderCatalogBegin ?
            (availabilityRestorePending ? NativeProviderBusy : nativeProviderStartCatalog(providerAPI, providerState, request)) :
            nativeProviderReplaceCatalog(providerState, request);
        nativeProviderCatalogReport(providerAPI, providerState, report);
        return kIOReturnSuccess;
    }
    if (selector == ElanProviderAuthorizeEnrollment) {
        nativeAuthorizeEnrollment(enrollmentAPI, providerState, *static_cast<const NativeEnrollmentRequest *>(input),
                                  *static_cast<NativeEnrollmentReport *>(output));
        return kIOReturnSuccess;
    }
    auto &report = *static_cast<NativeProviderReport *>(output);
    if (selector == ElanProviderBegin)
        report.operationStatus = availabilityRestorePending ? NativeProviderBusy :
            nativeProviderStart(providerAPI, providerState, *static_cast<const NativeProviderRequest *>(input));
    else if (selector == ElanProviderMatch)
        nativeProviderSubmit(providerAPI, providerState, *static_cast<const NativeProviderRequest *>(input), report);
    else if (selector == ElanProviderEnd)
        report.operationStatus = report.restoreStatus = nativeProviderStop(providerAPI, providerState);
    else return kIOReturnBadArgument;
    nativeProviderReport(providerAPI, providerState, report);
    return kIOReturnSuccess;
}

IOReturn ELANNativeProbe::providerOperation(OSObject *client, uint32_t selector, const void *input, void *output) {
    if (!__atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE) || !providerReady || !ADDPR(startSuccess))
        return kIOReturnNotReady;
    IOLockLock(providerLock);
    IOReturn result = kIOReturnSuccess;
    if (providerOwner && providerOwner != client) result = kIOReturnBusy;
    else if (selector == ElanProviderBegin || selector == ElanProviderCatalogBegin) {
        if (providerOwner || providerPlatform.attached() || settingsPlatform.attached()) result = kIOReturnBusy;
        else {
            result = providerACM(selector, input, output);
            if (providerState.active || providerState.restorePending) providerOwner = client;
        }
    } else if (selector == ElanProviderMatch || selector == ElanProviderCatalogReplace || selector == ElanProviderAuthorizeEnrollment) {
        if (providerOwner != client) result = kIOReturnNotOpen;
        else result = providerACM(selector, input, output);
    } else if (selector == ElanProviderEnd) {
        result = providerACM(selector, nullptr, static_cast<NativeProviderReport *>(output));
        int restored = providerPlatform.restore();
        int settingsRestored = settingsPlatform.restore();
        auto *report = static_cast<NativeProviderReport *>(output);
        if (!report->restoreStatus) report->restoreStatus = restored;
        if (!report->restoreStatus) report->restoreStatus = settingsRestored;
        if (!providerState.restorePending && !providerState.quarantined && !providerPlatform.attached() && !settingsPlatform.attached()) providerOwner = nullptr;
    } else if (selector == ElanProviderPlatformEnable || selector == ElanProviderPlatformRestore) {
        int status = NativeProviderNotActive;
        if (selector == ElanProviderPlatformRestore) status = providerPlatform.restore();
        else if (providerOwner == client && providerState.active)
            status = providerPlatform.enable(*static_cast<const NativePlatformProcessRequest *>(input));
        providerPlatform.report(status, *static_cast<NativePlatformProcessReport *>(output));
    } else if (selector == ElanProviderSettingsEnable || selector == ElanProviderSettingsRestore) {
        int status = NativeProviderNotActive;
        if (selector == ElanProviderSettingsRestore) status = settingsPlatform.restore();
        else if (providerOwner == client && providerState.active)
            status = settingsPlatform.enableSettings(*static_cast<const NativeSettingsProcessRequest *>(input));
        settingsPlatform.report(status, *static_cast<NativePlatformProcessReport *>(output));
    } else result = kIOReturnBadArgument;
    setProperty("ProviderSessionActive", providerState.active);
    setProperty("ProviderRestorePending", providerState.restorePending || providerState.quarantined || providerPlatform.pending() || settingsPlatform.pending());
    IOLockUnlock(providerLock);
    return result;
}

void ELANNativeProbe::providerClosed(OSObject *client) {
    if (!providerLock) return;
    IOLockLock(providerLock);
    if (providerOwner == client) {
        NativeProviderReport report {};
        IOReturn stopped = providerACM(ElanProviderEnd, nullptr, &report);
        int restored = providerPlatform.restore();
        int settingsRestored = settingsPlatform.restore();
        providerOwner = nullptr;
        setProperty("ProviderSessionActive", providerState.active);
        setProperty("ProviderRestorePending", providerState.restorePending || providerState.quarantined || providerPlatform.pending() || settingsPlatform.pending());
        if (stopped || report.restoreStatus || restored || settingsRestored)
            SYSLOG("native", "provider cleanup pending: call=0x%x ACM=%d platform=%d settings=%d", stopped, report.restoreStatus, restored, settingsRestored);
    }
    IOLockUnlock(providerLock);
}

IOReturn ELANNativeProbe::studyGated(OSObject *, void *rawSelector, void *rawReport, void *, void *) {
    auto *report = static_cast<NativeCredentialStudyReport *>(rawReport);
    uint32_t selector = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(rawSelector));
    if (selector == ElanProbeRestoreAvailability) {
        report->abi = 1;
        report->restoreStatus = 0;
        if (availabilityRestorePending) {
            uint8_t unavailable = 0;
            report->availabilityWriteAttempted = 1;
            report->restoreStatus = studyAPI.setAvailability(NativeBiometryProvider, 6, &unavailable, sizeof(unavailable));
        }
        uint8_t after = 0xff;
        report->readbackStatus = getAvailability(NativeEnvironmentReader, 6, &after, false);
        report->availabilityAfter = after;
        if (!report->restoreStatus && !report->readbackStatus && after == 0) availabilityRestorePending = false;
        report->availabilityRestorePending = availabilityRestorePending;
        report->passed = !report->restoreStatus && !report->readbackStatus && !availabilityRestorePending;
    } else {
        runNativeCredentialStudy(studyAPI, selector == ElanProbePolicyStudy, availabilityRestorePending, *report);
    }
    return kIOReturnSuccess;
}

static const char *disableArgs[] = {"-elannativeoff"};
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME), parseModuleVersion(xStringify(MODULE_VERSION)), LiluAPI::AllowNormal,
    disableArgs, arrsize(disableArgs), nullptr, 0, nullptr, 0,
    KernelVersion::Sequoia, KernelVersion::Sequoia,
    []() {
        __atomic_fetch_or(&initializationStages, ElanStagePluginEntered, __ATOMIC_RELAXED);
        auto error = lilu.onKextLoad(&acmInfo, 1, acmLoaded);
        if (error != LiluAPI::Error::NoError) {
            ADDPR(startSuccess) = false;
            SYSLOG("native", "ACM callback registration failed: %d", static_cast<int>(error));
        } else __atomic_fetch_or(&initializationStages, ElanStageCallbackRegistered, __ATOMIC_RELAXED);
    }
};
