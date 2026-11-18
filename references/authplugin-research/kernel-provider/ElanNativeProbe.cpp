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
#include "NativePasswordPrincipal.h"
#include "NativePasswordPrincipalProfile.h"
#include "NativePlatformProcess.h"
#include "../agent-integration-candidate/startup-retirement/PatcherBootstrap.h"
#include "NativeStartupObserverKernel.h"
#include "NativeOperationGate.h"
#include "NativeStartupTrialState.h"
#include <libkern/c++/OSSymbol.h>

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
static NativeOperationGate providerGate;
static NativeStartupTrialState startupTrial;
static OSObject *startupLeaseOwner;
static bool startupTrialRecoveryPending;
static bool startupTrialCommitted;
static OSObject *startupRecoveryOwner;
static NativePlatformProcess providerPlatform;
static NativePlatformProcess settingsPlatform;
static const uint8_t *globalContextHandle;
static const uint8_t *nullContextHandle;
static bool providerReady;
static uint32_t readinessStage, readinessFailure, retirementReady, platformReady;

static void publishReadinessProperties(IOService *service) {
    if (!service) return;
    service->setProperty("NativeReadinessStage", __atomic_load_n(&readinessStage, __ATOMIC_ACQUIRE), 32);
    service->setProperty("NativeReadinessFailure", __atomic_load_n(&readinessFailure, __ATOMIC_ACQUIRE), 32);
    service->setProperty("NativeRetirementReady", __atomic_load_n(&retirementReady, __ATOMIC_ACQUIRE), 32);
    service->setProperty("NativePlatformReady", __atomic_load_n(&platformReady, __ATOMIC_ACQUIRE), 32);
    service->setProperty("NativeProviderReady", __atomic_load_n(&readinessStage, __ATOMIC_ACQUIRE) == 8);
}
struct PublishReadinessOnExit {
    ~PublishReadinessOnExit() {
        auto *matching = IOService::serviceMatching(ELAN_NATIVE_PROBE_SERVICE);
        auto *service = matching ? IOService::copyMatchingService(matching) : nullptr;
        if (matching) matching->release();
        if (service) { publishReadinessProperties(service); service->release(); }
    }
};

static const NativeEnvironmentSlot *availabilitySlot;
static const void *availabilityValidation;
static int (*findStudyCredential)(const void *, unsigned, void **);
static int (*copyStudyCredentials)(const void *, unsigned, unsigned, void ***, unsigned *);
static void (*deallocStudyCredentials)(void **, unsigned);
static int (*getStudyProperty)(const void *, unsigned, const void **, size_t *);

static int emptyPrivateContext(const uint8_t *handle) {
    if (!globalContextHandle || !nullContextHandle || !memcmp(handle, globalContextHandle, 16) ||
        !memcmp(handle, nullContextHandle, 16)) return NativeProviderInvalid;
    void *borrowed = nullptr;
    int status = findStudyCredential(handle, 3, &borrowed);
    // On the pinned ACM image, -7 means an existing context has no credential of this type.
    return status == -7 && !borrowed ? 0 : status ? status : NativeProviderBusy;
}

static int privatePasswordContext(const uint8_t *handle, uint32_t expectedUser,
                                  uint32_t *types, uint32_t *principalTypes, NativeEnrollmentDiagnostic *diagnostic) {
    *types = 0; *principalTypes = 0;
    if (!globalContextHandle || !nullContextHandle || !memcmp(handle, globalContextHandle, 16) ||
        !memcmp(handle, nullContextHandle, 16)) { diagnostic->rejectKind=NativeEnrollmentContext; return NativeProviderInvalid; }
    return nativePasswordPrincipals({copyStudyCredentials, deallocStudyCredentials, getStudyProperty}, handle,
                                    expectedUser, types, principalTypes, diagnostic);
}

#ifdef ELAN_DIRECT_ENROLLMENT
#include "NativeDirectEnrollmentClient.inc"
#endif

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
    PublishReadinessOnExit publishOnExit;
    __atomic_store_n(&readinessStage, 1U, __ATOMIC_RELEASE);
    __atomic_fetch_or(&initializationStages, ElanStageCallbackSeen, __ATOMIC_RELAXED);
    bool supported = matchesUUID(address, size);
    __atomic_store_n(&uuidMatched, supported ? 1U : 0U, __ATOMIC_RELAXED);
    if (!supported) { __atomic_store_n(&readinessFailure, 1U, __ATOMIC_RELEASE); SYSLOG("native", "unsupported ACM image; probe disabled"); return; }
    __atomic_store_n(&readinessStage, 2U, __ATOMIC_RELEASE);
    const char *names[] = {"_Cred_GetPermissions", "_Env_GetVariableByte", "_ACMKernContextCreate", "_ACMKernContextDelete"};
    mach_vm_address_t functions[4] = {};
    for (unsigned i = 0; i < arrsize(names); i++) {
        functions[i] = patcher.solveSymbol(index, names[i]);
        patcher.clearError();
        if (functions[i] < address || functions[i] - address >= size) {
            __atomic_store_n(&readinessFailure, 2U, __ATOMIC_RELEASE);
            SYSLOG("native", "required symbol %u unavailable", i);
            return;
        }
        __atomic_fetch_or(&symbolMask, 1U << i, __ATOMIC_RELAXED);
    }
    getPermissions = reinterpret_cast<decltype(getPermissions)>(functions[0]);
    getAvailability = reinterpret_cast<decltype(getAvailability)>(functions[1]);
    createContext = reinterpret_cast<decltype(createContext)>(functions[2]);
    deleteContext = reinterpret_cast<decltype(deleteContext)>(functions[3]);
    __atomic_store_n(&readinessStage, 3U, __ATOMIC_RELEASE);
    const char *studyNames[] = {
        "_LibCall_ACMCredentialCreate", "_LibCall_ACMCredentialDelete", "_LibCall_ACMCredentialSetProperty",
        "_addCredential", "_findCredentialHelper", "_ACMKernContextVerifyPolicyAndCopyRequirementEx",
        "_ACMKernRequirementDelete", "_Env_SetVariable", "__envTable", "_DataValidation_BiometryPresent",
        "_LibCall_ACMCredentialGetPropertyData", "_CopyCredentials", "_DeallocCredentialList"
    };
    mach_vm_address_t studyFunctions[arrsize(studyNames)] = {};
    bool complete = true;
    for (unsigned i = 0; i < arrsize(studyNames); i++) {
        studyFunctions[i] = patcher.solveSymbol(index, studyNames[i]);
        patcher.clearError();
        size_t required = i == 8 ? 7 * sizeof(NativeEnvironmentSlot) :
                          i == 11 ? sizeof(NativeCopyCredentialsProfile) :
                          i == 12 ? sizeof(NativeDeallocCredentialListProfile) : 1;
        if (studyFunctions[i] < address || studyFunctions[i] - address > size ||
            required > size - (studyFunctions[i] - address)) complete = false;
    }
    if (complete && (memcmp(reinterpret_cast<const void *>(studyFunctions[11]), NativeCopyCredentialsProfile, sizeof(NativeCopyCredentialsProfile)) ||
                     memcmp(reinterpret_cast<const void *>(studyFunctions[12]), NativeDeallocCredentialListProfile, sizeof(NativeDeallocCredentialListProfile)))) complete = false;
    if (!complete) __atomic_store_n(&readinessFailure, 3U, __ATOMIC_RELEASE);
    if (complete) {
        __atomic_store_n(&readinessStage, 4U, __ATOMIC_RELEASE);
        findStudyCredential = reinterpret_cast<decltype(findStudyCredential)>(studyFunctions[4]);
        getStudyProperty = reinterpret_cast<decltype(getStudyProperty)>(studyFunctions[10]);
        copyStudyCredentials = reinterpret_cast<decltype(copyStudyCredentials)>(studyFunctions[11]);
        deallocStudyCredentials = reinterpret_cast<decltype(deallocStudyCredentials)>(studyFunctions[12]);
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
#ifdef ELAN_DIRECT_ENROLLMENT
            prepareDirectEnrollment(patcher);
#endif
            __atomic_store_n(&readinessStage, 5U, __ATOMIC_RELEASE);
#ifndef ELAN_AUTOMATIC_SETTINGS
            bool retirement = RetirementRuntime::configureFromPatcher(patcher);
            __atomic_store_n(&retirementReady, retirement ? 1U : 0U, __ATOMIC_RELEASE);
            if (!retirement) __atomic_store_n(&readinessFailure, 5U, __ATOMIC_RELEASE);
            else {
                __atomic_store_n(&readinessStage, 6U, __ATOMIC_RELEASE);
                bool platform = NativePlatformProcess::initialize(patcher);
                __atomic_store_n(&platformReady, platform ? 1U : 0U, __ATOMIC_RELEASE);
                if (!platform) __atomic_store_n(&readinessFailure, 6U, __ATOMIC_RELEASE);
                else __atomic_store_n(&readinessStage, 7U, __ATOMIC_RELEASE);
                providerReady = platform;
            }
#endif
        } else {
            __atomic_store_n(&readinessFailure, 4U, __ATOMIC_RELEASE);
        }
    }
    __atomic_store_n(&symbolsReady, 1U, __ATOMIC_RELEASE);
    if (providerReady) __atomic_store_n(&readinessStage, 8U, __ATOMIC_RELEASE);
    SYSLOG("native", "ACM diagnostic entrypoints ready");
}

#ifdef ELAN_AUTOMATIC_SETTINGS
uint64_t elanSettingsStartupDiagnostic();
uint32_t elanSettingsStartupAttempts();
uint32_t elanSettingsStartupRouted();
#endif
class ELANNativeProbe : public IOService {
    OSDeclareDefaultStructors(ELANNativeProbe)
public:
    bool start(IOService *provider) override;
#ifdef ELAN_AUTOMATIC_SETTINGS
    bool serializeProperties(OSSerialize *output) const override;
#endif
    IOReturn newUserClient(task_t task, void *securityID, UInt32 type, IOUserClient **handler) override;
    IOReturn collectReport(uint32_t selector, ElanNativeProbeReport *report);
    IOReturn collectStudy(OSObject *client, uint32_t selector, NativeCredentialStudyReport *report);
    IOReturn providerOperation(OSObject *client, uint32_t selector, const void *input, void *output);
    void providerClosed(OSObject *client);
    IOReturn callPlatformFunction(const OSSymbol *, bool, void *, void *, void *, void *) override;
    IOReturn startupTrialLease(NativeStartupTrialLeaseRequest &);
    IOReturn startupTrialArm(OSObject *, const NativeStartupTrialRequest &, NativeStartupTrialReport &);
    IOReturn startupTrialCancel(OSObject *, const NativeStartupTrialRequest &, NativeStartupTrialReport &);
private:
    static IOReturn collectGated(OSObject *owner, void *selector, void *report, void *, void *);
    static IOReturn studyGated(OSObject *owner, void *selector, void *report, void *, void *);
    static IOReturn providerGated(OSObject *, void *selector, void *input, void *output, void *);
    IOReturn providerACM(uint32_t selector, const void *input, void *report);
    IOReturn providerRun(OSObject *client, uint32_t selector, const void *input, void *output, bool study);
    IOReturn providerDispatch(OSObject *client, uint32_t selector, const void *input, void *output);
    IOReturn providerStudy(uint32_t selector, NativeCredentialStudyReport *report);
    void providerCleanup();
    void providerPublish();
};

static int nativeRetireCommittedSettings(NativeStartupTrialReport &report) {
    if (!startupTrialCommitted) { report = {1, 0, 0, 0, 0, 0, 0}; return 0; }
    report = {1, NativeProviderNotActive, 0, 0, 0, 1, 0};
    auto *matching = IOService::serviceMatching(NativeStartupTrialWriterService);
    IOService *writer = matching ? IOService::copyMatchingService(matching) : nullptr;
    if (matching) matching->release();
    if (!writer) return NativeProviderNotActive;
    auto *name = OSSymbol::withCString(NativeStartupTrialRetireFunction);
    IOReturn result = name ? writer->callPlatformFunction(name, false, &report, nullptr, nullptr, nullptr) : kIOReturnNoMemory;
    if (name) name->release();
    writer->release();
    bool clean = !result && report.abi == 1 && !report.status && !report.armed && !report.inFlight && !report.recoveryRequired;
    if (!clean) { report.recoveryRequired = 1; if (!report.status) report.status = NativeProviderBusy; }
    if (clean) startupTrialCommitted = false;
    return clean ? 0 : NativeProviderBusy;
}

#include "NativeProviderOperationLifecycle.h"

OSDefineMetaClassAndStructors(ELANNativeProbe, IOService)
#ifdef ELAN_AUTOMATIC_SETTINGS
bool ELANNativeProbe::serializeProperties(OSSerialize *output) const {
    // Allocate registry values only on a registry read, never in the startup hook.
    auto *service=const_cast<ELANNativeProbe *>(this);
    service->setProperty("SettingsStartupDiagnostic",elanSettingsStartupDiagnostic(),64);
    service->setProperty("SettingsStartupAttempts",elanSettingsStartupAttempts(),32);
    service->setProperty("SettingsStartupRouted",elanSettingsStartupRouted(),32);
    service->setProperty("SettingsStartupEnabled",elanSettingsStartupAvailable());
#ifdef ELAN_DIRECT_ENROLLMENT
    const uint64_t word=directEnrollmentDiagnostic.snapshot();
    const auto enrollment=NativeEnrollmentDiagnostics::decode(word);
    service->setProperty("EnrollmentDiagnostic",word,64);
    service->setProperty("EnrollmentObserved",enrollment.observed);
    service->setProperty("EnrollmentOperationStatus",enrollment.operationStatus,32);
    service->setProperty("EnrollmentRejectKind",enrollment.rejectKind,32);
    service->setProperty("EnrollmentPasswordTypes",enrollment.passwordTypes,32);
    service->setProperty("EnrollmentPrincipalTypes",enrollment.principalTypes,32);
    service->setProperty("EnrollmentOwnerPolicy",enrollment.ownerPolicy);
    service->setProperty("EnrollmentAuthorized",enrollment.authorized);
#endif
    return IOService::serializeProperties(output);
}
#endif

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
    setProperty("ProviderRestorePending", false);
    publishReadinessProperties(this);
    registerService();
    SYSLOG("native", "diagnostic service published; Lilu started=%d", ADDPR(startSuccess));
    return true;
}

IOReturn ELANNativeProbe::callPlatformFunction(const OSSymbol *name, bool wait, void *p1, void *p2, void *p3, void *p4) {
#ifdef ELAN_AUTOMATIC_SETTINGS
    return IOService::callPlatformFunction(name, wait, p1, p2, p3, p4);
#else
    if (!name || !name->isEqualTo(NativeStartupTrialLeaseFunction))
        return IOService::callPlatformFunction(name, wait, p1, p2, p3, p4);
    if (wait || !p1 || p2 || p3 || p4) return kIOReturnBadArgument;
    return startupTrialLease(*static_cast<NativeStartupTrialLeaseRequest *>(p1));
#endif
}

IOReturn ELANNativeProbe::newUserClient(task_t task, void *securityID, UInt32 type, IOUserClient **handler) {
    if (!handler) return kIOReturnBadArgument;
    *handler = nullptr;
#ifdef ELAN_DIRECT_ENROLLMENT
    if (type == ElanEnrollmentConnectionType)
        return ELANEnrollmentPolicyClient::open(this, task, securityID, handler);
#endif
#ifdef ELAN_AUTOMATIC_SETTINGS
    return kIOReturnUnsupported;
#else
    if (type != 0) return kIOReturnBadArgument;
    if (kauth_cred_getuid(kauth_cred_get()) != 0) return kIOReturnNotPrivileged;
    auto *client = new ELANNativeProbeClient;
    if (!client) return kIOReturnNoMemory;
    if (!client->initWithTask(task, securityID, type)) { client->release(); return kIOReturnError; }
    if (!client->attach(this)) { client->release(); return kIOReturnError; }
    if (!client->start(this)) { client->detach(this); client->release(); return kIOReturnError; }
    *handler = client;
    return kIOReturnSuccess;
#endif
}

IOReturn ELANNativeProbeClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                             IOExternalMethodDispatch *, OSObject *, void *) {
    if (isClosing()) return kIOReturnNotAttached;
    if (kauth_cred_getuid(kauth_cred_get()) != 0) return kIOReturnNotPrivileged;
    if (selector == ElanProbeReadiness) {
        if (!arguments || arguments->scalarInputCount || arguments->scalarOutputCount ||
            arguments->structureInputSize || arguments->structureInputDescriptor || arguments->structureOutputDescriptor ||
            !arguments->structureOutput || arguments->structureOutputSize != sizeof(NativeReadinessReport)) return kIOReturnBadArgument;
        NativeReadinessReport report {};
        report.abi = 1;
        report.stage = __atomic_load_n(&readinessStage, __ATOMIC_ACQUIRE);
        report.failure = __atomic_load_n(&readinessFailure, __ATOMIC_ACQUIRE);
        report.symbolsReady = __atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE);
        report.providerReady = report.stage == 8;
        report.liluStarted = ADDPR(startSuccess) ? 1U : 0U;
        report.retirementReady = __atomic_load_n(&retirementReady, __ATOMIC_ACQUIRE);
        report.platformReady = __atomic_load_n(&platformReady, __ATOMIC_ACQUIRE);
        if (!providerLock) report.gateBusy = 1;
        else {
            IOLockLock(providerLock);
            report.gateBusy = providerGate.snapshot().active;
            if (!report.gateBusy) {
                report.sessionActive = providerState.active;
                report.restorePending = startupTrialRecoveryPending || availabilityRestorePending || providerState.restorePending || providerState.quarantined || providerGate.snapshot().recoveryOnly;
                report.ownerPresent = providerOwner != nullptr;
                report.platformAttached = providerPlatform.attached();
                report.settingsAttached = settingsPlatform.attached();
                report.trialCommitted = startupTrialCommitted;
            }
            IOLockUnlock(providerLock);
        }
        memcpy(arguments->structureOutput, &report, sizeof(report));
        arguments->structureOutputSize = sizeof(report);
        return kIOReturnSuccess;
    }
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
        IOReturn status = provider->collectStudy(this, selector, &report);
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
    if (selector == ElanProviderStartupTrialArm) {
        auto &report = *static_cast<NativeStartupTrialReport *>(output);
        uint8_t availability = 0;
        int status = getAvailability(0x2000000000000000ULL, 6, &availability, false);
        report = {1, status ? status : availability == 1 ? 0 : NativeProviderNotActive, 0, 0, 0, 0, 0};
        return kIOReturnSuccess;
    }
    if (selector == ElanProviderCatalogBegin || selector == ElanProviderCatalogReplace) {
        auto &report = *static_cast<NativeProviderCatalogReport *>(output);
        const auto &request = *static_cast<const NativeProviderCatalogRequest *>(input);
        report.provider.operationStatus = selector == ElanProviderCatalogBegin ?
            (availabilityRestorePending ? NativeProviderBusy : nativeProviderStartCatalog(providerAPI, providerState, request)) :
            nativeProviderReplaceCatalog(providerState, request);
        nativeProviderCatalogReport(providerAPI, providerState, report);
        // ABI contract: callback execution always returns IO success; business
        // failures are in the report, never IO NotReady.
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
        // Only the official EXEC notification counter is wired here.
        // No private routes or process-memory observation are enabled.
        NativeStartupObserverKernel::start(NativeStartupObserverKernel::RuntimeEnabled);
#ifdef ELAN_AUTOMATIC_SETTINGS
        if (!elanRegisterSettingsStartup()) SYSLOG("settings","startup registration unavailable");
#endif
        auto error = lilu.onKextLoad(&acmInfo, 1, acmLoaded);
        if (error != LiluAPI::Error::NoError) {
            ADDPR(startSuccess) = false;
            SYSLOG("native", "ACM callback registration failed: %d", static_cast<int>(error));
        } else __atomic_fetch_or(&initializationStages, ElanStageCallbackRegistered, __ATOMIC_RELAXED);
    }
};
