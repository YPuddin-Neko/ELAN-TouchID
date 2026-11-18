#pragma once

class ELANNativeProbeClient : public IOUserClient {
    OSDeclareDefaultStructors(ELANNativeProbeClient)
    volatile uint32_t closing = 0;
public:
    bool isClosing() const { return __atomic_load_n(&closing, __ATOMIC_ACQUIRE) != 0; }
    void beginClose() { __atomic_store_n(&closing, 1U, __ATOMIC_RELEASE); }
    IOReturn clientClose() override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                           IOExternalMethodDispatch *, OSObject *, void *) override;
};

class NativeProviderOperationReferences {
    OSObject *provider;
    OSObject *client;
public:
    NativeProviderOperationReferences(OSObject *p, OSObject *c) : provider(p), client(c) {
        if (provider) provider->retain();
        if (client) client->retain();
    }
    ~NativeProviderOperationReferences() {
        if (client) client->release();
        if (provider) provider->release();
    }
    NativeProviderOperationReferences(const NativeProviderOperationReferences &) = delete;
    NativeProviderOperationReferences &operator=(const NativeProviderOperationReferences &) = delete;
};

static bool nativeProviderStateClean() {
    return !startupTrialCommitted && !startupTrialRecoveryPending && !providerState.active && !providerState.restorePending && !providerState.quarantined &&
        !providerPlatform.attached() && !settingsPlatform.attached();
}
static bool nativeProviderRecoverySelector(uint32_t selector) {
    return selector == ElanProviderEnd || selector == ElanProviderPlatformRestore || selector == ElanProviderSettingsRestore || selector == ElanProviderCoreauthRetire || selector == ElanProviderStartupTrialRetire;
}
static bool nativeProviderFailedChange(uint32_t selector, const void *output) {
    if (selector == ElanProviderPlatformEnable)
        return static_cast<const NativePlatformProcessReport *>(output)->status && providerPlatform.pending();
    if (selector == ElanProviderSettingsEnable)
        return static_cast<const NativePlatformProcessReport *>(output)->status && settingsPlatform.pending();
    if (selector == ElanProviderSettingsRecover)
        return static_cast<const NativeSettingsRecoveryReport *>(output)->transactionStatus && settingsPlatform.pending();
    return false;
}

IOReturn ELANNativeProbeClient::clientClose() {
    beginClose();
    NativeProviderOperationReferences references(nullptr, this);
    auto *provider = OSDynamicCast(ELANNativeProbe, getProvider());
    if (provider) provider->providerClosed(this);
    terminate();
    return kIOReturnSuccess;
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

void ELANNativeProbe::providerPublish() {
    setProperty("ProviderSessionActive", providerState.active);
    setProperty("ProviderRestorePending", startupTrialRecoveryPending || availabilityRestorePending || providerState.restorePending || providerState.quarantined || providerPlatform.pending() || settingsPlatform.pending());
}

void ELANNativeProbe::providerCleanup() {
    NativeStartupTrialReport trial {};
    if (nativeRetireCommittedSettings(trial)) {
        startupTrialRecoveryPending = true;
        // A failed close keeps raw providerOwner reachable; retain that exact
        // owner until recovery rather than exposing a released IOUserClient.
        if (!startupRecoveryOwner && providerOwner) {
            startupRecoveryOwner = static_cast<OSObject *>(providerOwner);
            startupRecoveryOwner->retain();
        }
        return;
    }
    NativeProviderReport report {};
    IOReturn stopped = providerACM(ElanProviderEnd, nullptr, &report);
    int restored = providerPlatform.restore();
    int settingsRestored = settingsPlatform.restore();
    providerOwner = nullptr;
    if (startupRecoveryOwner) { auto *owner = startupRecoveryOwner; startupRecoveryOwner = nullptr; owner->release(); }
    if (stopped || report.restoreStatus || restored || settingsRestored)
        SYSLOG("native", "provider cleanup pending: call=0x%x ACM=%d platform=%d settings=%d", stopped, report.restoreStatus, restored, settingsRestored);
}

IOReturn ELANNativeProbe::providerRun(OSObject *client, uint32_t selector, const void *input, void *output, bool study) {
    auto *nativeClient = OSDynamicCast(ELANNativeProbeClient, client);
    if (!nativeClient || !providerLock) return kIOReturnNotAttached;
    NativeProviderOperationReferences references(this, client);
    uint64_t identity = reinterpret_cast<uintptr_t>(client), token = 0;
    IOReturn result = kIOReturnBusy;
    IOLockLock(providerLock);
    if (nativeClient->isClosing()) result = kIOReturnNotAttached;
    // An active token owns all provider state, including providerOwner, outside this mutex.
    else if (!providerGate.snapshot().active) {
        if (study) {
            bool recovery = selector == ElanProbeRestoreAvailability;
            if (!providerOwner && nativeProviderStateClean() && (!availabilityRestorePending || recovery))
                token = providerGate.begin(identity, recovery);
        } else if (!providerOwner || providerOwner == client) {
            bool recovery = nativeProviderRecoverySelector(selector);
            bool continuing = providerOwner == client && providerState.active && !providerState.quarantined &&
                !providerGate.snapshot().recoveryOnly;
            if (!availabilityRestorePending || recovery)
                token = providerGate.begin(identity, recovery || continuing);
        }
    }
    if (token && selector != ElanProviderStartupTrialArm) startupTrial.invalidate(identity);
    if (token && !study && selector == ElanProviderEnd) providerGate.requireRecovery(token, identity);
    IOLockUnlock(providerLock);
    if (!token) return result;

    IOLockLock(providerLock);
    if (nativeClient->isClosing()) providerGate.ownerClosed(identity);
    bool proceed = providerGate.mayProceed(token, identity);
    IOLockUnlock(providerLock);
    result = proceed ? (study ? providerStudy(selector, static_cast<NativeCredentialStudyReport *>(output)) :
                              providerDispatch(client, selector, input, output)) : kIOReturnAborted;

    // Studies own no provider state and perform their own in-transaction rollback.
    bool cleaned = study || (proceed && selector == ElanProviderEnd && !startupTrialCommitted);
    bool recoveryRequired = proceed && !study && nativeProviderFailedChange(selector, output);
    bool cancellationHandled = false;
    for (;;) {
        IOLockLock(providerLock);
        if (recoveryRequired) providerGate.requireRecovery(token, identity);
        if (nativeClient->isClosing()) providerGate.ownerClosed(identity);
        bool cancelled = !providerGate.mayProceed(token, identity);
        IOLockUnlock(providerLock);
        if (cancelled) {
            if (!cleaned) { providerCleanup(); cleaned = true; }
            else if (!startupTrialCommitted) providerOwner = nullptr;
            result = kIOReturnAborted;
            cancellationHandled = true;
        }
        providerPublish();
        IOLockLock(providerLock);
        if (nativeClient->isClosing()) providerGate.ownerClosed(identity);
        // Close during dispatch or publication belongs to this token. After finish,
        // close can reserve a separate cleanup token for the committed session.
        if (!cancellationHandled && !providerGate.mayProceed(token, identity)) {
            IOLockUnlock(providerLock);
            continue;
        }
        providerGate.finish(token, identity, nativeProviderStateClean() && !availabilityRestorePending);
        IOLockUnlock(providerLock);
        return result;
    }
}

IOReturn ELANNativeProbe::providerOperation(OSObject *client, uint32_t selector, const void *input, void *output) {
    if (!__atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE) || !providerReady || !ADDPR(startSuccess))
        return kIOReturnNotReady;
    if (!nativeProviderIsSelector(selector)) return kIOReturnBadArgument;
    if (selector == ElanProviderStartupTrialCancel)
        return startupTrialCancel(client, *static_cast<const NativeStartupTrialRequest *>(input), *static_cast<NativeStartupTrialReport *>(output));
    return providerRun(client, selector, input, output, false);
}

IOReturn ELANNativeProbe::collectStudy(OSObject *client, uint32_t selector, NativeCredentialStudyReport *report) {
    if (!__atomic_load_n(&symbolsReady, __ATOMIC_ACQUIRE) || !studyReady || !ADDPR(startSuccess))
        return kIOReturnNotReady;
    if (selector < ElanProbeCredentialStudy || selector > ElanProbeRestoreAvailability) return kIOReturnBadArgument;
    return providerRun(client, selector, nullptr, report, true);
}

IOReturn ELANNativeProbe::providerStudy(uint32_t selector, NativeCredentialStudyReport *report) {
    auto *matching = serviceMatching("AppleCredentialManager");
    if (!matching) return kIOReturnNoMemory;
    IOService *acm = copyMatchingService(matching);
    matching->release();
    IOWorkLoop *workLoop = acm ? acm->getWorkLoop() : nullptr;
    IOReturn status = workLoop ? workLoop->runAction(studyGated, this,
        reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), report) : kIOReturnNotReady;
    if (acm) acm->release();
    return status;
}

IOReturn ELANNativeProbe::providerDispatch(OSObject *client, uint32_t selector, const void *input, void *output) {
    IOReturn result = kIOReturnSuccess;
    if (selector == ElanProviderStartupTrialArm) {
        return startupTrialArm(client, *static_cast<const NativeStartupTrialRequest *>(input), *static_cast<NativeStartupTrialReport *>(output));
    }
    if (selector == ElanProviderBegin || selector == ElanProviderCatalogBegin) {
        if (providerOwner || providerPlatform.attached() || settingsPlatform.attached()) result = kIOReturnBusy;
        else {
            result = providerACM(selector, input, output);
            if (providerState.active || providerState.restorePending) providerOwner = client;
        }
    } else if (selector == ElanProviderMatch || selector == ElanProviderCatalogReplace || selector == ElanProviderAuthorizeEnrollment) {
        if (providerOwner != client) result = kIOReturnNotOpen;
        else result = providerACM(selector, input, output);
    } else if (selector == ElanProviderStartupTrialRetire) {
        auto &report = *static_cast<NativeStartupTrialReport *>(output);
        int status = nativeRetireCommittedSettings(report);
        if (status) startupTrialRecoveryPending = true;
        if (startupTrialRecoveryPending) { report.recoveryRequired = 1; if (!report.status) report.status = NativeProviderBusy; }
        return status || startupTrialRecoveryPending ? kIOReturnNotReady : kIOReturnSuccess;
    } else if (selector == ElanProviderCoreauthRetire) {
        int status = providerPlatform.retireExact();
        providerPlatform.report(status, *static_cast<NativePlatformProcessReport *>(output));
    } else if (selector == ElanProviderEnd) {
        NativeStartupTrialReport trial {};
        if (nativeRetireCommittedSettings(trial)) {
            startupTrialRecoveryPending = true;
            auto &report = *static_cast<NativeProviderReport *>(output);
            report = {}; report.abi = 1; report.operationStatus = report.restoreStatus = NativeProviderBusy;
            return kIOReturnNotReady;
        }
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
    } else if (selector == ElanProviderSettingsInspect) {
        auto &report = *static_cast<NativeSettingsInspectionReport *>(output);
        report = {2, NativeProviderNotActive, 0, 0, 0, {0, 0, 0}};
        if (providerOwner == client && providerState.active)
            settingsPlatform.inspectSettings(*static_cast<const NativeSettingsProcessRequest *>(input), report);
    } else if (selector == ElanProviderSettingsRecover) {
        auto &report = *static_cast<NativeSettingsRecoveryReport *>(output);
        report = {};
        int status = NativeProviderNotActive;
        if (providerOwner == client && providerState.active)
            status = settingsPlatform.recoverSettingsConnection(*static_cast<const NativeSettingsProcessRequest *>(input), &report);
        report.transactionStatus = status;
        settingsPlatform.report(status, report.platform);
    } else if (selector == ElanProviderSettingsEnable || selector == ElanProviderSettingsRestore) {
        int status = NativeProviderNotActive;
        if (selector == ElanProviderSettingsRestore) status = settingsPlatform.restore();
        else if (providerOwner == client && providerState.active)
            status = settingsPlatform.enableSettings(*static_cast<const NativeSettingsProcessRequest *>(input));
        settingsPlatform.report(status, *static_cast<NativePlatformProcessReport *>(output));
    } else result = kIOReturnBadArgument;
    return result;
}

void ELANNativeProbe::providerClosed(OSObject *client) {
    auto *nativeClient = OSDynamicCast(ELANNativeProbeClient, client);
    if (!nativeClient) return;
    nativeClient->beginClose();
    if (!providerLock) return;
    NativeProviderOperationReferences references(this, client);
    uint64_t identity = reinterpret_cast<uintptr_t>(client), token = 0;
    IOLockLock(providerLock);
    startupTrial.invalidate(identity);
    if (providerGate.snapshot().active) providerGate.ownerClosed(identity);
    else if (providerOwner == client) {
        token = providerGate.begin(identity, true);
        if (token) providerGate.requireRecovery(token, identity);
    }
    IOLockUnlock(providerLock);
    if (!token) return;
    providerCleanup();
    providerPublish();
    IOLockLock(providerLock);
    providerGate.finish(token, identity, nativeProviderStateClean() && !availabilityRestorePending);
    IOLockUnlock(providerLock);
}

#include "NativeStartupTrialLifecycle.h"
