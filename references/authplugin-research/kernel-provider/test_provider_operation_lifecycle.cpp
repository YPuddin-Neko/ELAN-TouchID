#include "ProviderOperationFixture.h"
#include "NativeProviderOperationLifecycle.h"
#include <initializer_list>

IOReturn ELANNativeProbeClient::externalMethod(uint32_t, IOExternalMethodArguments *, IOExternalMethodDispatch *, OSObject *, void *) { return 0; }

struct Fixture {
    ELANNativeProbe provider;
    ELANNativeProbeClient client, foreign;
    NativeProviderInput input {};
    NativeProviderOutput output {};
    Fixture() {
        assert(!providerGate.snapshot().active && !lockHeld);
        providerGate = {};
        providerState = {};
        providerOwner = nullptr;
        providerPlatform.seed(false); settingsPlatform.seed(false);
        callback = {}; events.clear();
        stopFails = mapFails = enableFails = recoverLeavesPending = missingMatching = missingService = missingWorkLoop = false;
        acmFailureSelector = -1;
        availabilityRestorePending = studyRestoreFails = false;
        providerReady = studyReady = startSuccess = true; symbolsReady = 1;
        acmCalls = stopCalls = mapCalls = studyCalls = 0;
        provider.label = "provider";
        client.label = "client"; foreign.label = "foreign";
        client.provider = foreign.provider = &provider;
    }
    ~Fixture() {
        callback = {};
        client.clientClose(); foreign.clientClose();
        assert(!providerGate.snapshot().active && !lockHeld);
        for (OSObject *object : {static_cast<OSObject *>(&provider), static_cast<OSObject *>(&client), static_cast<OSObject *>(&foreign)})
            assert(object->references == 1 && object->retains == object->releases);
        providerOwner = nullptr;
    }
    IOReturn call(uint32_t selector, ELANNativeProbeClient *who = nullptr) {
        return provider.providerOperation(who ? who : &client, selector,
            nativeProviderInputSize(selector) ? &input : nullptr, &output);
    }
    IOReturn study(uint32_t selector = ElanProbeCredentialStudy, ELANNativeProbeClient *who = nullptr) {
        NativeCredentialStudyReport report {};
        return provider.collectStudy(who ? who : &client, selector, &report);
    }
    void begin() {
        assert(call(ElanProviderBegin) == kIOReturnSuccess);
        assert(providerOwner == &client && providerGate.snapshot().pending && !providerGate.snapshot().recoveryOnly);
        events.clear(); acmCalls = stopCalls = mapCalls = 0;
    }
};
static unsigned scenarios;
static void checkReadOnlyReport(Fixture &f) {
    auto before = providerGate.snapshot();
    unsigned calls = acmCalls + mapCalls + studyCalls;
    bool previous = stateAccessAllowed;
    stateAccessAllowed = false;
    ElanNativeProbeReport report {};
    assert(f.provider.collectReport(ElanProbeStatus, &report) == kIOReturnSuccess);
    stateAccessAllowed = previous;
    auto after = providerGate.snapshot();
    assert(report.abi == ELAN_NATIVE_PROBE_ABI && !report.permissionsStatus && !report.availabilityStatus);
    assert(calls == acmCalls + mapCalls + studyCalls && before.active == after.active && before.pending == after.pending &&
        before.recoveryOnly == after.recoveryOnly);
}
static void checkReentry(Fixture &f) {
    assert(f.provider.references >= 2 && f.client.references >= 2);
    bool previous = stateAccessAllowed;
    stateAccessAllowed = false;
    assert(f.call(ElanProviderMatch) == (f.client.isClosing() ? kIOReturnNotAttached : kIOReturnBusy));
    assert(f.call(ElanProviderMatch, &f.foreign) == kIOReturnBusy);
    assert(f.study(ElanProbePolicyStudy, &f.foreign) == kIOReturnBusy);
    checkReadOnlyReport(f);
    stateAccessAllowed = previous;
}

int main() {
    for (uint32_t selector = ElanProviderBegin; selector <= ElanProviderSettingsRecover; ++selector) {
        {
            Fixture f;
            IOReturn result = f.call(selector);
            bool ownerRequired = selector == ElanProviderMatch || selector == ElanProviderCatalogReplace || selector == ElanProviderAuthorizeEnrollment;
            assert(result == (ownerRequired ? kIOReturnNotOpen : kIOReturnSuccess));
            assert(!providerGate.snapshot().active); ++scenarios;
        }
        {
            Fixture f; f.begin();
            IOReturn result = f.call(selector);
            bool begin = selector == ElanProviderBegin || selector == ElanProviderCatalogBegin;
            assert(result == (begin ? kIOReturnBusy : kIOReturnSuccess));
            if (selector == ElanProviderSettingsRecover) assert(f.output.recovery.transactionStatus == -31004);
            if (selector == ElanProviderPlatformRestore || selector == ElanProviderSettingsRestore) {
                assert(!providerGate.snapshot().recoveryOnly && f.call(ElanProviderMatch) == 0);
            }
            assert(!providerGate.snapshot().active); ++scenarios;
        }
        {
            Fixture f; f.begin();
            assert(f.call(selector, &f.foreign) == kIOReturnBusy);
            assert(providerOwner == &f.client && !acmCalls && !mapCalls); ++scenarios;
        }
        {
            Fixture f; f.client.clientClose();
            assert(f.call(selector) == kIOReturnNotAttached && !acmCalls && !mapCalls); ++scenarios;
        }
        {
            Fixture f; providerState.restorePending = true;
            auto token = providerGate.begin(1); assert(token && providerGate.finish(token, 1, false));
            assert(f.call(selector) == (nativeProviderRecoverySelector(selector) ? kIOReturnSuccess : kIOReturnBusy));
            if (!nativeProviderRecoverySelector(selector)) assert(!acmCalls && !mapCalls); ++scenarios;
        }
    }
    {
        Fixture f; f.client.beginClose();
        assert(f.call(ElanProviderBegin) == kIOReturnNotAttached && !acmCalls);
        assert(f.study() == kIOReturnNotAttached); ++scenarios;
    }
    {
        Fixture f; bool closed = false;
        callback = [&](const std::string &name) {
            if (name == "unlock" && providerGate.snapshot().active && !closed) {
                closed = true; stateAccessAllowed = false; f.client.clientClose(); stateAccessAllowed = true;
            }
        };
        assert(f.call(ElanProviderBegin) == kIOReturnAborted);
        assert(closed && acmCalls == 1 && stopCalls == 1 && !providerOwner); ++scenarios;
    }
    for (uint32_t selector : {uint32_t(ElanProviderBegin), uint32_t(ElanProviderCatalogBegin), uint32_t(ElanProviderMatch),
                             uint32_t(ElanProviderCatalogReplace), uint32_t(ElanProviderAuthorizeEnrollment), uint32_t(ElanProviderEnd)}) {
        Fixture f;
        if (selector != ElanProviderBegin && selector != ElanProviderCatalogBegin) f.begin();
        bool closed = false;
        callback = [&](const std::string &name) {
            if (name == "acm-" + std::to_string(selector) && !closed) {
                closed = true; checkReentry(f);
                stateAccessAllowed = false; f.client.clientClose(); stateAccessAllowed = true;
            }
        };
        assert(f.call(selector) == kIOReturnAborted && closed);
        assert(stopCalls == 1);
        assert(!providerOwner && !providerGate.snapshot().pending);
        assert(f.call(ElanProviderBegin) == kIOReturnNotAttached); ++scenarios;
    }
    for (uint32_t selector : {uint32_t(ElanProviderPlatformEnable), uint32_t(ElanProviderPlatformRestore),
                             uint32_t(ElanProviderSettingsEnable), uint32_t(ElanProviderSettingsRestore),
                             uint32_t(ElanProviderSettingsInspect), uint32_t(ElanProviderSettingsRecover)}) {
        Fixture f; f.begin(); bool closed = false;
        callback = [&](const std::string &name) {
            if ((name.find("platform-") == 0 || name.find("settings-") == 0) && !closed) {
                closed = true; checkReentry(f);
                stateAccessAllowed = false; f.client.clientClose(); stateAccessAllowed = true;
            }
        };
        assert(f.call(selector) == kIOReturnAborted && closed && stopCalls == 1);
        assert(!providerOwner && !providerPlatform.attached() && !settingsPlatform.attached()); ++scenarios;
    }
    for (bool endRequest : {false, true}) {
        Fixture f; if (endRequest) f.begin();
        stopFails = true; bool closed = false;
        callback = [&](const std::string &name) {
            if (name == (endRequest ? "acm-7" : "acm-5") && !closed) { closed = true; f.client.clientClose(); }
        };
        assert(f.call(endRequest ? ElanProviderEnd : ElanProviderBegin) == kIOReturnAborted);
        assert(stopCalls == 1 && !providerOwner && providerGate.snapshot().pending && providerState.restorePending);
        callback = {}; stopFails = false;
        assert(f.call(ElanProviderEnd, &f.foreign) == 0 && !providerGate.snapshot().pending); ++scenarios;
    }
    {
        Fixture f; f.begin(); bool closed = false;
        callback = [&](const std::string &name) {
            if (name == "acm-7" && !closed) { closed = true; f.client.clientClose(); }
        };
        f.client.clientClose();
        assert(closed && stopCalls == 1 && !providerOwner && !providerGate.snapshot().pending); ++scenarios;
    }
    for (const std::string point : {"property-ProviderSessionActive", "property-ProviderRestorePending"}) {
        Fixture f; bool closed = false;
        callback = [&](const std::string &name) {
            if (name == point && !closed) { closed = true; f.client.clientClose(); }
        };
        assert(f.call(ElanProviderBegin) == kIOReturnAborted && closed && stopCalls == 1);
        assert(!providerOwner && !providerGate.snapshot().pending); ++scenarios;
    }
    for (const std::string point : {"unlock", "release-client"}) {
        Fixture f; bool closed = false;
        callback = [&](const std::string &name) {
            if (name == point && !providerGate.snapshot().active && providerOwner == &f.client && !closed) {
                closed = true; f.client.clientClose();
            }
        };
        assert(f.call(ElanProviderBegin) == kIOReturnSuccess && closed && stopCalls == 1);
        assert(!providerOwner && !providerGate.snapshot().pending);
        assert(f.call(ElanProviderBegin) == kIOReturnNotAttached); ++scenarios;
    }
    {
        Fixture f; bool closed = false;
        callback = [&](const std::string &name) {
            if (name == "acm-5" && !closed) {
                closed = true; checkReentry(f);
                stateAccessAllowed = false; f.foreign.clientClose(); stateAccessAllowed = true;
            }
        };
        assert(f.call(ElanProviderBegin) == kIOReturnSuccess && closed && !stopCalls);
        assert(providerOwner == &f.client && !f.client.isClosing()); ++scenarios;
    }
    {
        Fixture f; f.begin(); f.foreign.clientClose();
        assert(providerOwner == &f.client && !stopCalls);
        assert(f.call(ElanProviderMatch) == kIOReturnSuccess && acmCalls == 1); ++scenarios;
    }
    for (bool closeOwner : {false, true}) {
        Fixture f; f.begin(); acmFailureSelector = ElanProviderEnd;
        callback = [](const std::string &name) { if (name == "acm-7") assert(providerGate.snapshot().recoveryOnly); };
        assert(f.call(ElanProviderEnd) == kIOReturnNotReady);
        assert(providerOwner == &f.client && providerState.active && !providerState.quarantined && providerGate.snapshot().recoveryOnly);
        unsigned calls = acmCalls + mapCalls;
        for (uint32_t selector = ElanProviderBegin; selector <= ElanProviderSettingsRecover; ++selector)
            if (!nativeProviderRecoverySelector(selector)) assert(f.call(selector) == kIOReturnBusy);
        assert(calls == acmCalls + mapCalls && f.call(ElanProviderEnd, &f.foreign) == kIOReturnBusy);
        assert(f.call(ElanProviderPlatformRestore) == 0 && f.call(ElanProviderSettingsRestore) == 0);
        assert(providerGate.snapshot().recoveryOnly && f.call(ElanProviderMatch) == kIOReturnBusy);
        if (closeOwner) {
            f.client.clientClose();
            assert(!providerOwner && providerGate.snapshot().recoveryOnly && providerState.active);
            assert(f.call(ElanProviderMatch, &f.foreign) == kIOReturnBusy);
        }
        acmFailureSelector = -1;
        auto *recoveryOwner = closeOwner ? &f.foreign : &f.client;
        assert(f.call(ElanProviderEnd, recoveryOwner) == 0 && !providerGate.snapshot().recoveryOnly && !providerGate.snapshot().pending);
        assert(f.call(ElanProviderBegin, recoveryOwner) == 0); ++scenarios;
    }
    for (uint32_t selector : {uint32_t(ElanProviderPlatformEnable), uint32_t(ElanProviderSettingsEnable), uint32_t(ElanProviderSettingsRecover)}) {
        Fixture f; f.begin(); enableFails = recoverLeavesPending = true;
        assert(f.call(selector) == 0 && providerState.active && !providerState.quarantined);
        assert(providerGate.snapshot().recoveryOnly && providerOwner == &f.client);
        unsigned calls = acmCalls + mapCalls;
        for (uint32_t next = ElanProviderBegin; next <= ElanProviderSettingsRecover; ++next)
            if (!nativeProviderRecoverySelector(next)) assert(f.call(next) == kIOReturnBusy);
        assert(calls == acmCalls + mapCalls && f.call(ElanProviderEnd, &f.foreign) == kIOReturnBusy);
        assert(f.call(ElanProviderPlatformRestore) == 0 && f.call(ElanProviderSettingsRestore) == 0);
        assert(providerGate.snapshot().recoveryOnly && f.call(ElanProviderMatch) == kIOReturnBusy);
        assert(f.call(ElanProviderEnd) == 0 && !providerGate.snapshot().recoveryOnly); ++scenarios;
    }
    for (bool settings : {false, true}) {
        Fixture f; f.begin();
        assert(f.call(settings ? ElanProviderSettingsEnable : ElanProviderPlatformEnable) == 0);
        mapFails = true;
        assert(f.call(settings ? ElanProviderSettingsRestore : ElanProviderPlatformRestore) == 0 && f.output.platform.status);
        assert(!providerGate.snapshot().recoveryOnly && f.call(ElanProviderMatch) == 0);
        mapFails = false; ++scenarios;
    }
    for (bool failedMap : {false, true}) {
        Fixture f; f.begin();
        if (failedMap) assert(f.call(ElanProviderPlatformEnable) == 0);
        stopFails = !failedMap; mapFails = failedMap;
        assert(f.call(ElanProviderEnd) == 0 && f.output.provider.restoreStatus);
        assert(providerOwner == &f.client && !providerState.active && providerGate.snapshot().pending);
        unsigned calls = acmCalls + mapCalls;
        for (uint32_t selector = ElanProviderBegin; selector <= ElanProviderSettingsRecover; ++selector)
            if (!nativeProviderRecoverySelector(selector)) assert(f.call(selector) == kIOReturnBusy);
        assert(calls == acmCalls + mapCalls);
        assert(f.call(ElanProviderEnd, &f.foreign) == kIOReturnBusy);
        stopFails = mapFails = false;
        assert(f.call(ElanProviderPlatformRestore) == 0 && f.call(ElanProviderSettingsRestore) == 0);
        assert(f.call(ElanProviderEnd) == 0 && !providerGate.snapshot().pending && !providerOwner);
        assert(f.call(ElanProviderBegin) == 0); ++scenarios;
    }
    {
        Fixture f; f.begin(); providerState.quarantined = true;
        assert(providerState.active);
        unsigned calls = acmCalls + mapCalls;
        for (uint32_t selector = ElanProviderBegin; selector <= ElanProviderSettingsRecover; ++selector)
            if (!nativeProviderRecoverySelector(selector)) assert(f.call(selector) == kIOReturnBusy);
        assert(calls == acmCalls + mapCalls && providerOwner == &f.client);
        assert(f.call(ElanProviderEnd) == 0 && !providerGate.snapshot().pending); ++scenarios;
    }
    for (bool failedMap : {false, true}) {
        Fixture f; f.begin();
        assert(f.call(ElanProviderPlatformEnable) == 0 && f.call(ElanProviderSettingsEnable) == 0);
        stopFails = !failedMap; mapFails = failedMap;
        f.client.clientClose();
        assert(!providerOwner && providerGate.snapshot().pending && stopCalls == 1);
        if (failedMap) assert(providerPlatform.attached() && settingsPlatform.attached());
        else assert(providerState.restorePending && providerState.quarantined);
        f.client.clientClose(); assert(stopCalls == 1);
        for (uint32_t selector = ElanProviderBegin; selector <= ElanProviderSettingsRecover; ++selector)
            if (!nativeProviderRecoverySelector(selector)) assert(f.call(selector, &f.foreign) == kIOReturnBusy);
        assert(f.study(ElanProbeRestoreAvailability, &f.foreign) == kIOReturnBusy);
        assert(f.call(ElanProviderEnd, &f.foreign) == kIOReturnSuccess && providerGate.snapshot().pending);
        stopFails = mapFails = false;
        assert(f.call(ElanProviderEnd, &f.foreign) == kIOReturnSuccess && !providerGate.snapshot().pending);
        assert(f.call(ElanProviderBegin, &f.foreign) == kIOReturnSuccess); ++scenarios;
    }
    {
        Fixture f; f.begin(); acmFailureSelector = ElanProviderEnd;
        f.client.clientClose();
        assert(!providerOwner && providerState.active && providerGate.snapshot().pending && stopCalls == 1);
        assert(f.call(ElanProviderBegin, &f.foreign) == kIOReturnBusy);
        assert(f.call(ElanProviderEnd, &f.foreign) == kIOReturnNotReady && providerGate.snapshot().pending);
        acmFailureSelector = -1;
        assert(f.call(ElanProviderEnd, &f.foreign) == 0 && !providerGate.snapshot().pending); ++scenarios;
    }
    {
        Fixture f; acmFailureSelector = ElanProviderBegin;
        assert(f.call(ElanProviderBegin) == kIOReturnNotReady && !providerOwner);
        assert(!providerGate.snapshot().pending); ++scenarios;
    }
    for (uint32_t selector : {uint32_t(ElanProbeCredentialStudy), uint32_t(ElanProbePolicyStudy), uint32_t(ElanProbeRestoreAvailability)}) {
        {
            Fixture f;
            assert(f.study(selector) == 0 && studyCalls == 1 && !providerGate.snapshot().active);
            f.client.clientClose(); assert(f.study(selector) == kIOReturnNotAttached); ++scenarios;
        }
        {
            Fixture f; f.begin(); assert(f.study(selector) == kIOReturnBusy && !studyCalls); ++scenarios;
        }
        {
            Fixture f; bool checked = false;
            callback = [&](const std::string &name) {
                if (name == "study-" + std::to_string(selector)) {
                    checked = true; checkReentry(f);
                    stateAccessAllowed = false; f.foreign.clientClose(); stateAccessAllowed = true;
                }
            };
            assert(f.study(selector) == kIOReturnSuccess && checked && !stopCalls); ++scenarios;
        }
        {
            Fixture f; bool closed = false;
            callback = [&](const std::string &name) {
                if (name == "study-" + std::to_string(selector) && !closed) {
                    closed = true; checkReentry(f); f.client.clientClose();
                }
            };
            assert(f.study(selector) == kIOReturnAborted && closed && !stopCalls && !mapCalls); ++scenarios;
        }
    }
    {
        Fixture f;
        callback = [&](const std::string &name) {
            if (name == "study-2") { availabilityRestorePending = true; f.client.clientClose(); }
        };
        assert(f.study() == kIOReturnAborted && availabilityRestorePending && providerGate.snapshot().pending);
        callback = {};
        assert(f.call(ElanProviderBegin, &f.foreign) == kIOReturnBusy);
        assert(f.study(ElanProbePolicyStudy, &f.foreign) == kIOReturnBusy);
        checkReadOnlyReport(f);
        assert(f.call(ElanProviderEnd, &f.foreign) == 0 && providerGate.snapshot().pending);
        studyRestoreFails = true;
        assert(f.study(ElanProbeRestoreAvailability, &f.foreign) == 0 && availabilityRestorePending && providerGate.snapshot().pending && providerGate.snapshot().recoveryOnly);
        studyRestoreFails = false;
        assert(f.study(ElanProbeRestoreAvailability, &f.foreign) == 0 && !availabilityRestorePending && !providerGate.snapshot().pending && !providerGate.snapshot().recoveryOnly);
        assert(f.call(ElanProviderBegin, &f.foreign) == 0); ++scenarios;
    }
    {
        Fixture f;
        callback = [&](const std::string &name) { if (name == "study-2") availabilityRestorePending = true; };
        assert(f.study() == 0 && availabilityRestorePending && providerGate.snapshot().pending);
        callback = {};
        assert(f.call(ElanProviderBegin) == kIOReturnBusy && f.study(ElanProbePolicyStudy) == kIOReturnBusy);
        checkReadOnlyReport(f);
        assert(f.study(ElanProbeRestoreAvailability) == 0 && !providerGate.snapshot().pending);
        assert(f.call(ElanProviderBegin) == 0); ++scenarios;
    }
    {
        Fixture f; providerReady = false;
        callback = [&](const std::string &name) { if (name == "study-2") f.client.clientClose(); };
        assert(f.study() == kIOReturnAborted && !acmCalls && !mapCalls);
        assert(!providerGate.snapshot().active && !providerGate.snapshot().pending); ++scenarios;
    }
    for (unsigned failure = 0; failure < 3; ++failure) {
        Fixture f;
        missingMatching = failure == 0; missingService = failure == 1; missingWorkLoop = failure == 2;
        assert(f.study() == (failure == 0 ? kIOReturnNoMemory : kIOReturnNotReady));
        assert(!providerGate.snapshot().active && !studyCalls); ++scenarios;
    }
    {
        Fixture f;
        providerReady = false; assert(f.call(ElanProviderBegin) == kIOReturnNotReady);
        providerReady = true; studyReady = false; assert(f.study() == kIOReturnNotReady);
        studyReady = true; symbolsReady = 0; assert(f.call(ElanProviderBegin) == kIOReturnNotReady);
        symbolsReady = 1; startSuccess = false; assert(f.study() == kIOReturnNotReady);
        startSuccess = true; assert(f.call(100) == kIOReturnBadArgument);
        assert(f.study(100) == kIOReturnBadArgument && !acmCalls && !mapCalls && !studyCalls); ++scenarios;
    }
    printf("provider operation lifecycle: %u shared production dispatch/close/study scenarios; unlocked callbacks, error retention and balanced references passed\n", scenarios);
}
