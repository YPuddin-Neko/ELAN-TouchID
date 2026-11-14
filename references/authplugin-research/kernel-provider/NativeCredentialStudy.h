#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct NativeACMParameter {
    uint32_t type;
    const void *value;
    uint32_t length;
};
static_assert(sizeof(NativeACMParameter) == 24, "ACM parameter ABI");
static_assert(offsetof(NativeACMParameter, value) == 8, "ACM parameter value ABI");

enum NativeStudyStep {
    StudyPreflight, StudyCreateTarget, StudyCreateControl, StudyEmptyPolicy,
    StudyAllocateCredential, StudyUserProperty, StudyFlagsProperty, StudyIdentityProperty,
    StudyAddCredential, StudyReadUser, StudyReadFlags, StudyReadIdentity,
    StudyUnavailablePolicy, StudyEnableAvailability, StudyControlPolicy,
    StudyMatchedPolicy, StudyWrongUserPolicy, StudyStepCount
};

struct NativeCredentialStudyReport {
    uint32_t abi;
    uint32_t completedSteps;
    int32_t stepStatus[StudyStepCount];
    uint32_t policySatisfied[5];
    uint32_t credentialsAdded;
    uint32_t contextsCreated;
    uint32_t contextsDeleted;
    uint32_t availabilityBefore;
    uint32_t availabilityAfter;
    uint32_t availabilityWriteAttempted;
    uint32_t availabilityRestorePending;
    uint32_t availabilityValueWasPresent;
    int32_t restoreStatus;
    int32_t readbackStatus;
    int32_t targetDeleteStatus;
    int32_t controlDeleteStatus;
    uint32_t passed;
};
static_assert(sizeof(NativeCredentialStudyReport) == 148, "study report ABI");

struct NativeCredentialStudyAPI {
    int (*preflight)(bool, uint32_t *);
    int (*getAvailability)(uint64_t, unsigned, uint8_t *, bool);
    int (*setAvailability)(uint64_t, unsigned, const void *, size_t);
    int (*createContext)(void **);
    int (*deleteContext)(void *, bool);
    int (*createCredential)(unsigned, void **);
    void (*deleteCredential)(void *);
    int (*setProperty)(void *, unsigned, const void *, size_t);
    int (*addCredential)(const void *, void *, unsigned, uint64_t);
    int (*readProperty)(void *, unsigned, unsigned, void *, size_t *);
    int (*verifyPolicy)(void *, const char *, const NativeACMParameter *, unsigned, unsigned, bool *, void **);
    int (*deleteRequirement)(void *);
};

static constexpr int NativeStudyNotRun = INT32_MIN;
static constexpr int NativeStudyUnexpected = -20001;
static constexpr uint64_t NativeBiometryProvider = 0x0000010000000000ULL;
static constexpr uint64_t NativeEnvironmentReader = 0x2000000000000000ULL;
static constexpr uint32_t NativeStudyUser = 0x7fff0001U;

static inline int nativeStudyPolicy(const NativeCredentialStudyAPI &api, void *context,
                                    uint32_t uid, bool expected, uint32_t *observed) {
    NativeACMParameter parameter {4, &uid, sizeof(uid)};
    bool satisfied = false;
    void *requirement = nullptr;
    int status = api.verifyPolicy(context, "DeviceOwnerAuthenticationWithBiometrics",
                                  &parameter, 1, 0, &satisfied, &requirement);
    *observed = satisfied ? 1U : 0U;
    if (requirement) {
        int cleanup = api.deleteRequirement(requirement);
        if (!status) status = cleanup;
    }
    if (!status && satisfied != expected) status = NativeStudyUnexpected;
    return status;
}

// The context handles stay inside this call and are never exposed to a client.
static inline void runNativeCredentialStudy(const NativeCredentialStudyAPI &api, bool withAvailability,
                                            bool &restorePending, NativeCredentialStudyReport &report) {
    memset(&report, 0, sizeof(report));
    report.abi = 1;
    for (auto &status : report.stepStatus) status = NativeStudyNotRun;
    report.restoreStatus = report.readbackStatus = NativeStudyNotRun;
    report.targetDeleteStatus = report.controlDeleteStatus = NativeStudyNotRun;
    void *context = nullptr, *control = nullptr, *credential = nullptr;
    bool stepsPassed = false;
    uint8_t originalAvailability = 0;
    uint32_t uid = NativeStudyUser, flags = 4;
    const uint8_t identity[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                  0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f};
    auto step = [&](NativeStudyStep index, int status) {
        report.completedSteps |= 1U << index;
        report.stepStatus[index] = status;
        return status == 0;
    };
    auto readEqual = [&](unsigned property, const void *expected, size_t length) {
        uint8_t value[16] = {};
        size_t actual = length;
        int status = api.readProperty(context, 3, property, value, &actual);
        if (!status && (actual != length || memcmp(value, expected, length))) status = NativeStudyUnexpected;
        return status;
    };
    do {
        int preflight = restorePending ? NativeStudyUnexpected : api.preflight(withAvailability, &report.availabilityValueWasPresent);
        if (!preflight) preflight = api.getAvailability(NativeEnvironmentReader, 6, &originalAvailability, false);
        report.availabilityBefore = originalAvailability;
        if (!preflight && originalAvailability != 0) preflight = NativeStudyUnexpected;
        if (!step(StudyPreflight, preflight)) break;
        int status = api.createContext(&context);
        if (!status && !context) status = NativeStudyUnexpected;
        if (context) report.contextsCreated++;
        if (!step(StudyCreateTarget, status)) break;
        status = api.createContext(&control);
        if (!status && !control) status = NativeStudyUnexpected;
        if (control) report.contextsCreated++;
        if (!step(StudyCreateControl, status)) break;
        if (!step(StudyEmptyPolicy, nativeStudyPolicy(api, context, uid, false, &report.policySatisfied[0]))) break;
        status = api.createCredential(3, &credential);
        if (!status && !credential) status = NativeStudyUnexpected;
        if (!step(StudyAllocateCredential, status)) break;
        if (!step(StudyUserProperty, api.setProperty(credential, 5, &uid, sizeof(uid)))) break;
        if (!step(StudyFlagsProperty, api.setProperty(credential, 101, &flags, sizeof(flags)))) break;
        if (!step(StudyIdentityProperty, api.setProperty(credential, 100, identity, sizeof(identity)))) break;
        if (!step(StudyAddCredential, api.addCredential(context, credential, 1, NativeBiometryProvider))) break;
        credential = nullptr;
        report.credentialsAdded = 1;
        if (!step(StudyReadUser, readEqual(5, &uid, sizeof(uid)))) break;
        if (!step(StudyReadFlags, readEqual(101, &flags, sizeof(flags)))) break;
        if (!step(StudyReadIdentity, readEqual(100, identity, sizeof(identity)))) break;
        if (!step(StudyUnavailablePolicy, nativeStudyPolicy(api, context, uid, false, &report.policySatisfied[1]))) break;
        if (withAvailability) {
            uint8_t available = 1;
            restorePending = true;
            report.availabilityWriteAttempted = 1;
            if (!step(StudyEnableAvailability, api.setAvailability(NativeBiometryProvider, 6, &available, sizeof(available)))) break;
            if (!step(StudyControlPolicy, nativeStudyPolicy(api, control, uid, false, &report.policySatisfied[2]))) break;
            if (!step(StudyMatchedPolicy, nativeStudyPolicy(api, context, uid, true, &report.policySatisfied[3]))) break;
            if (!step(StudyWrongUserPolicy, nativeStudyPolicy(api, context, uid + 1, false, &report.policySatisfied[4]))) break;
        }
        stepsPassed = true;
    } while (false);
    if (credential) api.deleteCredential(credential);
    if (context) {
        report.targetDeleteStatus = api.deleteContext(context, true);
        if (!report.targetDeleteStatus) report.contextsDeleted++;
    }
    if (control) {
        report.controlDeleteStatus = api.deleteContext(control, true);
        if (!report.controlDeleteStatus) report.contextsDeleted++;
    }
    if (report.availabilityWriteAttempted) {
        // Restore the logical availability value through Apple's setter, including after a failed write.
        report.restoreStatus = api.setAvailability(NativeBiometryProvider, 6, &originalAvailability, sizeof(originalAvailability));
    }
    uint8_t after = 0xff;
    report.readbackStatus = api.getAvailability(NativeEnvironmentReader, 6, &after, false);
    report.availabilityAfter = after;
    if (report.availabilityWriteAttempted && !report.restoreStatus && !report.readbackStatus && after == originalAvailability)
        restorePending = false;
    report.availabilityRestorePending = restorePending ? 1U : 0U;
    report.passed = stepsPassed && report.contextsCreated == report.contextsDeleted &&
                    !report.readbackStatus && after == originalAvailability && !restorePending;
}
