#pragma once
#include "ElanNativeProbe.h"
#include "NativeEnrollmentAuthorization.h"
#include "NativeStartupTrialABI.h"

struct NativeSettingsRecoveryReport {
    NativePlatformProcessReport platform;
    uint32_t phase;
    int32_t transactionStatus;
    int32_t rollbackStatus;
    uint32_t reserved;
};
static_assert(sizeof(NativeSettingsRecoveryReport) == 48, "settings recovery report ABI");
static inline bool nativeSettingsRecoveryReportValid(int call, size_t length, const NativeSettingsRecoveryReport &r) {
    return !call && length == sizeof(r) && r.platform.abi == 1 && !r.platform.reserved &&
        !r.reserved && r.phase <= 7 && r.transactionStatus == r.platform.status &&
        r.platform.kernelReady <= 1 && r.platform.restorePending <= 1 &&
        r.platform.attached <= 1 && r.platform.restartRequired <= 1 &&
        (r.transactionStatus != 0 || (r.phase == 7 && r.rollbackStatus == 0));
}
union NativeProviderInput {
    NativeProviderRequest provider;
    NativePlatformProcessRequest platform;
    NativeProviderCatalogRequest catalog;
    NativeEnrollmentRequest enrollment;
    NativeSettingsProcessRequest settings;
    NativeStartupTrialRequest startupTrial;
};
union NativeProviderOutput {
    NativeProviderReport provider;
    NativePlatformProcessReport platform;
    NativeSettingsInspectionReport inspection;
    NativeSettingsRecoveryReport recovery;
    NativeProviderCatalogReport catalog;
    NativeEnrollmentReport enrollment;
    NativeStartupTrialReport startupTrial;
};

static inline bool nativeProviderIsSelector(uint32_t selector) {
    return selector >= ElanProviderBegin && selector <= ElanProviderStartupTrialRetire;
}
static inline size_t nativeProviderInputSize(uint32_t selector) {
    switch (selector) {
        case ElanProviderStartupTrialArm: case ElanProviderStartupTrialCancel: return sizeof(NativeStartupTrialRequest);
        case ElanProviderBegin: case ElanProviderMatch: return sizeof(NativeProviderRequest);
        case ElanProviderPlatformEnable: return sizeof(NativePlatformProcessRequest);
        case ElanProviderCatalogBegin: case ElanProviderCatalogReplace: return sizeof(NativeProviderCatalogRequest);
        case ElanProviderAuthorizeEnrollment: return sizeof(NativeEnrollmentRequest);
        case ElanProviderSettingsEnable: case ElanProviderSettingsInspect: case ElanProviderSettingsRecover: return sizeof(NativeSettingsProcessRequest);
        default: return 0;
    }
}
static inline size_t nativeProviderOutputSize(uint32_t selector) {
    switch (selector) {
        case ElanProviderStartupTrialArm: case ElanProviderStartupTrialCancel: case ElanProviderStartupTrialRetire: return sizeof(NativeStartupTrialReport);
        case ElanProviderBegin: case ElanProviderMatch: case ElanProviderEnd: return sizeof(NativeProviderReport);
        case ElanProviderPlatformEnable: case ElanProviderPlatformRestore: case ElanProviderCoreauthRetire: return sizeof(NativePlatformProcessReport);
        case ElanProviderSettingsInspect: return sizeof(NativeSettingsInspectionReport);
        case ElanProviderSettingsEnable: case ElanProviderSettingsRestore: return sizeof(NativePlatformProcessReport);
        case ElanProviderSettingsRecover: return sizeof(NativeSettingsRecoveryReport);
        case ElanProviderCatalogBegin: case ElanProviderCatalogReplace: return sizeof(NativeProviderCatalogReport);
        case ElanProviderAuthorizeEnrollment: return sizeof(NativeEnrollmentReport);
        default: return 0;
    }
}

static inline bool nativeSettingsInspectionAllowsEnable(int call, size_t length,
                                                        const NativeSettingsInspectionReport &report) {
    return !call && length == sizeof(report) && report.abi == 2 && !report.status &&
        report.imageMatched == 1 && report.stage == 9 && report.observation == 1 &&
        !report.reserved[0] && !report.reserved[1] && !report.reserved[2];
}

static inline bool nativeSettingsInspectionAllowsRecovery(int call, size_t length,
    const NativeSettingsInspectionReport &report, bool explicitlyEnabled) {
    return explicitlyEnabled && !call && length == sizeof(report) && report.abi == 2 && !report.status &&
        report.imageMatched == 1 && report.stage == 9 && report.observation == 2 &&
        !report.reserved[0] && !report.reserved[1] && !report.reserved[2];
}
