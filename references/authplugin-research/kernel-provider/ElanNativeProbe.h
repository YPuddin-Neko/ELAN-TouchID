#pragma once
#include <stdint.h>

#define ELAN_NATIVE_PROBE_ABI 1
#define ELAN_NATIVE_PROBE_SERVICE "ELANNativeProbe"

enum {
    ElanProbeStatus = 0, ElanProbeContextLifecycle = 1,
    ElanProbeCredentialStudy = 2, ElanProbePolicyStudy = 3, ElanProbeRestoreAvailability = 4,
    ElanProviderBegin = 5, ElanProviderMatch = 6, ElanProviderEnd = 7,
    ElanProviderPlatformEnable = 8, ElanProviderPlatformRestore = 9,
    ElanProviderCatalogBegin = 10, ElanProviderCatalogReplace = 11, ElanProviderAuthorizeEnrollment = 12,
    ElanProviderSettingsEnable = 13, ElanProviderSettingsRestore = 14
};

struct NativeSettingsProcessRequest {
    uint32_t abi;
    uint32_t user;
    int32_t pid;
    uint32_t reserved;
    uint64_t function;
    uint64_t image;
};
static_assert(sizeof(NativeSettingsProcessRequest) == 32, "settings process request ABI");

struct NativePlatformProcessRequest {
    uint32_t abi;
    uint32_t user;
    int32_t pid;
    uint32_t reserved;
    uint64_t function;
    uint64_t instanceGetter;
    uint64_t faultGetter;
    uint64_t permanentGetter;
    uint64_t helperClass;
};
struct NativePlatformProcessReport {
    uint32_t abi;
    int32_t status;
    uint32_t kernelReady;
    uint32_t restorePending;
    int32_t pid;
    uint32_t attached;
    uint32_t restartRequired;
    uint32_t reserved;
};
static_assert(sizeof(NativePlatformProcessRequest) == 56, "platform process request ABI");
static_assert(sizeof(NativePlatformProcessReport) == 32, "platform process report ABI");
enum {
    ElanStageLiluStarted = 1U << 0,
    ElanStagePluginEntered = 1U << 1,
    ElanStageCallbackRegistered = 1U << 2,
    ElanStageCallbackSeen = 1U << 3,
    ElanStageACMPresent = 1U << 4,
    ElanStageWorkLoopPresent = 1U << 5
};

typedef struct {
    uint32_t abi;
    uint32_t ready;
    uint32_t uuidMatched;
    uint32_t symbols;
    int32_t permissionsStatus;
    int32_t availabilityStatus;
    int32_t createStatus;
    int32_t deleteStatus;
    uint64_t requiredPermissions;
    uint32_t availability;
    uint32_t contextsCreated;
    uint32_t contextsDeleted;
    uint32_t stages;
} ElanNativeProbeReport;

static_assert(sizeof(ElanNativeProbeReport) == 56, "probe ABI size");
