#pragma once
#include <stdint.h>

// A separate IOServiceOpen type. No UID, PID, selector from the legacy client, or caller verdict is accepted.
enum {
    ElanEnrollmentConnectionType = 0x454e524c,
    ElanCheckEnrollment = 0,
    ElanPublishSettingsListener = 1,
    ElanSyncProviderCatalog = 2,
    ElanSubmitDirectMatch = 3,
    ElanCopyEnrollmentPassphrase = 4,
    ElanDispatchUnlockKeystrokes = 5
};

typedef struct { uint8_t handle[16]; } ElanDirectEnrollmentContext;
typedef struct { uint32_t abi; uint32_t authorized; } ElanDirectEnrollmentReply;
typedef struct {
    uint32_t abi;
    uint32_t length;
    uint8_t bytes[128];
} ElanDirectPassphraseReply;
typedef struct {
    uint32_t abi;
    uint32_t length;
    uint8_t bytes[128];
} ElanDirectUnlockRequest;
typedef struct {
    uint32_t abi;
    uint32_t count;
    uint8_t identities[3][16];
} ElanDirectCatalogSync;
typedef struct {
    uint32_t abi;
    int32_t status;
} ElanDirectOperationReply;
typedef struct {
    uint32_t abi;
    uint32_t matched;
    uint64_t sequence;
    uint8_t identity[16];
    uint8_t context[16];
} ElanDirectMatchSubmission;
_Static_assert(sizeof(ElanDirectEnrollmentContext) == 16, "ACM external context");
_Static_assert(sizeof(ElanDirectEnrollmentReply) == 8, "enrollment reply");
_Static_assert(sizeof(ElanDirectCatalogSync) == 56, "catalog sync request");
_Static_assert(sizeof(ElanDirectOperationReply) == 8, "direct operation reply");
_Static_assert(sizeof(ElanDirectMatchSubmission) == 48, "direct match submission");
_Static_assert(sizeof(ElanDirectUnlockRequest) == 136, "direct unlock request");
