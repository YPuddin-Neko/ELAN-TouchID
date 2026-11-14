#include "NativeProviderABI.h"
#include <assert.h>
#include <stdio.h>

static uint32_t credentialTypes;
static bool ownerAccepted, wrongUserAccepted;
static int contextStatus, policyStatus, cleanupStatus;
static unsigned policies, deleted;
static const uint8_t handle[16] = {0x51, 0x22};
static int privateContext(const uint8_t *context, uint32_t *types) {
    if (memcmp(context, handle, 16)) return NativeProviderInvalid;
    *types = credentialTypes;
    return contextStatus;
}
static int verify(void *context, const char *policy, const NativeACMParameter *parameters,
                  unsigned count, unsigned age, bool *satisfied, void **requirement) {
    assert(!memcmp(context, handle, 16) && !strcmp(policy, "TouchIdEnrollment"));
    assert(count == 1 && parameters->type == 4 && parameters->length == 4 && !age);
    uint32_t user = *static_cast<const uint32_t *>(parameters->value);
    assert(user == 501 || user == 502);
    *satisfied = user == 501 ? ownerAccepted : wrongUserAccepted;
    *requirement = new unsigned(7);
    policies++;
    return policyStatus;
}
static int destroyRequirement(void *requirement) {
    assert(requirement && *static_cast<unsigned *>(requirement) == 7);
    delete static_cast<unsigned *>(requirement);
    deleted++;
    return cleanupStatus;
}
static NativeEnrollmentAPI api() {
    NativeEnrollmentAPI value {};
    value.acm.verifyPolicy = verify;
    value.acm.deleteRequirement = destroyRequirement;
    value.privatePasswordContext = privateContext;
    return value;
}
static NativeEnrollmentReport authorize(NativeProviderState &state, uint64_t sequence) {
    NativeEnrollmentRequest request {1, 501, sequence, {}};
    memcpy(request.context, handle, 16);
    NativeEnrollmentReport report {};
    nativeAuthorizeEnrollment(api(), state, request, report);
    assert(policies == deleted);
    return report;
}
int main() {
    NativeProviderState state {};
    assert(authorize(state, 1).operationStatus == NativeProviderNotActive && !policies);
    state.active = true; state.user = 501;
    // An empty or biometric-only context cannot authorize enrollment, even if a policy were permissive.
    ownerAccepted = true;
    auto empty = authorize(state, 1);
    assert(empty.operationStatus == NativeEnrollmentNotAuthorized && !empty.authorized && !policies);
    credentialTypes = 1;
    ownerAccepted = false;
    auto expired = authorize(state, 2);
    assert(expired.operationStatus == NativeEnrollmentNotAuthorized && !expired.authorized && policies == 1);
    ownerAccepted = true; wrongUserAccepted = true;
    auto wrong = authorize(state, 3);
    assert(wrong.operationStatus == NativeEnrollmentNotAuthorized && wrong.wrongUserPolicy && !wrong.authorized);
    wrongUserAccepted = false;
    for (uint32_t type = 1; type <= 3; type++) {
        credentialTypes = type;
        auto allowed = authorize(state, 3 + type);
        assert(!allowed.operationStatus && allowed.authorized && allowed.ownerPolicy && !allowed.wrongUserPolicy &&
               allowed.passwordCredentialTypes == type && allowed.sequence == 3 + type);
    }
    auto replay = authorize(state, 6);
    assert(replay.operationStatus == NativeProviderInvalid && !replay.authorized);
    contextStatus = -2;
    assert(authorize(state, 7).operationStatus == -2);
    contextStatus = 0; policyStatus = -40;
    assert(authorize(state, 8).operationStatus == -40);
    policyStatus = 0; cleanupStatus = -41;
    assert(authorize(state, 9).operationStatus == -41);
    cleanupStatus = 0; credentialTypes = 4;
    assert(authorize(state, 10).operationStatus == NativeEnrollmentNotAuthorized);
    unsigned previous = policies;
    NativeEnrollmentRequest bad {1, 502, 11, {}};
    memcpy(bad.context, handle, 16);
    NativeEnrollmentReport report {};
    nativeAuthorizeEnrollment(api(), state, bad, report);
    assert(report.operationStatus == NativeProviderInvalid && state.lastSequence == 10 && policies == previous);
    bad.user = 501; memset(bad.context, 0, 16);
    nativeAuthorizeEnrollment(api(), state, bad, report);
    assert(report.operationStatus == NativeProviderInvalid && policies == previous);
    memset(bad.context, 0x88, 16);
    nativeAuthorizeEnrollment(api(), state, bad, report);
    assert(report.operationStatus == NativeProviderInvalid && state.lastSequence == 11 && policies == previous);
    assert(nativeProviderInputSize(ElanProviderCatalogBegin) == 72 && nativeProviderOutputSize(ElanProviderCatalogBegin) == 112);
    assert(nativeProviderInputSize(ElanProviderAuthorizeEnrollment) == 32 && nativeProviderOutputSize(ElanProviderAuthorizeEnrollment) == 40);
    assert(nativeProviderOutputSize(ElanProviderPlatformRestore) == 32 && !nativeProviderIsSelector(15));
    assert(nativeProviderInputSize(ElanProviderSettingsEnable) == 32 && nativeProviderOutputSize(ElanProviderSettingsRestore) == 32);
    assert(!nativeProviderInputSize(15) && !nativeProviderOutputSize(15));
    printf("enrollment authorization: empty, expired, wrong user, credential types, replay, context and policy failures passed; no credential creation or availability writes\n");
}
