#pragma once
#include "NativeProviderSession.h"

static constexpr int NativeEnrollmentNotAuthorized = -32004;

struct NativeEnrollmentRequest {
    uint32_t abi;
    uint32_t user;
    uint64_t sequence;
    uint8_t context[16];
};
struct NativeEnrollmentReport {
    uint32_t abi;
    int32_t operationStatus;
    uint32_t passwordCredentialTypes;
    uint32_t ownerPolicy;
    uint32_t wrongUserPolicy;
    uint32_t authorized;
    uint64_t sequence;
    uint32_t active;
    uint32_t reserved;
};
static_assert(sizeof(NativeEnrollmentRequest) == 32, "enrollment authorization request ABI");
static_assert(sizeof(NativeEnrollmentReport) == 40, "enrollment authorization report ABI");

struct NativeEnrollmentAPI {
    NativeCredentialStudyAPI acm;
    // Checks a private context and reports existing password credential types 1 and 10 as bits 0 and 1.
    int (*privatePasswordContext)(const uint8_t *, uint32_t *);
};

static inline int nativeEnrollmentPolicy(const NativeEnrollmentAPI &api, void *context,
                                         uint32_t user, uint32_t &observed) {
    NativeACMParameter parameter {4, &user, sizeof(user)};
    bool satisfied = false;
    void *requirement = nullptr;
    // Apple's policy may set the enrollment flag on this caller-owned context.
    int status = api.acm.verifyPolicy(context, "TouchIdEnrollment", &parameter, 1, 0, &satisfied, &requirement);
    observed = satisfied ? 1U : 0U;
    if (requirement) {
        int cleanup = api.acm.deleteRequirement(requirement);
        if (!status) status = cleanup;
    }
    return status;
}

static inline void nativeAuthorizeEnrollment(const NativeEnrollmentAPI &api, NativeProviderState &state,
                                             const NativeEnrollmentRequest &request, NativeEnrollmentReport &report) {
    report = {};
    report.abi = 1;
    report.active = state.active;
    report.sequence = state.lastSequence;
    if (!state.active) { report.operationStatus = NativeProviderNotActive; return; }
    if (request.abi != 1 || request.user != state.user || !request.sequence ||
        request.sequence <= state.lastSequence || !nativeNonzeroBytes(request.context, 16)) {
        report.operationStatus = NativeProviderInvalid;
        return;
    }
    state.lastSequence = request.sequence;
    report.sequence = request.sequence;
    uint8_t context[16];
    memcpy(context, request.context, sizeof(context));
    int status = api.privatePasswordContext(context, &report.passwordCredentialTypes);
    if (!status && (!report.passwordCredentialTypes || (report.passwordCredentialTypes & ~3U)))
        status = NativeEnrollmentNotAuthorized;
    if (!status) status = nativeEnrollmentPolicy(api, context, state.user, report.ownerPolicy);
    if (!status && !report.ownerPolicy) status = NativeEnrollmentNotAuthorized;
    if (!status) status = nativeEnrollmentPolicy(api, context, state.user + 1, report.wrongUserPolicy);
    if (!status && report.wrongUserPolicy) status = NativeEnrollmentNotAuthorized;
    report.operationStatus = status;
    report.authorized = status == 0;
}
