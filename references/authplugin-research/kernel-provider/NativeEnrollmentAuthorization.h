#pragma once
#include "NativeProviderSession.h"

static constexpr int NativeEnrollmentNotAuthorized = -32004;

enum NativeEnrollmentRejectKind : uint32_t {
 NativeEnrollmentUnobserved=0, NativeEnrollmentCopyError=1, NativeEnrollmentPropertyError=2,
 NativeEnrollmentShape=3, NativeEnrollmentWildcard=4, NativeEnrollmentZero=5,
 NativeEnrollmentOtherPrincipal=6, NativeEnrollmentMatch=7, NativeEnrollmentPolicy=8,
 NativeEnrollmentContext=9, NativeEnrollmentRequestInvalid=10, NativeEnrollmentInactive=11,
 NativeEnrollmentNoPassword=12
};
struct NativeEnrollmentDiagnostic {
 uint32_t type=0, index=UINT32_MAX, count=0, rejectKind=NativeEnrollmentUnobserved;
};
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
    uint32_t principalVerifiedTypes;
    uint32_t authorized;
    uint64_t sequence;
    uint32_t active;
    uint32_t reserved;
    NativeEnrollmentDiagnostic diagnostic;
};
static_assert(sizeof(NativeEnrollmentRequest) == 32, "enrollment authorization request ABI");
static_assert(sizeof(NativeEnrollmentReport) == 56, "enrollment authorization report ABI");

struct NativeEnrollmentAPI {
    NativeCredentialStudyAPI acm;
    // Reports existing password types 1/10 and the subset bound to expectedUser.
    int (*privatePasswordContext)(const uint8_t *, uint32_t, uint32_t *, uint32_t *, NativeEnrollmentDiagnostic *);
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

static inline void nativeCheckEnrollmentContext(const NativeEnrollmentAPI &api, uint32_t user,
                                                const uint8_t handle[16], NativeEnrollmentReport &report) {
    report.authorized = 0;
    report.passwordCredentialTypes = 0;
    report.principalVerifiedTypes = 0;
    report.ownerPolicy = 0;
    report.diagnostic = NativeEnrollmentDiagnostic{};
    if (!nativeNonzeroBytes(handle, 16)) {
        report.operationStatus = NativeProviderInvalid;
        report.diagnostic.rejectKind = NativeEnrollmentRequestInvalid;
        return;
    }
    uint8_t context[16];
    memcpy(context, handle, sizeof(context));
    int status = api.privatePasswordContext(context, user, &report.passwordCredentialTypes, &report.principalVerifiedTypes, &report.diagnostic);
    if (!status && (!report.passwordCredentialTypes || (report.passwordCredentialTypes & ~3U) ||
                    report.principalVerifiedTypes != report.passwordCredentialTypes))
        { status = NativeEnrollmentNotAuthorized; report.diagnostic=NativeEnrollmentDiagnostic{}; report.diagnostic.rejectKind=NativeEnrollmentNoPassword; }
    if (!status) {
        status = nativeEnrollmentPolicy(api, context, user, report.ownerPolicy);
        if (!status && !report.ownerPolicy) status = NativeEnrollmentNotAuthorized;
        report.diagnostic=NativeEnrollmentDiagnostic{};
        report.diagnostic.rejectKind=status?NativeEnrollmentPolicy:NativeEnrollmentMatch;
    }
    report.operationStatus = status;
    report.authorized = status == 0;
}

static inline void nativeAuthorizeEnrollment(const NativeEnrollmentAPI &api, NativeProviderState &state,
                                             const NativeEnrollmentRequest &request, NativeEnrollmentReport &report) {
    report = {};
    report.abi = 3;
    report.active = state.active;
    report.sequence = state.lastSequence;
    if (!state.active) { report.diagnostic.rejectKind=NativeEnrollmentInactive; report.operationStatus = NativeProviderNotActive; return; }
    if (request.abi != 3 || request.user != state.user || !request.sequence ||
        request.sequence <= state.lastSequence || !nativeNonzeroBytes(request.context, 16)) {
        report.diagnostic.rejectKind=NativeEnrollmentRequestInvalid;
        report.operationStatus = NativeProviderInvalid;
        return;
    }
    state.lastSequence = request.sequence;
    report.sequence = request.sequence;
    nativeCheckEnrollmentContext(api, state.user, request.context, report);
}
