#pragma once
#include "NativeCredentialStudy.h"

static constexpr int NativeProviderInvalid = -32001;
static constexpr int NativeProviderBusy = -32002;
static constexpr int NativeProviderNotActive = -32003;
static constexpr unsigned NativeProviderMaxIdentities = 3;

struct NativeProviderRequest {
    uint32_t abi;
    uint32_t user;
    uint64_t sequence;
    uint8_t identity[16];
    uint8_t context[16];
    uint32_t matched;
    uint32_t reserved;
};
static_assert(sizeof(NativeProviderRequest) == 56, "provider request ABI");

struct NativeProviderReport {
    uint32_t abi;
    int32_t operationStatus;
    int32_t restoreStatus;
    uint32_t active;
    uint32_t restorePending;
    uint32_t availability;
    uint32_t credentialAdded;
    uint32_t matchedPolicy;
    uint32_t wrongUserPolicy;
    uint32_t propertiesVerified;
    uint64_t sequence;
    uint32_t quarantinedContext;
    uint32_t reserved;
};
static_assert(sizeof(NativeProviderReport) == 56, "provider report ABI");

struct NativeProviderCatalogRequest {
    uint32_t abi;
    uint32_t user;
    uint64_t sequence;
    uint32_t count;
    uint32_t reserved;
    uint8_t identities[NativeProviderMaxIdentities][16];
};
struct NativeProviderCatalogReport {
    NativeProviderReport provider;
    uint32_t count;
    uint32_t reserved;
    uint8_t identities[NativeProviderMaxIdentities][16];
};
static_assert(sizeof(NativeProviderCatalogRequest) == 72, "catalog request ABI");
static_assert(sizeof(NativeProviderCatalogReport) == 112, "catalog report ABI");

struct NativeProviderState {
    uint32_t user;
    uint32_t identityCount;
    uint8_t identities[NativeProviderMaxIdentities][16];
    uint64_t lastSequence;
    bool active;
    bool restorePending;
    bool quarantined;
    uint8_t failedContext[16];
};

struct NativeProviderAPI {
    NativeCredentialStudyAPI acm;
    // Returns 0 only for an existing, private context without a type-3 credential.
    int (*emptyPrivateContext)(const uint8_t *);
};

static inline bool nativeNonzeroBytes(const uint8_t *bytes, size_t length) {
    uint8_t value = 0;
    for (size_t i = 0; i < length; i++) value |= bytes[i];
    return value != 0;
}

static inline void nativeProviderReport(const NativeProviderAPI &api, const NativeProviderState &state,
                                        NativeProviderReport &report) {
    report.abi = 1;
    report.active = state.active;
    report.restorePending = state.restorePending;
    report.sequence = state.lastSequence;
    report.quarantinedContext = state.quarantined;
    uint8_t availability = 0xff;
    int status = api.acm.getAvailability(NativeEnvironmentReader, 6, &availability, false);
    report.availability = status ? 0xff : availability;
    if (!report.operationStatus && status) report.operationStatus = status;
}

static inline int nativeProviderStop(const NativeProviderAPI &api, NativeProviderState &state) {
    state.active = false;
    if (state.restorePending) {
        uint8_t zero = 0, after = 0xff;
        int status = api.acm.setAvailability(NativeBiometryProvider, 6, &zero, 1);
        int read = api.acm.getAvailability(NativeEnvironmentReader, 6, &after, false);
        if (read || after != 0) return status ? status : read ? read : NativeStudyUnexpected;
        state.restorePending = false;
    }
    if (state.quarantined) {
        int empty = api.emptyPrivateContext(state.failedContext);
        if (empty != 0 && empty != -2) return NativeProviderBusy;
    }
    memset(&state, 0, sizeof(state));
    return 0;
}

static inline bool nativeProviderValidCatalog(const NativeProviderCatalogRequest &request) {
    if (request.abi != 1 || request.user != 501 || request.reserved || request.count > NativeProviderMaxIdentities)
        return false;
    for (unsigned i = 0; i < NativeProviderMaxIdentities; i++) {
        if (nativeNonzeroBytes(request.identities[i], 16) != (i < request.count)) return false;
        for (unsigned j = 0; j < i && i < request.count; j++)
            if (!memcmp(request.identities[i], request.identities[j], 16)) return false;
    }
    return true;
}

static inline void nativeProviderSetCatalog(NativeProviderState &state, const NativeProviderCatalogRequest &request) {
    state.identityCount = request.count;
    memcpy(state.identities, request.identities, sizeof(state.identities));
    state.lastSequence = request.sequence;
}

static inline void nativeProviderCatalogReport(const NativeProviderAPI &api, const NativeProviderState &state,
                                               NativeProviderCatalogReport &report) {
    nativeProviderReport(api, state, report.provider);
    report.count = state.identityCount;
    memcpy(report.identities, state.identities, sizeof(report.identities));
}

static inline int nativeProviderStartCatalog(const NativeProviderAPI &api, NativeProviderState &state,
                                             const NativeProviderCatalogRequest &request) {
    if (state.active || state.restorePending || state.quarantined) return NativeProviderBusy;
    if (!nativeProviderValidCatalog(request) || request.sequence) return NativeProviderInvalid;
    uint32_t present = 0;
    int status = api.acm.preflight(true, &present);
    uint8_t before = 0xff;
    if (!status) status = api.acm.getAvailability(NativeEnvironmentReader, 6, &before, false);
    if (status) return status;
    if (before != 0) return NativeProviderBusy;
    state.user = request.user;
    nativeProviderSetCatalog(state, request);
    state.restorePending = true;
    uint8_t one = 1, after = 0xff;
    status = api.acm.setAvailability(NativeBiometryProvider, 6, &one, 1);
    int read = api.acm.getAvailability(NativeEnvironmentReader, 6, &after, false);
    if (!status && (read || after != 1)) status = read ? read : NativeStudyUnexpected;
    if (status) { nativeProviderStop(api, state); return status; }
    state.active = true;
    return 0;
}

static inline int nativeProviderStart(const NativeProviderAPI &api, NativeProviderState &state,
                                      const NativeProviderRequest &request) {
    if (state.active || state.restorePending || state.quarantined) return NativeProviderBusy;
    if (request.abi != 1 || request.user != 501 || request.sequence || request.matched || request.reserved ||
        nativeNonzeroBytes(request.context, 16) || !nativeNonzeroBytes(request.identity, 16)) return NativeProviderInvalid;
    NativeProviderCatalogRequest catalog {};
    catalog.abi = 1; catalog.user = request.user; catalog.count = 1;
    memcpy(catalog.identities[0], request.identity, 16);
    return nativeProviderStartCatalog(api, state, catalog);
}

// The broker serializes catalog commits with matches; older capture sequences cannot cross a replacement.
static inline int nativeProviderReplaceCatalog(NativeProviderState &state, const NativeProviderCatalogRequest &request) {
    if (!state.active) return NativeProviderNotActive;
    if (!nativeProviderValidCatalog(request) || request.user != state.user ||
        !request.sequence || request.sequence <= state.lastSequence) return NativeProviderInvalid;
    nativeProviderSetCatalog(state, request);
    return 0;
}

static inline bool nativeProviderHasIdentity(const NativeProviderState &state, const uint8_t identity[16]) {
    for (unsigned i = 0; i < state.identityCount; i++)
        if (!memcmp(state.identities[i], identity, 16)) return true;
    return false;
}

// Called only by the owning root broker, on ACM's work loop, after its ELAN worker has finished matching.
static inline void nativeProviderSubmit(const NativeProviderAPI &api, NativeProviderState &state,
                                        const NativeProviderRequest &request, NativeProviderReport &report) {
    report = {};
    report.abi = 1;
    if (!state.active) { report.operationStatus = NativeProviderNotActive; return; }
    if (request.abi != 1 || request.user != state.user || request.matched > 1 || request.reserved ||
        !request.sequence || request.sequence <= state.lastSequence ||
        !nativeProviderHasIdentity(state, request.identity) || !nativeNonzeroBytes(request.context, 16)) {
        report.operationStatus = NativeProviderInvalid;
        return;
    }
    // Consume a sequence even on a rejected context so a late worker reply cannot replay it.
    state.lastSequence = request.sequence;
    uint8_t context[16];
    memcpy(context, request.context, sizeof(context));
    int status = api.emptyPrivateContext(context);
    uint32_t observed = 0;
    if (!status) status = nativeStudyPolicy(api.acm, context, state.user, false, &observed);
    if (status || !request.matched) { report.operationStatus = status; return; }
    void *credential = nullptr;
    uint32_t user = state.user, flags = 4;
    status = api.acm.createCredential(3, &credential);
    if (!status && !credential) status = NativeStudyUnexpected;
    if (!status) status = api.acm.setProperty(credential, 5, &user, sizeof(user));
    if (!status) status = api.acm.setProperty(credential, 101, &flags, sizeof(flags));
    if (!status) status = api.acm.setProperty(credential, 100, request.identity, sizeof(request.identity));
    if (!status) {
        status = api.acm.addCredential(context, credential, 1, NativeBiometryProvider);
        if (!status) { credential = nullptr; report.credentialAdded = 1; }
    }
    if (credential) api.acm.deleteCredential(credential);
    const unsigned properties[] = {5, 101, 100};
    const void *values[] = {&user, &flags, request.identity};
    const size_t lengths[] = {sizeof(user), sizeof(flags), sizeof(request.identity)};
    for (unsigned i = 0; !status && i < 3; i++) {
        uint8_t value[16] = {};
        size_t actual = lengths[i];
        status = api.acm.readProperty(context, 3, properties[i], value, &actual);
        if (!status && (actual != lengths[i] || memcmp(value, values[i], actual))) status = NativeStudyUnexpected;
        if (!status) report.propertiesVerified |= 1U << i;
    }
    if (!status) status = nativeStudyPolicy(api.acm, context, user, true, &report.matchedPolicy);
    if (!status) status = nativeStudyPolicy(api.acm, context, user + 1, false, &report.wrongUserPolicy);
    report.operationStatus = status;
    // Accepted credentials belong to the requesting ACM context. Its LAContext owner invalidates it.
    // If verification fails, withdraw provider availability before any success callback can be sent.
    if (status && report.credentialAdded) {
        state.quarantined = true;
        for (unsigned i = 0; i < 16; i++) state.failedContext[i] = context[i];
        report.restoreStatus = nativeProviderStop(api, state);
    }
}
