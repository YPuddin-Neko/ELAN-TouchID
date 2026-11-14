#include "NativeProviderSession.h"
#include <assert.h>
#include <stdio.h>

struct Credential { uint32_t uid, flags; uint8_t identity[16]; };
static Credential *accepted;
static unsigned allocations, calls, failAt, additions;
static uint8_t availability;
static bool failEnableAfterWrite, failRestore, wrongUserAccepted;
static const uint8_t handle[16] = {0x51,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f};
static int operation() { return ++calls == failAt ? -70 : 0; }
static int preflight(bool enabled, uint32_t *present) { assert(enabled); *present = 1; return operation(); }
static int getAvailability(uint64_t permission, unsigned slot, uint8_t *value, bool parameters) {
    assert(permission == NativeEnvironmentReader && slot == 6 && !parameters);
    *value = availability; return 0;
}
static int setAvailability(uint64_t permission, unsigned slot, const void *bytes, size_t length) {
    assert(permission == NativeBiometryProvider && slot == 6 && length == 1);
    uint8_t value = *static_cast<const uint8_t *>(bytes);
    if (!value && failRestore) return -71;
    availability = value;
    return value && failEnableAfterWrite ? -72 : 0;
}
static int empty(const uint8_t *context) {
    if (int status = operation()) return status;
    if (memcmp(context, handle, 16)) return -2;
    return accepted ? NativeProviderBusy : 0;
}
static int create(unsigned type, void **out) {
    assert(type == 3);
    if (int status = operation()) return status;
    *out = new Credential {}; allocations++; return 0;
}
static void destroy(void *credential) {
    assert(credential && allocations); allocations--; delete static_cast<Credential *>(credential);
}
static void *field(Credential *credential, unsigned property, size_t length) {
    if (property == 5) { assert(length == 4); return &credential->uid; }
    if (property == 101) { assert(length == 4); return &credential->flags; }
    assert(property == 100 && length == 16); return credential->identity;
}
static int setProperty(void *credential, unsigned property, const void *bytes, size_t length) {
    if (int status = operation()) return status;
    memcpy(field(static_cast<Credential *>(credential), property, length), bytes, length); return 0;
}
static int add(const void *context, void *credential, unsigned scope, uint64_t permission) {
    assert(!memcmp(context, handle, 16) && scope == 1 && permission == NativeBiometryProvider && !accepted);
    if (int status = operation()) return status;
    accepted = static_cast<Credential *>(credential); additions++; return 0;
}
static int readProperty(void *context, unsigned type, unsigned property, void *bytes, size_t *length) {
    assert(!memcmp(context, handle, 16) && type == 3 && accepted);
    if (int status = operation()) return status;
    memcpy(bytes, field(accepted, property, *length), *length); return 0;
}
static int verify(void *context, const char *policy, const NativeACMParameter *parameters,
                  unsigned count, unsigned age, bool *satisfied, void **requirement) {
    assert(!memcmp(context, handle, 16) && !strcmp(policy, "DeviceOwnerAuthenticationWithBiometrics"));
    assert(count == 1 && parameters->type == 4 && parameters->length == 4 && !age);
    if (int status = operation()) return status;
    *requirement = nullptr;
    uint32_t user = *static_cast<const uint32_t *>(parameters->value);
    *satisfied = availability && accepted && (accepted->uid == user || wrongUserAccepted);
    return 0;
}
static NativeProviderAPI api {{preflight, getAvailability, setAvailability, nullptr, nullptr,
    create, destroy, setProperty, add, readProperty, verify, nullptr}, empty};
static void reset() {
    if (accepted) { destroy(accepted); accepted = nullptr; }
    assert(!allocations);
    calls = failAt = additions = 0; availability = 0;
    failEnableAfterWrite = failRestore = wrongUserAccepted = false;
}
static NativeProviderRequest startRequest() {
    NativeProviderRequest request {};
    request.abi = 1; request.user = 501;
    memcpy(request.identity, handle, 16); request.identity[0] = 0x77;
    return request;
}
static NativeProviderRequest matchRequest(uint64_t sequence, bool matched) {
    auto request = startRequest();
    request.sequence = sequence; request.matched = matched;
    memcpy(request.context, handle, 16); return request;
}
static NativeProviderReport submit(NativeProviderState &state, const NativeProviderRequest &request) {
    NativeProviderReport report {};
    nativeProviderSubmit(api, state, request, report);
    nativeProviderReport(api, state, report);
    return report;
}
int main() {
    NativeProviderState state {};
    reset();
    auto begin = startRequest();
    assert(!nativeProviderStart(api, state, begin) && state.active && availability == 1);
    assert(nativeProviderStart(api, state, begin) == NativeProviderBusy);
    auto negative = submit(state, matchRequest(1, false));
    assert(!negative.operationStatus && !negative.credentialAdded && !additions && state.active);
    auto positive = submit(state, matchRequest(2, true));
    assert(!positive.operationStatus && positive.credentialAdded && positive.matchedPolicy &&
           !positive.wrongUserPolicy && positive.propertiesVerified == 7 && additions == 1);
    assert(submit(state, matchRequest(2, true)).operationStatus == NativeProviderInvalid);
    assert(submit(state, matchRequest(3, true)).operationStatus == NativeProviderBusy && additions == 1);
    assert(!nativeProviderStop(api, state) && !availability && !state.active && !state.restorePending);
    // The external context, including its accepted credential, is owned by LAContext.
    assert(accepted && allocations == 1);
    reset();
    assert(!nativeProviderStart(api, state, begin));
    calls = 0;
    positive = submit(state, matchRequest(1, true));
    assert(!positive.operationStatus);
    unsigned count = calls;
    assert(!nativeProviderStop(api, state));
    for (unsigned failure = 1; failure <= count; failure++) {
        reset(); state = {};
        assert(!nativeProviderStart(api, state, begin));
        calls = 0; failAt = failure;
        auto report = submit(state, matchRequest(1, true));
        assert(report.operationStatus);
        if (report.credentialAdded) {
            assert(!state.active && !state.restorePending && !availability && state.quarantined);
            assert(nativeProviderStart(api, state, begin) == NativeProviderBusy);
            assert(nativeProviderStop(api, state) == NativeProviderBusy);
        }
        assert(allocations == (accepted ? 1U : 0U));
        if (accepted) { destroy(accepted); accepted = nullptr; }
        assert(!nativeProviderStop(api, state));
    }
    reset(); state = {}; failEnableAfterWrite = true;
    assert(nativeProviderStart(api, state, begin) == -72 && !state.active && !state.restorePending && !availability);
    reset(); failEnableAfterWrite = failRestore = true;
    assert(nativeProviderStart(api, state, begin) == -72 && !state.active && state.restorePending && availability == 1);
    assert(nativeProviderStart(api, state, begin) == NativeProviderBusy);
    failRestore = false;
    assert(!nativeProviderStop(api, state) && !state.restorePending && !availability);
    reset(); state = {}; wrongUserAccepted = true;
    assert(!nativeProviderStart(api, state, begin));
    auto wrong = submit(state, matchRequest(1, true));
    assert(wrong.operationStatus == NativeStudyUnexpected && wrong.wrongUserPolicy && !state.active && !availability);
    assert(state.quarantined && nativeProviderStart(api, state, begin) == NativeProviderBusy);
    reset();
    assert(!nativeProviderStop(api, state) && !state.quarantined);
    auto badUser = begin; badUser.user = 502;
    assert(nativeProviderStart(api, state, badUser) == NativeProviderInvalid && !availability);
    assert(!nativeProviderStart(api, state, begin));
    auto badIdentity = matchRequest(1, true); badIdentity.identity[0] ^= 1;
    assert(submit(state, badIdentity).operationStatus == NativeProviderInvalid && !additions);
    auto badHandle = matchRequest(2, true); badHandle.context[0] ^= 1;
    assert(submit(state, badHandle).operationStatus == -2 && !additions);
    assert(submit(state, matchRequest(2, true)).operationStatus == NativeProviderInvalid && !additions);
    assert(!nativeProviderStop(api, state));
    reset();
    NativeProviderCatalogRequest catalog {};
    catalog.abi = 1; catalog.user = 501;
    assert(!nativeProviderStartCatalog(api, state, catalog) && state.identityCount == 0);
    assert(submit(state, matchRequest(1, true)).operationStatus == NativeProviderInvalid && !additions);
    catalog.count = 3; catalog.sequence = 1;
    for (unsigned i = 0; i < 3; i++) {
        memcpy(catalog.identities[i], begin.identity, 16);
        catalog.identities[i][0] += i;
    }
    assert(!nativeProviderReplaceCatalog(state, catalog) && state.identityCount == 3 && state.lastSequence == 1);
    NativeProviderCatalogReport catalogReport {};
    nativeProviderCatalogReport(api, state, catalogReport);
    assert(catalogReport.count == 3 && !memcmp(catalogReport.identities, catalog.identities, sizeof(catalog.identities)));
    auto secondFinger = matchRequest(2, true);
    memcpy(secondFinger.identity, catalog.identities[1], 16);
    assert(!submit(state, secondFinger).operationStatus && accepted && !memcmp(accepted->identity, secondFinger.identity, 16));
    destroy(accepted); accepted = nullptr;
    auto invalid = catalog; invalid.sequence = 3; invalid.count = 4;
    assert(nativeProviderReplaceCatalog(state, invalid) == NativeProviderInvalid && state.lastSequence == 2);
    invalid = catalog; invalid.sequence = 3; memcpy(invalid.identities[1], invalid.identities[0], 16);
    assert(nativeProviderReplaceCatalog(state, invalid) == NativeProviderInvalid && state.identityCount == 3);
    invalid = catalog; invalid.sequence = 3; memset(invalid.identities[1], 0, 16);
    assert(nativeProviderReplaceCatalog(state, invalid) == NativeProviderInvalid);
    invalid = catalog; invalid.sequence = 3; invalid.user = 502;
    assert(nativeProviderReplaceCatalog(state, invalid) == NativeProviderInvalid);
    invalid = catalog; invalid.sequence = 3; invalid.count = 2;
    assert(nativeProviderReplaceCatalog(state, invalid) == NativeProviderInvalid);
    assert(nativeProviderReplaceCatalog(state, catalog) == NativeProviderInvalid);
    catalog.sequence = 3; catalog.count = 1;
    memset(catalog.identities[1], 0, 32);
    assert(!nativeProviderReplaceCatalog(state, catalog));
    secondFinger.sequence = 4;
    assert(submit(state, secondFinger).operationStatus == NativeProviderInvalid && !accepted && additions == 1);
    // Even an identity that remains registered cannot reuse a capture from before replacement.
    assert(submit(state, matchRequest(2, true)).operationStatus == NativeProviderInvalid);
    assert(!submit(state, matchRequest(4, true)).operationStatus && accepted);
    destroy(accepted); accepted = nullptr;
    catalog.sequence = 5; catalog.count = 0; memset(catalog.identities, 0, sizeof(catalog.identities));
    assert(!nativeProviderReplaceCatalog(state, catalog) && !state.identityCount);
    assert(submit(state, matchRequest(6, true)).operationStatus == NativeProviderInvalid && !accepted);
    assert(!nativeProviderStop(api, state) && !state.identityCount && !availability);
    assert(nativeProviderReplaceCatalog(state, catalog) == NativeProviderNotActive);
    reset();
    printf("provider session: negative/positive, wrong user, replay, context ownership, %u failure points, restoration retry and three-identity replacement/removal passed\n", count);
}
