#include "NativeCredentialStudy.h"
#include "NativeEnvironmentSlot.h"
#include <assert.h>
#include <stdio.h>

struct FixtureCredential { uint32_t user, flags; uint8_t identity[16]; };
struct FixtureContext { FixtureCredential *credential; };
static unsigned calls, failAt, liveContexts, liveCredentials, liveRequirements;
static uint8_t availability;
static bool failEnableAfterWrite, failRestore, leakAcrossContexts, ignoreUser;
static int operation() { return ++calls == failAt ? -73 : 0; }
static int preflight(bool, uint32_t *present) { *present = 1; return operation(); }
static int getAvailability(uint64_t, unsigned slot, uint8_t *value, bool) {
    assert(slot == 6); *value = availability; return 0;
}
static int setAvailability(uint64_t permissions, unsigned slot, const void *value, size_t length) {
    assert(permissions == NativeBiometryProvider && slot == 6 && length == 1);
    uint8_t next = *static_cast<const uint8_t *>(value);
    if (!next && failRestore) return -74;
    availability = next;
    return next && failEnableAfterWrite ? -75 : 0;
}
static int createContext(void **out) {
    if (int error = operation()) return error;
    *out = new FixtureContext {}; liveContexts++; return 0;
}
static void deleteCredential(void *value) {
    assert(value && liveCredentials); liveCredentials--; delete static_cast<FixtureCredential *>(value);
}
static int deleteContext(void *value, bool destroy) {
    assert(value && destroy && liveContexts);
    auto *context = static_cast<FixtureContext *>(value);
    if (context->credential) deleteCredential(context->credential);
    delete context; liveContexts--; return 0;
}
static int createCredential(unsigned type, void **out) {
    assert(type == 3);
    if (int error = operation()) return error;
    *out = new FixtureCredential {}; liveCredentials++; return 0;
}
static void *property(FixtureCredential *credential, unsigned property, size_t length) {
    if (property == 5) { assert(length == 4); return &credential->user; }
    if (property == 101) { assert(length == 4); return &credential->flags; }
    assert(property == 100 && length == 16); return credential->identity;
}
static int setProperty(void *value, unsigned key, const void *bytes, size_t length) {
    if (int error = operation()) return error;
    memcpy(property(static_cast<FixtureCredential *>(value), key, length), bytes, length); return 0;
}
static int addCredential(const void *handle, void *credential, unsigned scope, uint64_t permission) {
    assert(scope == 1 && permission == NativeBiometryProvider);
    if (int error = operation()) return error;
    auto *context = const_cast<FixtureContext *>(static_cast<const FixtureContext *>(handle));
    assert(!context->credential); context->credential = static_cast<FixtureCredential *>(credential); return 0;
}
static int readProperty(void *handle, unsigned type, unsigned key, void *bytes, size_t *length) {
    assert(type == 3);
    if (int error = operation()) return error;
    auto *context = static_cast<FixtureContext *>(handle);
    assert(context->credential); memcpy(bytes, property(context->credential, key, *length), *length); return 0;
}
static int verifyPolicy(void *handle, const char *policy, const NativeACMParameter *parameters,
                        unsigned count, unsigned age, bool *satisfied, void **requirement) {
    assert(!strcmp(policy, "DeviceOwnerAuthenticationWithBiometrics"));
    assert(count == 1 && parameters->type == 4 && parameters->length == 4 && age == 0);
    if (int error = operation()) return error;
    auto *context = static_cast<FixtureContext *>(handle);
    uint32_t user = *static_cast<const uint32_t *>(parameters->value);
    *satisfied = availability && ((context->credential && (ignoreUser || context->credential->user == user)) || leakAcrossContexts);
    *requirement = new unsigned(3); liveRequirements++; return 0;
}
static int deleteRequirement(void *value) {
    assert(value && liveRequirements); liveRequirements--; delete static_cast<unsigned *>(value); return 0;
}
static NativeCredentialStudyAPI api {preflight, getAvailability, setAvailability, createContext, deleteContext,
    createCredential, deleteCredential, setProperty, addCredential, readProperty, verifyPolicy, deleteRequirement};
static void reset() {
    assert(!liveContexts && !liveCredentials && !liveRequirements);
    calls = failAt = 0; availability = 0;
    failEnableAfterWrite = failRestore = leakAcrossContexts = ignoreUser = false;
}
static NativeCredentialStudyReport study(bool policy, bool &pending) {
    NativeCredentialStudyReport report {};
    runNativeCredentialStudy(api, policy, pending, report);
    assert(!liveContexts && !liveCredentials && !liveRequirements);
    return report;
}
int main() {
    uint8_t storedAvailability = 0;
    NativeEnvironmentSlot slot {};
    slot.identifier = 6;
    slot.setPermissions = 0x0002090000000000ULL;
    slot.validation = &storedAvailability;
    slot.timestamp = 123456789;
    slot.data = &storedAvailability;
    slot.length = 1;
    assert(nativeEnvironmentMismatches(slot, slot.validation, NativeBiometryProvider) == 0);
    slot.flags = 4;
    assert(nativeEnvironmentMismatches(slot, slot.validation, NativeBiometryProvider) == (1U << 1));
    slot.flags = 0;
    slot.setCallback = &storedAvailability;
    assert(nativeEnvironmentMismatches(slot, slot.validation, NativeBiometryProvider) == (1U << 5));
    slot.setCallback = nullptr;
    slot.data = nullptr;
    slot.length = 0;
    assert(nativeEnvironmentMismatches(slot, slot.validation, NativeBiometryProvider) == 0);
    bool pending = false;
    reset();
    auto report = study(false, pending);
    assert(report.passed && report.credentialsAdded == 1 && !report.availabilityWriteAttempted && !availability);
    reset();
    report = study(true, pending);
    assert(report.passed && report.policySatisfied[3] && !report.policySatisfied[2] && !report.policySatisfied[4]);
    assert(report.contextsCreated == 2 && report.contextsDeleted == 2 && !pending && !availability);
    unsigned operations = calls;
    for (unsigned point = 1; point <= operations; point++) {
        reset(); failAt = point; report = study(true, pending);
        assert(!report.passed && !pending && !availability);
    }
    reset(); failEnableAfterWrite = true; report = study(true, pending);
    assert(!report.passed && report.availabilityWriteAttempted && !pending && !availability);
    reset(); failRestore = true; report = study(true, pending);
    assert(!report.passed && pending && availability == 1);
    report = study(true, pending);
    assert(!report.passed && !report.contextsCreated && !report.availabilityWriteAttempted && pending);
    pending = false;
    reset(); leakAcrossContexts = true; report = study(true, pending);
    assert(!report.passed && report.stepStatus[StudyControlPolicy] == NativeStudyUnexpected && !availability);
    reset(); ignoreUser = true; report = study(true, pending);
    assert(!report.passed && report.stepStatus[StudyWrongUserPolicy] == NativeStudyUnexpected && !availability);
    printf("credential study: initialized environment timestamp, callback/persistence guards, happy paths, %u operation failures, partial write, restore failure, context and user isolation passed\n", operations);
}
