#include "NativeDirectEnrollment.h"
#include "NativeEnrollmentDiagnostics.h"
#include "NativeSettingsEnrollmentAuthorization.h"
#define ELAN_RELAX_SERVICE_HASH_CHECK 1
#include "../agent-integration-candidate/permit-driver-candidate/KernelBinding.h"
#undef ELAN_RELAX_SERVICE_HASH_CHECK
#include "ElanEnrollmentServiceIdentity.h"

namespace {
ElanPermitKernelBinding::Bound directBinding;
uint32_t directEnrollmentReady;
NativeEnrollmentDiagnostics::State directEnrollmentDiagnostic;
uint8_t elanCapturedPassphrase[128]{};
uint32_t elanCapturedPassphraseLen = 0;
mach_vm_address_t origACMSetProperty = 0;

int wrapACMSetProperty(void *cred, unsigned prop, const void *data, size_t len) {
    if (cred && data && len >= 1 && len <= sizeof(elanCapturedPassphrase)) {
        const uint32_t ctype = *reinterpret_cast<const uint32_t *>(cred);
        if ((ctype == 2 && prop == 200) || (ctype == 13 && prop == 701)) {
            memcpy(elanCapturedPassphrase, data, len);
            __atomic_store_n(&elanCapturedPassphraseLen, static_cast<uint32_t>(len), __ATOMIC_RELEASE);
        }
    }
    return reinterpret_cast<int (*)(void *, unsigned, const void *, size_t)>(origACMSetProperty)(cred, prop, data, len);
}

void prepareDirectEnrollment(KernelPatcher &patcher) {
    auto resolve = [](void *context, const char *name) -> uintptr_t {
        auto &owner = *static_cast<KernelPatcher *>(context);
        owner.clearError();
        auto address = owner.solveSymbol(KernelPatcher::KernelID, name);
        return owner.getError() == KernelPatcher::Error::NoError ? address : 0;
    };
    auto readHeader = [](void *, uintptr_t address, void *out, size_t size) {
        memcpy(out, reinterpret_cast<const void *>(address), size);
        return true;
    };
    auto readSymbol = [](void *, uintptr_t address, void *out, size_t size) {
        memcpy(out, reinterpret_cast<const void *>(address), size);
        return size;
    };
    uint64_t slide = 0;
    uint8_t uuid[16]{};
    if (RetirementRuntime::inspectKernelHeader(resolve, &patcher, readHeader, nullptr, slide, uuid) &&
        ElanPermitKernelBinding::bind(resolve, readSymbol, &patcher, slide, uuid, directBinding)) {
        if (studyAPI.setProperty && !origACMSetProperty) {
            KernelPatcher::RouteRequest req("_LibCall_ACMCredentialSetProperty", wrapACMSetProperty, origACMSetProperty);
            if (patcher.routeMultiple(acmInfo.loadIndex, &req, 1) && origACMSetProperty) {
                studyAPI.setProperty = wrapACMSetProperty;
            }
            patcher.clearError();
        }
        __atomic_store_n(&directEnrollmentReady, 1U, __ATOMIC_RELEASE);
    }
}

int directEnrollmentVerifyPolicy(const uint8_t *context, uint32_t expectedUser, bool *matched) {
    uint8_t handle[16]{};
    memcpy(handle, context, sizeof(handle));
    uint32_t observed = 0;
    int status = nativeEnrollmentPolicy(enrollmentAPI, handle, expectedUser, observed);
    *matched = status == 0 && observed != 0;
    return status;
}

IOReturn directEnrollmentGated(OSObject *, void *rawContext, void *rawReply, void *rawTrustedSource, void *) {
    auto &input = *static_cast<const ElanDirectEnrollmentContext *>(rawContext);
    auto &out = *static_cast<ElanDirectEnrollmentReply *>(rawReply);
    NativeSettingsEnrollmentAuthorization::Input authInput{};
    authInput.trustedSettingsSource = rawTrustedSource != nullptr;
    authInput.privateContext = globalContextHandle && nullContextHandle &&
        memcmp(input.handle, globalContextHandle, 16) && memcmp(input.handle, nullContextHandle, 16);
    authInput.expectedUser = directServiceIdentity.binary.uid;
    memcpy(authInput.context, input.handle, sizeof(authInput.context));
    const NativeSettingsEnrollmentAuthorization::API authAPI{
        copyStudyCredentials, deallocStudyCredentials, getStudyProperty, directEnrollmentVerifyPolicy
    };
    const auto result = NativeSettingsEnrollmentAuthorization::authorize(authAPI, authInput);
    if (result.authorized && copyStudyCredentials && deallocStudyCredentials && getStudyProperty) {
        const unsigned types[2] = {2, 13};
        const unsigned props[2] = {200, 701};
        for (unsigned k = 0; k < 2; ++k) {
            void **list = nullptr;
            unsigned count = 0;
            if (!copyStudyCredentials(input.handle, types[k], 0, &list, &count) && list) {
                if (count > 0 && count <= 64 && list[0]) {
                    const void *val = nullptr;
                    size_t sz = 0;
                    if (!getStudyProperty(list[0], props[k], &val, &sz) && val && sz >= 1 && sz <= sizeof(elanCapturedPassphrase)) {
                        memcpy(elanCapturedPassphrase, val, sz);
                        __atomic_store_n(&elanCapturedPassphraseLen, static_cast<uint32_t>(sz), __ATOMIC_RELEASE);
                    }
                }
                deallocStudyCredentials(list, count);
            }
        }
    }
    const uint32_t seenTypes = (result.exactUIDSeen ? 1U : 0U) | (result.wildcardSeen ? 2U : 0U);
    uint32_t rejectKind = NativeEnrollmentMatch;
    if (!result.authorized) {
        using Reject = NativeSettingsEnrollmentAuthorization::Reject;
        switch (result.reject) {
        case Reject::None: rejectKind = NativeEnrollmentUnobserved; break;
        case Reject::Source: rejectKind = NativeEnrollmentInactive; break;
        case Reject::Context: rejectKind = NativeEnrollmentContext; break;
        case Reject::API: rejectKind = NativeEnrollmentRequestInvalid; break;
        case Reject::Copy: rejectKind = NativeEnrollmentCopyError; break;
        case Reject::Shape: rejectKind = NativeEnrollmentShape; break;
        case Reject::Principal: rejectKind = NativeEnrollmentOtherPrincipal; break;
        case Reject::Flags: rejectKind = NativeEnrollmentWildcard; break;
        case Reject::Property: rejectKind = NativeEnrollmentPropertyError; break;
        case Reject::Policy: rejectKind = NativeEnrollmentPolicy; break;
        }
    }
    const int32_t status = result.authorized ? 0 :
        (result.operationStatus ? result.operationStatus : NativeEnrollmentNotAuthorized);
    directEnrollmentDiagnostic.record(status, rejectKind, seenTypes ? 1U : 0U, seenTypes,
        result.authorized, result.authorized);
    out = {1, result.authorized ? 1U : 0U};
    return kIOReturnSuccess;
}
#ifdef ELAN_AUTOMATIC_SETTINGS
static uint64_t directMatchSequence;

IOReturn directListenerAvailabilityGated(OSObject *, void *rawEnable, void *rawStatus, void *, void *) {
    const bool enable = rawEnable != nullptr;
    auto &out = *static_cast<int *>(rawStatus);
    if (enable) {
        if (availabilityRestorePending || providerState.active || providerState.quarantined) {
            out = NativeProviderBusy;
            return kIOReturnSuccess;
        }
        uint32_t present = 0;
        int status = studyAPI.preflight(true, &present);
        uint8_t before = 0xff;
        if (!status) status = studyAPI.getAvailability(NativeEnvironmentReader, 6, &before, false);
        if (status) { out = status; return kIOReturnSuccess; }
        if (before != 0) { out = NativeProviderBusy; return kIOReturnSuccess; }
        availabilityRestorePending = true;
        uint8_t one = 1, after = 0xff;
        status = studyAPI.setAvailability(NativeBiometryProvider, 6, &one, 1);
        int read = studyAPI.getAvailability(NativeEnvironmentReader, 6, &after, false);
        if (!status && (read || after != 1)) status = read ? read : NativeStudyUnexpected;
        if (status) {
            uint8_t zero = 0, restored = 0xff;
            studyAPI.setAvailability(NativeBiometryProvider, 6, &zero, 1);
            if (!studyAPI.getAvailability(NativeEnvironmentReader, 6, &restored, false) && restored == 0)
                availabilityRestorePending = false;
        } else {
            memset(&providerState, 0, sizeof(providerState));
            providerState.user = directServiceIdentity.binary.uid;
            providerState.active = true;
            providerState.restorePending = false;
            directMatchSequence = 0;
        }
        out = status;
        return kIOReturnSuccess;
    }
    providerState.active = false;
    directMatchSequence = 0;
    if (!providerState.quarantined) memset(&providerState, 0, sizeof(providerState));
    if (!availabilityRestorePending) { out = 0; return kIOReturnSuccess; }
    uint8_t zero = 0, after = 0xff;
    int status = studyAPI.setAvailability(NativeBiometryProvider, 6, &zero, 1);
    int read = studyAPI.getAvailability(NativeEnvironmentReader, 6, &after, false);
    if (!read && after == 0) {
        availabilityRestorePending = false;
        out = 0;
    } else {
        out = status ? status : read ? read : NativeStudyUnexpected;
    }
    return kIOReturnSuccess;
}

IOReturn directCatalogSyncGated(OSObject *, void *rawInput, void *rawReply, void *rawTrustedSource, void *) {
    const auto &input = *static_cast<const ElanDirectCatalogSync *>(rawInput);
    auto &out = *static_cast<ElanDirectOperationReply *>(rawReply);
    if (!rawTrustedSource) { out = {1, NativeProviderNotActive}; return kIOReturnSuccess; }
    if (!availabilityRestorePending || !providerState.active || providerState.quarantined) {
        out = {1, NativeProviderNotActive};
        return kIOReturnSuccess;
    }
    NativeProviderCatalogRequest request{};
    request.abi = input.abi;
    request.user = directServiceIdentity.binary.uid;
    request.sequence = providerState.lastSequence + 1;
    request.count = input.count;
    memcpy(request.identities, input.identities, sizeof(request.identities));
    out = {1, nativeProviderReplaceCatalog(providerState, request)};
    return kIOReturnSuccess;
}

IOReturn directMatchSubmitGated(OSObject *, void *rawInput, void *rawReply, void *rawTrustedSource, void *) {
    const auto &input = *static_cast<const ElanDirectMatchSubmission *>(rawInput);
    auto &out = *static_cast<ElanDirectOperationReply *>(rawReply);
    if (!rawTrustedSource) { out = {1, NativeProviderNotActive}; return kIOReturnSuccess; }
    if (!availabilityRestorePending || !providerState.active || providerState.quarantined) {
        out = {1, NativeProviderNotActive};
        return kIOReturnSuccess;
    }
    if (input.abi != 1 || !input.sequence || input.sequence <= directMatchSequence) {
        out = {1, NativeProviderInvalid};
        return kIOReturnSuccess;
    }
    directMatchSequence = input.sequence;
    NativeProviderRequest request{};
    request.abi = 1;
    request.user = directServiceIdentity.binary.uid;
    request.sequence = providerState.lastSequence + 1;
    request.matched = input.matched;
    memcpy(request.identity, input.identity, sizeof(request.identity));
    memcpy(request.context, input.context, sizeof(request.context));
    NativeProviderReport report{};
    nativeProviderSubmit(providerAPI, providerState, request, report);
    if (providerState.quarantined && availabilityRestorePending) {
        uint8_t zero = 0, after = 0xff;
        studyAPI.setAvailability(NativeBiometryProvider, 6, &zero, 1);
        if (!studyAPI.getAvailability(NativeEnvironmentReader, 6, &after, false) && after == 0)
            availabilityRestorePending = false;
    }
    out = {1, report.operationStatus};
    return kIOReturnSuccess;
}

int directSetListenerAvailability(bool enable) {
    auto *matching = IOService::serviceMatching("AppleCredentialManager");
    IOService *acm = matching ? IOService::copyMatchingService(matching) : nullptr;
    if (matching) matching->release();
    auto *loop = acm ? acm->getWorkLoop() : nullptr;
    int acmStatus = NativeStudyUnexpected;
    IOReturn call = loop ? loop->runAction(directListenerAvailabilityGated, acm,
        enable ? reinterpret_cast<void *>(1) : nullptr, &acmStatus) : kIOReturnNotReady;
    if (acm) acm->release();
    return call ? call : acmStatus;
}

bool elanMapAsciiToADB(uint8_t ch, uint8_t &keyCode, bool &shift) {
    shift = false;
    switch (ch) {
    case 'a': case 'A': keyCode = 0x00; shift = (ch == 'A'); return true;
    case 's': case 'S': keyCode = 0x01; shift = (ch == 'S'); return true;
    case 'd': case 'D': keyCode = 0x02; shift = (ch == 'D'); return true;
    case 'f': case 'F': keyCode = 0x03; shift = (ch == 'F'); return true;
    case 'h': case 'H': keyCode = 0x04; shift = (ch == 'H'); return true;
    case 'g': case 'G': keyCode = 0x05; shift = (ch == 'G'); return true;
    case 'z': case 'Z': keyCode = 0x06; shift = (ch == 'Z'); return true;
    case 'x': case 'X': keyCode = 0x07; shift = (ch == 'X'); return true;
    case 'c': case 'C': keyCode = 0x08; shift = (ch == 'C'); return true;
    case 'v': case 'V': keyCode = 0x09; shift = (ch == 'V'); return true;
    case 'b': case 'B': keyCode = 0x0b; shift = (ch == 'B'); return true;
    case 'q': case 'Q': keyCode = 0x0c; shift = (ch == 'Q'); return true;
    case 'w': case 'W': keyCode = 0x0d; shift = (ch == 'W'); return true;
    case 'e': case 'E': keyCode = 0x0e; shift = (ch == 'E'); return true;
    case 'r': case 'R': keyCode = 0x0f; shift = (ch == 'R'); return true;
    case 'y': case 'Y': keyCode = 0x10; shift = (ch == 'Y'); return true;
    case 't': case 'T': keyCode = 0x11; shift = (ch == 'T'); return true;
    case '1': case '!': keyCode = 0x12; shift = (ch == '!'); return true;
    case '2': case '@': keyCode = 0x13; shift = (ch == '@'); return true;
    case '3': case '#': keyCode = 0x14; shift = (ch == '#'); return true;
    case '4': case '$': keyCode = 0x15; shift = (ch == '$'); return true;
    case '6': case '^': keyCode = 0x16; shift = (ch == '^'); return true;
    case '5': case '%': keyCode = 0x17; shift = (ch == '%'); return true;
    case '=': case '+': keyCode = 0x18; shift = (ch == '+'); return true;
    case '9': case '(': keyCode = 0x19; shift = (ch == '('); return true;
    case '7': case '&': keyCode = 0x1a; shift = (ch == '&'); return true;
    case '-': case '_': keyCode = 0x1b; shift = (ch == '_'); return true;
    case '8': case '*': keyCode = 0x1c; shift = (ch == '*'); return true;
    case '0': case ')': keyCode = 0x1d; shift = (ch == ')'); return true;
    case ']': case '}': keyCode = 0x1e; shift = (ch == '}'); return true;
    case 'o': case 'O': keyCode = 0x1f; shift = (ch == 'O'); return true;
    case 'u': case 'U': keyCode = 0x20; shift = (ch == 'U'); return true;
    case '[': case '{': keyCode = 0x21; shift = (ch == '{'); return true;
    case 'i': case 'I': keyCode = 0x22; shift = (ch == 'I'); return true;
    case 'p': case 'P': keyCode = 0x23; shift = (ch == 'P'); return true;
    case 'l': case 'L': keyCode = 0x25; shift = (ch == 'L'); return true;
    case 'j': case 'J': keyCode = 0x26; shift = (ch == 'J'); return true;
    case '\'': case '"': keyCode = 0x27; shift = (ch == '"'); return true;
    case 'k': case 'K': keyCode = 0x28; shift = (ch == 'K'); return true;
    case ';': case ':': keyCode = 0x29; shift = (ch == ':'); return true;
    case '\\': case '|': keyCode = 0x2a; shift = (ch == '|'); return true;
    case ',': case '<': keyCode = 0x2b; shift = (ch == '<'); return true;
    case '/': case '?': keyCode = 0x2c; shift = (ch == '?'); return true;
    case 'n': case 'N': keyCode = 0x2d; shift = (ch == 'N'); return true;
    case 'm': case 'M': keyCode = 0x2e; shift = (ch == 'M'); return true;
    case '.': case '>': keyCode = 0x2f; shift = (ch == '>'); return true;
    case ' ': keyCode = 0x31; shift = false; return true;
    case '`': case '~': keyCode = 0x32; shift = (ch == '~'); return true;
    default: return false;
    }
}

IOReturn directClearAlphaLockGated(OSObject *owner, void *, void *, void *, void *) {
    auto *kbd = static_cast<IOService *>(owner);
    if (!kbd) return kIOReturnBadArgument;
    auto *vtable = *reinterpret_cast<uintptr_t * const *>(kbd);
    if (!vtable) return kIOReturnUnsupported;
    using AlphaLockFn = bool (*)(IOService *);
    using SetAlphaLockFn = void (*)(IOService *, bool);
    auto alphaLock = reinterpret_cast<AlphaLockFn>(vtable[0x900 / sizeof(uintptr_t)]);
    auto setAlphaLock = reinterpret_cast<SetAlphaLockFn>(vtable[0x908 / sizeof(uintptr_t)]);
    if (alphaLock && setAlphaLock && alphaLock(kbd)) {
        setAlphaLock(kbd, false);
    }
    return kIOReturnSuccess;
}

IOReturn directDispatchOneKeyEventGated(OSObject *owner, void *arg0, void *arg1, void *, void *) {
    auto *kbd = static_cast<IOService *>(owner);
    if (!kbd) return kIOReturnBadArgument;
    auto *vtable = *reinterpret_cast<uintptr_t * const *>(kbd);
    if (!vtable) return kIOReturnUnsupported;
    using DispatchFn = void (*)(IOService *, unsigned int, bool, uint64_t);
    auto dispatchKey = reinterpret_cast<DispatchFn>(vtable[0x880 / sizeof(uintptr_t)]);
    if (!dispatchKey) return kIOReturnUnsupported;
    const unsigned int keyCode = static_cast<unsigned int>(reinterpret_cast<uintptr_t>(arg0));
    const bool goingDown = arg1 != nullptr;
    uint64_t now = 0;
    clock_get_uptime(&now);
    dispatchKey(kbd, keyCode, goingDown, now);
    return kIOReturnSuccess;
}

void directSendKeyEvent(IOService *kbd, IOWorkLoop *loop, unsigned int keyCode, bool goingDown) {
    void *codeArg = reinterpret_cast<void *>(static_cast<uintptr_t>(keyCode));
    void *downArg = goingDown ? reinterpret_cast<void *>(1) : nullptr;
    if (loop) {
        loop->runAction(directDispatchOneKeyEventGated, kbd, codeArg, downArg);
    } else {
        directDispatchOneKeyEventGated(kbd, codeArg, downArg, nullptr, nullptr);
    }
}

int32_t directDispatchUnlockKeystrokes(const ElanDirectUnlockRequest &req) {
    if (req.abi != 1 || req.length < 1 || req.length > sizeof(req.bytes)) return kIOReturnBadArgument;
    for (uint32_t i = 0; i < req.length; ++i) {
        uint8_t kc = 0;
        bool sh = false;
        if (!elanMapAsciiToADB(req.bytes[i], kc, sh)) return kIOReturnBadArgument;
    }
    auto *matching = IOService::serviceMatching("IOHIKeyboard");
    IOService *kbd = matching ? IOService::copyMatchingService(matching) : nullptr;
    if (matching) matching->release();
    if (!kbd) return kIOReturnNotFound;
    IOWorkLoop *loop = kbd->getWorkLoop();
    if (loop) {
        loop->runAction(directClearAlphaLockGated, kbd);
    } else {
        directClearAlphaLockGated(kbd, nullptr, nullptr, nullptr, nullptr);
    }
    for (uint32_t i = 0; i < req.length; ++i) {
        uint8_t kc = 0;
        bool sh = false;
        elanMapAsciiToADB(req.bytes[i], kc, sh);
        if (sh) {
            directSendKeyEvent(kbd, loop, 0x38, true);
            IOSleep(2);
        }
        directSendKeyEvent(kbd, loop, kc, true);
        IOSleep(4);
        directSendKeyEvent(kbd, loop, kc, false);
        if (sh) {
            IOSleep(2);
            directSendKeyEvent(kbd, loop, 0x38, false);
        }
        IOSleep(8);
    }
    IOSleep(25);
    directSendKeyEvent(kbd, loop, 0x24, true);
    IOSleep(8);
    directSendKeyEvent(kbd, loop, 0x24, false);
    kbd->release();
    return 0;
}
#endif
} // namespace

#ifdef ELAN_AUTOMATIC_SETTINGS
bool elanRegisterSettingsStartup();
bool elanSettingsStartupAvailable();
static OSObject *listenerOwner;
static uint64_t listenerProcessUnique;
static uint32_t listenerEpoch;
static uint64_t listenerGeneration;
uint64_t elanProviderGeneration() { return __atomic_load_n(&listenerGeneration,__ATOMIC_ACQUIRE); }
uint32_t elanStartupAuditSession(void *task) {
    if (!task || !__atomic_load_n(&directEnrollmentReady,__ATOMIC_ACQUIRE) || !studyReady) return 0;
    audit_token_t token{};
    unsigned count=TASK_AUDIT_TOKEN_COUNT;
    if (directBinding.current.taskInfo(task,TASK_AUDIT_TOKEN,reinterpret_cast<int *>(&token),&count) ||
        count!=TASK_AUDIT_TOKEN_COUNT || !ElanPermitIdentity::valid(token)) return 0;
    return token.val[6];
}
bool elanStartupAuditMatches(void *task, uint32_t sessionAsid) {
    if (!task || !sessionAsid || !__atomic_load_n(&directEnrollmentReady,__ATOMIC_ACQUIRE) || !studyReady) return false;
    audit_token_t token{};
    unsigned count=TASK_AUDIT_TOKEN_COUNT;
    if (directBinding.current.taskInfo(task,TASK_AUDIT_TOKEN,reinterpret_cast<int *>(&token),&count) ||
        count!=TASK_AUDIT_TOKEN_COUNT || !ElanPermitIdentity::valid(token) || token.val[6]!=sessionAsid) return false;
    return true;
}
bool elanSettingsAuditMatches(void *task,uint64_t generation) {
    if (!generation || generation!=elanProviderGeneration()) return false;
    audit_token_t token{};
    unsigned count=TASK_AUDIT_TOKEN_COUNT;
    return !directBinding.current.taskInfo(task,TASK_AUDIT_TOKEN,reinterpret_cast<int *>(&token),&count) &&
           count==TASK_AUDIT_TOKEN_COUNT && ElanPermitIdentity::valid(token) &&
           token.val[6]==static_cast<uint32_t>(generation);
}
#endif

class ELANEnrollmentPolicyClient : public IOUserClient {
    OSDeclareDefaultStructors(ELANEnrollmentPolicyClient)
    ElanPermitIdentity::Snapshot opening{};
public:
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args,
                            IOExternalMethodDispatch *, OSObject *, void *) override {
        if (isInactive() || !getProvider()) return kIOReturnNotAttached;
        if (!args || args->asyncWakePort || args->scalarInputCount || args->scalarOutputCount ||
            args->structureInputDescriptor || args->structureOutputDescriptor) return kIOReturnBadArgument;

        ElanPermitIdentity::Snapshot caller{};
        if (!ElanPermitIdentity::capture(directBinding.current, directServiceIdentity,
                                         directBinding.current.binary.currentTask(), caller) ||
            caller.processUnique != opening.processUnique ||
            memcmp(&caller.audit, &opening.audit, sizeof(caller.audit))) return kIOReturnNotPrivileged;
#ifdef ELAN_AUTOMATIC_SETTINGS
        if (selector == ElanPublishSettingsListener) {
            if (args->structureInputSize || args->structureOutputSize) return kIOReturnBadArgument;
            if (!elanSettingsStartupAvailable()) return kIOReturnNotReady;
            IOLockLock(providerLock);
            uint64_t generation = 0;
            IOReturn status = kIOReturnExclusiveAccess;
            if (!isInactive() && !closed && !listenerOwner && listenerEpoch != UINT32_MAX &&
                !availabilityRestorePending) {
                listenerOwner = this;
                listenerProcessUnique = opening.processUnique;
                generation = (static_cast<uint64_t>(++listenerEpoch)<<32) | opening.audit.val[6];
                status = kIOReturnSuccess;
            }
            IOLockUnlock(providerLock);
            if (status) return status;
            int acmStatus = directSetListenerAvailability(true);
            IOLockLock(providerLock);
            if (!acmStatus && !isInactive() && !closed && listenerOwner == this) {
                __atomic_store_n(&listenerGeneration,generation,__ATOMIC_RELEASE);
                IOLockUnlock(providerLock);
                return kIOReturnSuccess;
            }
            const bool needRestore = listenerOwner == this;
            if (needRestore) {
                __atomic_store_n(&listenerGeneration,uint64_t{0},__ATOMIC_RELEASE);
                listenerProcessUnique = 0;
            }
            IOLockUnlock(providerLock);
            if (needRestore) {
                int restored = directSetListenerAvailability(false);
                IOLockLock(providerLock);
                if (!restored && listenerOwner == this) listenerOwner = nullptr;
                IOLockUnlock(providerLock);
            }
            return kIOReturnNotReady;
        }
        if (selector == ElanSyncProviderCatalog || selector == ElanSubmitDirectMatch) {
            const size_t expectedInput = selector == ElanSyncProviderCatalog ?
                sizeof(ElanDirectCatalogSync) : sizeof(ElanDirectMatchSubmission);
            if (!args->structureInput || !args->structureOutput ||
                args->structureInputSize != expectedInput ||
                args->structureOutputSize != sizeof(ElanDirectOperationReply)) return kIOReturnBadArgument;
            const uint64_t generation = elanProviderGeneration();
            bool sameListenerProcess = false;
            IOLockLock(providerLock);
            sameListenerProcess = listenerOwner != nullptr && listenerProcessUnique == opening.processUnique;
            IOLockUnlock(providerLock);
            const bool trustedListener = sameListenerProcess && generation != 0 &&
                static_cast<uint32_t>(generation) == opening.audit.val[6] &&
                elanSettingsAuditMatches(directBinding.current.binary.currentTask(), generation);
            ElanDirectCatalogSync catalogInput{};
            ElanDirectMatchSubmission matchInput{};
            if (selector == ElanSyncProviderCatalog) memcpy(&catalogInput, args->structureInput, sizeof(catalogInput));
            else memcpy(&matchInput, args->structureInput, sizeof(matchInput));
            ElanDirectOperationReply opReply{};
            auto *matching = IOService::serviceMatching("AppleCredentialManager");
            IOService *acm = matching ? IOService::copyMatchingService(matching) : nullptr;
            if (matching) matching->release();
            auto *loop = acm ? acm->getWorkLoop() : nullptr;
            IOReturn opStatus = kIOReturnNotReady;
            if (loop) {
                opStatus = selector == ElanSyncProviderCatalog ?
                    loop->runAction(directCatalogSyncGated, this, &catalogInput, &opReply,
                        trustedListener ? reinterpret_cast<void *>(1) : nullptr) :
                    loop->runAction(directMatchSubmitGated, this, &matchInput, &opReply,
                        trustedListener ? reinterpret_cast<void *>(1) : nullptr);
            }
            if (acm) acm->release();
            if (!opStatus) {
                memcpy(args->structureOutput, &opReply, sizeof(opReply));
                args->structureOutputSize = sizeof(opReply);
            }
            return opStatus;
        }
        if (selector == ElanDispatchUnlockKeystrokes) {
            if (!args->structureInput || !args->structureOutput ||
                args->structureInputSize != sizeof(ElanDirectUnlockRequest) ||
                args->structureOutputSize != sizeof(ElanDirectOperationReply)) return kIOReturnBadArgument;
            const uint64_t generation = elanProviderGeneration();
            bool sameListenerProcess = false;
            IOLockLock(providerLock);
            sameListenerProcess = listenerOwner != nullptr && listenerProcessUnique == opening.processUnique;
            IOLockUnlock(providerLock);
            const bool trustedListener = sameListenerProcess && generation != 0 &&
                static_cast<uint32_t>(generation) == opening.audit.val[6] &&
                elanSettingsAuditMatches(directBinding.current.binary.currentTask(), generation);
            ElanDirectUnlockRequest unlockReq{};
            memcpy(&unlockReq, args->structureInput, sizeof(unlockReq));
            const int32_t unlockStatus = trustedListener ?
                directDispatchUnlockKeystrokes(unlockReq) : NativeProviderNotActive;
            memset(&unlockReq, 0, sizeof(unlockReq));
            ElanDirectOperationReply opReply{1, unlockStatus};
            memcpy(args->structureOutput, &opReply, sizeof(opReply));
            args->structureOutputSize = sizeof(opReply);
            return kIOReturnSuccess;
        }
#endif
        if (selector == ElanCopyEnrollmentPassphrase) {
            if (args->structureInputSize || !args->structureOutput ||
                args->structureOutputSize != sizeof(ElanDirectPassphraseReply)) return kIOReturnBadArgument;
            ElanDirectPassphraseReply pwReply{};
            pwReply.abi = 1;
            uint32_t len = __atomic_load_n(&elanCapturedPassphraseLen, __ATOMIC_ACQUIRE);
            if (len > 0 && len <= sizeof(pwReply.bytes)) {
                pwReply.length = len;
                memcpy(pwReply.bytes, elanCapturedPassphrase, len);
            }
            memcpy(args->structureOutput, &pwReply, sizeof(pwReply));
            args->structureOutputSize = sizeof(pwReply);
            return kIOReturnSuccess;
        }
        if (selector != ElanCheckEnrollment || !args->structureInput || !args->structureOutput ||
            args->structureInputSize != sizeof(ElanDirectEnrollmentContext) ||
            args->structureOutputSize != sizeof(ElanDirectEnrollmentReply)) return kIOReturnBadArgument;
        ElanDirectEnrollmentContext input{};
        memcpy(&input, args->structureInput, sizeof(input));
        ElanDirectEnrollmentReply reply{};
#ifdef ELAN_AUTOMATIC_SETTINGS
        const uint64_t generation = elanProviderGeneration();
        const bool trustedSettingsSource = generation != 0 &&
            static_cast<uint32_t>(generation) == opening.audit.val[6] &&
            elanSettingsAuditMatches(directBinding.current.binary.currentTask(), generation);
#else
        const bool trustedSettingsSource = true;
#endif
        auto *matching = IOService::serviceMatching("AppleCredentialManager");
        IOService *acm = matching ? IOService::copyMatchingService(matching) : nullptr;
        if (matching) matching->release();
        auto *loop = acm ? acm->getWorkLoop() : nullptr;
        IOReturn status = loop ? loop->runAction(directEnrollmentGated, this, &input, &reply,
            trustedSettingsSource ? reinterpret_cast<void *>(1) : nullptr) : kIOReturnNotReady;
        if (acm) acm->release();
        if (!status) {
            memcpy(args->structureOutput, &reply, sizeof(reply));
            args->structureOutputSize = sizeof(reply);
        }
        return status;
    }

    static IOReturn open(IOService *provider, task_t task, void *securityID, IOUserClient **handler) {
        if (!__atomic_load_n(&directEnrollmentReady, __ATOMIC_ACQUIRE)) return kIOReturnNotReady;
        ElanPermitIdentity::Snapshot caller{};
        if (!ElanPermitIdentity::capture(directBinding.current, directServiceIdentity, task, caller))
            return kIOReturnNotPrivileged;
        auto *client = new ELANEnrollmentPolicyClient;
        if (!client) return kIOReturnNoMemory;
        client->opening = caller;
        if (!client->initWithTask(task, securityID, ElanEnrollmentConnectionType) || !client->attach(provider)) {
            client->release();
            return kIOReturnError;
        }
        if (!client->start(provider)) {
            client->detach(provider);
            client->release();
            return kIOReturnError;
        }
        *handler = client;
        return kIOReturnSuccess;
    }
#ifdef ELAN_AUTOMATIC_SETTINGS
private:
    bool closed = false;
    void withdraw() {
        IOLockLock(providerLock);
        closed = true;
        const bool owned = listenerOwner == this;
        if (owned) {
            __atomic_store_n(&listenerGeneration,uint64_t{0},__ATOMIC_RELEASE);
            listenerProcessUnique = 0;
        }
        IOLockUnlock(providerLock);
        if (owned) {
            int restored = directSetListenerAvailability(false);
            IOLockLock(providerLock);
            if (!restored && listenerOwner == this) listenerOwner = nullptr;
            IOLockUnlock(providerLock);
        }
    }
public:
    void stop(IOService *service) override { withdraw(); IOUserClient::stop(service); }
    IOReturn clientDied() override { return clientClose(); }
#endif
    IOReturn clientClose() override {
#ifdef ELAN_AUTOMATIC_SETTINGS
        withdraw();
#endif
        terminate();
        return kIOReturnSuccess;
    }
};
OSDefineMetaClassAndStructors(ELANEnrollmentPolicyClient, IOUserClient)
