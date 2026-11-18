#pragma once
#include "../kernel-provider/NativeDirectEnrollment.h"
#include <IOKit/IOKitLib.h>
#include <string.h>
#include <unistd.h>
#include <os/log.h>

#ifndef ELAN_SETTINGS_DIAGNOSTIC
#define ELAN_SETTINGS_DIAGNOSTIC(stage, status) do { \
    os_log_error(OS_LOG_DEFAULT, "ELAN_SETTINGS enrollment_stage=%{public}s status=%{public}d", stage, (int)(status)); \
} while (0)
#endif

static inline int elanOpenDirectEnrollment(io_connect_t *channel) {
    if (getuid() == 0 || geteuid() != getuid()) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-uid", kIOReturnNotPrivileged);
        return kIOReturnNotPrivileged;
    }
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("ELANNativeProbe"));
    if (!service) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-service", kIOReturnNotReady);
        return kIOReturnNotReady;
    }
    IOReturn result = IOServiceOpen(service, mach_task_self(), ElanEnrollmentConnectionType, channel);
    IOObjectRelease(service);
    if (result) ELAN_SETTINGS_DIAGNOSTIC("direct-open", result);
    return result;
}

static inline int elanCheckDirectEnrollment(const uint8_t handle[16]) {
    io_connect_t channel = IO_OBJECT_NULL;
    if (!handle) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-input", kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    IOReturn result = elanOpenDirectEnrollment(&channel);
    if (result) return result;
    ElanDirectEnrollmentContext request;
    memcpy(request.handle, handle, sizeof(request.handle));
    ElanDirectEnrollmentReply reply = {0, 0};
    size_t size = sizeof(reply);
    result = IOConnectCallStructMethod(channel, ElanCheckEnrollment, &request, sizeof(request), &reply, &size);
    IOServiceClose(channel);
    if (result) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-call", result);
        return result;
    }
    if (size != sizeof(reply)) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-reply-size", kIOReturnNotPrivileged);
        return kIOReturnNotPrivileged;
    }
    if (reply.abi != 1) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-reply-abi", kIOReturnNotPrivileged);
        return kIOReturnNotPrivileged;
    }
    if (reply.authorized != 1) {
        ELAN_SETTINGS_DIAGNOSTIC("direct-denied", kIOReturnNotPrivileged);
        return kIOReturnNotPrivileged;
    }
    ELAN_SETTINGS_DIAGNOSTIC("direct-authorized", 0);
    return 0;
}

static inline int elanSyncDirectCatalog(const uint8_t *identities, uint32_t count) {
    io_connect_t channel = IO_OBJECT_NULL;
    if (count > 3 || (count && !identities)) {
        ELAN_SETTINGS_DIAGNOSTIC("catalog-sync-input", kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    IOReturn result = elanOpenDirectEnrollment(&channel);
    if (result) return result;
    ElanDirectCatalogSync request;
    memset(&request, 0, sizeof(request));
    request.abi = 1;
    request.count = count;
    if (count) memcpy(request.identities, identities, (size_t)count * 16);
    ElanDirectOperationReply reply = {0, -1};
    size_t size = sizeof(reply);
    result = IOConnectCallStructMethod(channel, ElanSyncProviderCatalog, &request, sizeof(request), &reply, &size);
    IOServiceClose(channel);
    if (result) {
        ELAN_SETTINGS_DIAGNOSTIC("catalog-sync-call", result);
        return result;
    }
    if (size != sizeof(reply) || reply.abi != 1 || reply.status != 0) {
        ELAN_SETTINGS_DIAGNOSTIC("catalog-sync-status", reply.status);
        return reply.status ? reply.status : kIOReturnNotPrivileged;
    }
    ELAN_SETTINGS_DIAGNOSTIC("catalog-synced", (int)count);
    return 0;
}

static inline int elanSubmitDirectMatch(uint64_t sequence, const uint8_t identity[16],
                                        const uint8_t context[16], uint32_t matched) {
    io_connect_t channel = IO_OBJECT_NULL;
    if (!sequence || !identity || !context || matched > 1) {
        ELAN_SETTINGS_DIAGNOSTIC("match-submit-input", kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    IOReturn result = elanOpenDirectEnrollment(&channel);
    if (result) return result;
    ElanDirectMatchSubmission request;
    memset(&request, 0, sizeof(request));
    request.abi = 1;
    request.matched = matched;
    request.sequence = sequence;
    memcpy(request.identity, identity, 16);
    memcpy(request.context, context, 16);
    ElanDirectOperationReply reply = {0, -1};
    size_t size = sizeof(reply);
    result = IOConnectCallStructMethod(channel, ElanSubmitDirectMatch, &request, sizeof(request), &reply, &size);
    IOServiceClose(channel);
    if (result) {
        ELAN_SETTINGS_DIAGNOSTIC("match-submit-call", result);
        return result;
    }
    if (size != sizeof(reply) || reply.abi != 1 || reply.status != 0) {
        ELAN_SETTINGS_DIAGNOSTIC("match-submit-status", reply.status);
        return reply.status ? reply.status : kIOReturnNotPrivileged;
    }
    ELAN_SETTINGS_DIAGNOSTIC("match-submitted", (int)matched);
    return 0;
}

static inline int elanCopyDirectPassphrase(uint8_t *outBytes, uint32_t *outLen) {
    if (!outBytes || !outLen) return kIOReturnBadArgument;
    *outLen = 0;
    io_connect_t channel = IO_OBJECT_NULL;
    IOReturn result = elanOpenDirectEnrollment(&channel);
    if (result) return result;
    ElanDirectPassphraseReply reply;
    memset(&reply, 0, sizeof(reply));
    size_t size = sizeof(reply);
    result = IOConnectCallStructMethod(channel, ElanCopyEnrollmentPassphrase, NULL, 0, &reply, &size);
    IOServiceClose(channel);
    if (result || size != sizeof(reply) || reply.abi != 1 || !reply.length || reply.length > sizeof(reply.bytes)) {
        memset(&reply, 0, sizeof(reply));
        return result ? result : kIOReturnNotFound;
    }
    memcpy(outBytes, reply.bytes, reply.length);
    *outLen = reply.length;
    memset(&reply, 0, sizeof(reply));
    return 0;
}

static inline int elanDispatchDirectUnlock(const uint8_t *bytes, uint32_t length) {
    if (!bytes || !length || length > 128) return kIOReturnBadArgument;
    io_connect_t channel = IO_OBJECT_NULL;
    IOReturn result = elanOpenDirectEnrollment(&channel);
    if (result) return result;
    ElanDirectUnlockRequest request;
    memset(&request, 0, sizeof(request));
    request.abi = 1;
    request.length = length;
    memcpy(request.bytes, bytes, length);
    ElanDirectOperationReply reply = {0, -1};
    size_t size = sizeof(reply);
    result = IOConnectCallStructMethod(channel, ElanDispatchUnlockKeystrokes, &request, sizeof(request), &reply, &size);
    memset(&request, 0, sizeof(request));
    IOServiceClose(channel);
    if (result) {
        ELAN_SETTINGS_DIAGNOSTIC("unlock-dispatch-call", result);
        return result;
    }
    if (size != sizeof(reply) || reply.abi != 1 || reply.status != 0) {
        ELAN_SETTINGS_DIAGNOSTIC("unlock-dispatch-status", reply.status);
        return reply.status ? reply.status : kIOReturnNotPrivileged;
    }
    ELAN_SETTINGS_DIAGNOSTIC("unlock-dispatched", (int)length);
    return 0;
}
