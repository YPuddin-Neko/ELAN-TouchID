#include "native-provider-client.h"
#include "native-provider-wire.h"
#include "native-enrollment-report-validation.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

static bool bytes(int fd, void *buffer, size_t length, bool send) {
    auto *cursor = static_cast<uint8_t *>(buffer);
    while (length) {
        ssize_t count = send ? write(fd, cursor, length) : read(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count; length -= static_cast<size_t>(count);
    }
    return true;
}
static int exchange(int fd, uint32_t selector, const void *input, NativeProviderWireReply &reply) {
    if (!nativeProviderIsSelector(selector) || (nativeProviderInputSize(selector) && !input)) return -33002;
    NativeProviderWireRequest request {};
    request.magic = NativeProviderWireMagic; request.selector = selector;
    request.length = static_cast<uint32_t>(nativeProviderInputSize(selector));
    if (request.length) memcpy(&request.data, input, request.length);
    bool sent = bytes(fd, &request, sizeof(request), true);
    memset(&request.data, 0, sizeof(request.data));
    if (!sent || !bytes(fd, &reply, sizeof(reply), false)) return -33001;
    if (reply.magic != NativeProviderWireMagic || reply.reserved || reply.length != nativeProviderOutputSize(selector)) return -33002;
    return reply.callStatus;
}
int elanProviderConnect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un address {};
    address.sun_family = AF_UNIX; address.sun_len = sizeof(address);
    strlcpy(address.sun_path, NativeProviderSocket, sizeof(address.sun_path));
    if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) { close(fd); return -1; }
    uid_t user; gid_t group;
    if (getpeereid(fd, &user, &group) || user != 0) { close(fd); return -1; }
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
    timeval timeout {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}
int elanProviderBegin(int fd, const uint8_t identity[16]) {
    NativeProviderRequest request {};
    request.abi = 1; request.user = 501; memcpy(request.identity, identity, 16);
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderBegin, &request, reply);
    if (status) return status;
    const auto &value = reply.data.provider;
    return value.abi == 1 && !value.operationStatus && value.active && value.availability == 1 &&
           !value.quarantinedContext ? 0 : value.operationStatus ? value.operationStatus : -33003;
}
static int catalogExchange(int fd, uint32_t selector, uint64_t sequence, const uint8_t *identities, uint32_t count) {
    if (count > NativeProviderMaxIdentities || (count && !identities)) return NativeProviderInvalid;
    NativeProviderCatalogRequest request {};
    request.abi = 1; request.user = 501; request.sequence = sequence; request.count = count;
    if (count) memcpy(request.identities, identities, count * 16);
    if (!nativeProviderValidCatalog(request) || (selector == ElanProviderCatalogBegin ? sequence != 0 : sequence == 0))
        return NativeProviderInvalid;
    NativeProviderWireReply reply {};
    int status = exchange(fd, selector, &request, reply);
    if (status) return status;
    const auto &catalog = reply.data.catalog;
    const auto &value = catalog.provider;
    if (value.abi != 1 || value.operationStatus || value.restoreStatus || !value.active || value.availability != 1 ||
        !value.restorePending || value.sequence != sequence || value.quarantinedContext || value.reserved ||
        value.credentialAdded || value.matchedPolicy || value.wrongUserPolicy || value.propertiesVerified ||
        catalog.count != count || catalog.reserved || memcmp(catalog.identities, request.identities, sizeof(request.identities)))
        return value.operationStatus ? value.operationStatus : -33008;
    return 0;
}
int elanProviderBeginCatalog(int fd, const uint8_t *identities, uint32_t count) {
    return catalogExchange(fd, ElanProviderCatalogBegin, 0, identities, count);
}
int elanProviderReplaceCatalog(int fd, uint64_t sequence, const uint8_t *identities, uint32_t count) {
    return catalogExchange(fd, ElanProviderCatalogReplace, sequence, identities, count);
}
int elanProviderAuthorizeEnrollment(int fd, uint64_t sequence, const uint8_t context[16]) {
    if (!sequence || !context || !nativeNonzeroBytes(context, 16)) return NativeProviderInvalid;
    NativeEnrollmentRequest request {};
    request.abi = 3; request.user = 501; request.sequence = sequence;
    memcpy(request.context, context, 16);
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderAuthorizeEnrollment, &request, reply);
    if (status) return status;
    const auto &value = reply.data.enrollment;
    if (!nativeEnrollmentReportValid(value, sequence)) return -33009;
    return value.operationStatus;

}
int elanProviderMatch(int fd, uint64_t sequence, const uint8_t identity[16], const uint8_t context[16], bool matched) {
    NativeProviderRequest request {};
    request.abi = 1; request.user = 501; request.sequence = sequence; request.matched = matched;
    memcpy(request.identity, identity, 16); memcpy(request.context, context, 16);
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderMatch, &request, reply);
    if (status) return status;
    const auto &value = reply.data.provider;
    if (value.abi != 1 || value.operationStatus || value.restoreStatus || !value.active || value.availability != 1 ||
        value.sequence != sequence || value.quarantinedContext) return value.operationStatus ? value.operationStatus : -33004;
    bool accepted = matched ? value.credentialAdded && value.matchedPolicy && !value.wrongUserPolicy && value.propertiesVerified == 7 :
                              !value.credentialAdded && !value.matchedPolicy && !value.wrongUserPolicy;
    return accepted ? 0 : -33005;
}
int elanProviderPlatform(int fd, int32_t pid, uint64_t function,
                         uint64_t instanceGetter, uint64_t faultGetter,
                         uint64_t permanentGetter, uint64_t helperClass) {
    NativePlatformProcessRequest request {1, 501, pid, 0, function, instanceGetter, faultGetter, permanentGetter, helperClass};
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderPlatformEnable, &request, reply);
    if (status) return status;
    const auto &value = reply.data.platform;
    return value.abi == 1 && !value.status && value.kernelReady && value.attached && value.restorePending && value.pid == pid &&
           value.restartRequired && !value.reserved ?
           0 : value.status ? value.status : -33006;
}
int elanProviderEnd(int fd) {
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderEnd, nullptr, reply);
    if (status) return status;
    const auto &value = reply.data.provider;
    return value.abi == 1 && !value.operationStatus && !value.restoreStatus && !value.active &&
           !value.restorePending && !value.quarantinedContext ? 0 : value.restoreStatus ? value.restoreStatus : -33007;
}
int elanProviderSettings(int fd, int32_t pid, uint64_t function) {
    if (pid <= 1 || function < 0x1000) return NativeProviderInvalid;
    NativeSettingsProcessRequest request {1, 501, pid, 0, function, 0};
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderSettingsEnable, &request, reply);
    if (status) return status;
    const auto &value = reply.data.platform;
    return value.abi == 1 && !value.status && value.kernelReady && value.attached && value.restorePending &&
        value.pid == pid && value.restartRequired && !value.reserved ? 0 : value.status ? value.status : -33010;
}
int elanProviderSettingsRestore(int fd) {
    NativeProviderWireReply reply {};
    int status = exchange(fd, ElanProviderSettingsRestore, nullptr, reply);
    if (status) return status;
    const auto &value = reply.data.platform;
    return value.abi == 1 && !value.status && !value.attached && !value.restorePending && !value.restartRequired &&
        !value.pid && !value.reserved ? 0 : value.status ? value.status : -33011;
}

static int startupTrialExchange(int fd, uint32_t selector, uint64_t nonce) {
    if (!nonce) return NativeProviderInvalid;
    NativeStartupTrialRequest request {1, 501, nonce};
    NativeProviderWireReply reply {};
    int status = exchange(fd, selector, &request, reply);
    if (status) return status;
    const auto &value = reply.data.startupTrial;
    if (value.abi != 1 || value.nonce != nonce || value.armed > 1 || value.inFlight > 1 ||
        value.cancelled > 1 || value.recoveryRequired > 1) return -33002;
    if (value.status) return value.status;
    if (selector == ElanProviderStartupTrialArm && (!value.armed || value.inFlight || value.cancelled || value.recoveryRequired)) return -33003;
    if (selector == ElanProviderStartupTrialCancel && (!value.cancelled || value.armed)) return -33003;
    return 0;
}
int elanProviderStartupTrialArm(int fd, uint64_t nonce) { return startupTrialExchange(fd, ElanProviderStartupTrialArm, nonce); }
int elanProviderStartupTrialCancel(int fd, uint64_t nonce) { return startupTrialExchange(fd, ElanProviderStartupTrialCancel, nonce); }
