#include "native-provider-client.h"
#include "native-provider-wire.h"
#include <assert.h>
#include <functional>
#include <stdio.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static void transfer(int fd, void *buffer, size_t length, bool send) {
    auto *bytes = static_cast<uint8_t *>(buffer);
    while (length) {
        size_t chunk = length > 7 ? 7 : length;
        ssize_t count = send ? write(fd, bytes, chunk) : read(fd, bytes, chunk);
        assert(count > 0);
        bytes += count; length -= static_cast<size_t>(count);
    }
}
static int roundtrip(uint32_t selector,
                     const std::function<int(int)> &client,
                     const std::function<void(const NativeProviderWireRequest &, NativeProviderWireReply &)> &replyBody) {
    int pair[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    std::thread server([&] {
        NativeProviderWireRequest request {};
        transfer(pair[1], &request, sizeof(request), false);
        assert(request.magic == NativeProviderWireMagic && request.selector == selector && !request.reserved);
        assert(request.length == nativeProviderInputSize(selector));
        NativeProviderWireReply reply {};
        reply.magic = NativeProviderWireMagic;
        reply.length = static_cast<uint32_t>(nativeProviderOutputSize(selector));
        replyBody(request, reply);
        transfer(pair[1], &reply, sizeof(reply), true);
        close(pair[1]);
    });
    int status = client(pair[0]);
    close(pair[0]); server.join();
    return status;
}
static void catalogReply(const NativeProviderWireRequest &request, NativeProviderWireReply &reply) {
    const auto &input = request.data.catalog;
    assert(input.abi == 1 && input.user == 501);
    auto &catalog = reply.data.catalog;
    catalog.provider.abi = 1;
    catalog.provider.active = catalog.provider.restorePending = catalog.provider.availability = 1;
    catalog.provider.sequence = input.sequence;
    catalog.count = input.count;
    memcpy(catalog.identities, input.identities, sizeof(catalog.identities));
}
static void enrollmentReply(const NativeProviderWireRequest &request, NativeProviderWireReply &reply) {
    const auto &input = request.data.enrollment;
    assert(input.abi == 1 && input.user == 501 && input.context[0] == 0x55);
    auto &value = reply.data.enrollment;
    value.abi = 1; value.active = 1; value.sequence = input.sequence;
    value.passwordCredentialTypes = 1; value.ownerPolicy = value.authorized = 1;
}
static void settingsReply(const NativeProviderWireRequest &request, NativeProviderWireReply &reply) {
    const auto &input = request.data.settings;
    assert(input.abi == 1 && input.user == 501 && input.pid == 1234 && input.function == 0x180001234);
    assert(!input.reserved && !input.image);
    reply.data.platform = {1, 0, 1, 1, input.pid, 1, 1, 0};
}
int main() {
    uint8_t identities[3][16] = {{0x11}, {0x22}, {0x33}};
    uint8_t context[16] = {0x55};
    auto begin = [&](int fd) { return elanProviderBeginCatalog(fd, identities[0], 3); };
    auto replace = [&](int fd) { return elanProviderReplaceCatalog(fd, 2, identities[1], 2); };
    assert(!roundtrip(ElanProviderCatalogBegin, begin, catalogReply));
    assert(!roundtrip(ElanProviderCatalogBegin, [](int fd) { return elanProviderBeginCatalog(fd, nullptr, 0); }, catalogReply));
    assert(!roundtrip(ElanProviderCatalogReplace, replace, catalogReply));
    assert(roundtrip(ElanProviderCatalogReplace, replace, [](const auto &request, auto &reply) {
        catalogReply(request, reply); reply.data.catalog.identities[0][0] ^= 1;
    }));
    assert(roundtrip(ElanProviderCatalogReplace, replace, [](const auto &request, auto &reply) {
        catalogReply(request, reply); reply.data.catalog.provider.sequence--;
    }));
    assert(roundtrip(ElanProviderCatalogBegin, begin, [](const auto &request, auto &reply) {
        catalogReply(request, reply); reply.magic = 0x454c414e;
    }));
    assert(roundtrip(ElanProviderCatalogBegin, begin, [](const auto &request, auto &reply) {
        catalogReply(request, reply); reply.length = sizeof(NativePlatformProcessReport);
    }));
    auto authorize = [&](int fd) { return elanProviderAuthorizeEnrollment(fd, 3, context); };
    assert(!roundtrip(ElanProviderAuthorizeEnrollment, authorize, enrollmentReply));
    assert(roundtrip(ElanProviderAuthorizeEnrollment, authorize, [](const auto &request, auto &reply) {
        enrollmentReply(request, reply); reply.data.enrollment.passwordCredentialTypes = 0;
    }));
    assert(roundtrip(ElanProviderAuthorizeEnrollment, authorize, [](const auto &request, auto &reply) {
        enrollmentReply(request, reply); reply.data.enrollment.wrongUserPolicy = 1;
    }));
    assert(roundtrip(ElanProviderAuthorizeEnrollment, authorize, [](const auto &request, auto &reply) {
        enrollmentReply(request, reply); reply.data.enrollment.operationStatus = -2;
    }) == -2);
    assert(roundtrip(ElanProviderAuthorizeEnrollment, authorize, [](const auto &request, auto &reply) {
        enrollmentReply(request, reply); reply.data.enrollment.sequence--;
    }));
    // Argument rejection occurs before touching the socket.
    assert(elanProviderBeginCatalog(-1, identities[0], 4) == NativeProviderInvalid);
    assert(elanProviderBeginCatalog(-1, nullptr, 1) == NativeProviderInvalid);
    assert(elanProviderReplaceCatalog(-1, 0, nullptr, 0) == NativeProviderInvalid);
    assert(elanProviderAuthorizeEnrollment(-1, 0, context) == NativeProviderInvalid);
    auto settings = [](int fd) { return elanProviderSettings(fd, 1234, 0x180001234); };
    assert(!roundtrip(ElanProviderSettingsEnable, settings, settingsReply));
    assert(roundtrip(ElanProviderSettingsEnable, settings, [](const auto &request, auto &reply) {
        settingsReply(request, reply); reply.data.platform.pid++;
    }));
    assert(roundtrip(ElanProviderSettingsEnable, settings, [](const auto &request, auto &reply) {
        settingsReply(request, reply); reply.data.platform.restartRequired = 0;
    }));
    assert(roundtrip(ElanProviderSettingsEnable, settings, [](const auto &request, auto &reply) {
        settingsReply(request, reply); reply.data.platform.attached = 0;
    }));
    assert(roundtrip(ElanProviderSettingsEnable, settings, [](const auto &request, auto &reply) {
        settingsReply(request, reply); reply.data.platform.status = -41;
    }) == -41);
    assert(roundtrip(ElanProviderSettingsEnable, settings, [](const auto &request, auto &reply) {
        settingsReply(request, reply); reply.callStatus = -42;
    }) == -42);
    assert(elanProviderSettings(-1, 1, 0x180001234) == NativeProviderInvalid);
    assert(elanProviderSettings(-1, 1234, 0) == NativeProviderInvalid);
    auto restore = [](int fd) { return elanProviderSettingsRestore(fd); };
    auto restored = [](const NativeProviderWireRequest &request, NativeProviderWireReply &reply) {
        assert(!request.length);
        reply.data.platform = {1, 0, 1, 0, 0, 0, 0, 0};
    };
    assert(!roundtrip(ElanProviderSettingsRestore, restore, restored));
    assert(roundtrip(ElanProviderSettingsRestore, restore, [&](const auto &request, auto &reply) {
        restored(request, reply); reply.data.platform.restartRequired = 1;
    }));
    assert(roundtrip(ElanProviderSettingsRestore, restore, [&](const auto &request, auto &reply) {
        restored(request, reply); reply.data.platform.restorePending = 1;
    }));
    assert(roundtrip(ElanProviderSettingsRestore, restore, [&](const auto &request, auto &reply) {
        restored(request, reply); reply.data.platform.pid = 1234;
    }));
    assert(!roundtrip(ElanProviderBegin, [&](int fd) { return elanProviderBegin(fd, identities[0]); },
        [&](const auto &request, auto &reply) {
            assert(!memcmp(request.data.provider.identity, identities[0], 16));
            reply.data.provider.abi = 1; reply.data.provider.active = reply.data.provider.availability = 1;
        }));
    assert(!roundtrip(ElanProviderMatch, [&](int fd) { return elanProviderMatch(fd, 4, identities[1], context, true); },
        [&](const auto &request, auto &reply) {
            assert(!memcmp(request.data.provider.identity, identities[1], 16) && !memcmp(request.data.provider.context, context, 16));
            auto &value = reply.data.provider;
            value.abi = 1; value.active = value.availability = value.credentialAdded = value.matchedPolicy = 1;
            value.sequence = 4; value.propertiesVerified = 7;
        }));
    puts("provider wire: fragmented catalog/auth/settings transport, identity readback, stale replies, incomplete settings restoration, mixed protocol rejection and legacy match passed");
}
