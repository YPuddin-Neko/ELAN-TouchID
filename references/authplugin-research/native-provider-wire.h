#pragma once
#include "kernel-provider/NativeProviderABI.h"

static constexpr uint32_t NativeProviderWireMagic = 0x454c4132;
static constexpr const char *NativeProviderSocket = "/private/var/run/elan-native-provider-501.sock";
static constexpr const char *NativeProviderWorker = "/Library/ELANFingerprintNativeTest/ELANNativeProvider.app";
struct NativeProviderWireRequest {
    uint32_t magic;
    uint32_t selector;
    uint32_t length;
    uint32_t reserved;
    NativeProviderInput data;
};
struct NativeProviderWireReply {
    uint32_t magic;
    int32_t callStatus;
    uint32_t length;
    uint32_t reserved;
    NativeProviderOutput data;
};
static_assert(sizeof(NativeProviderWireRequest) == 88, "provider request wire ABI");
static_assert(sizeof(NativeProviderWireReply) == 128, "provider reply wire ABI");
