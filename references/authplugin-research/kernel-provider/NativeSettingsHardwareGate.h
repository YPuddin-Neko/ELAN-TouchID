#pragma once
#include "NativeSettingsRoute.h"

namespace NativeSettingsHardwareGate {
// Both class methods have type c16@0:8. PSBiometricIdentity +isSupported looks up
// its own class explicitly and queries connectedAccessoriesWithError: on its BKDevice.
enum class Stage:uint8_t {None,Arguments,ReadMetadata,Relocation,Metadata,PrivateSlot,Write,Route,Restore,Complete,Selector};
constexpr uint64_t destination = 0x78be8;
constexpr uint64_t source = 0x758a0;
constexpr uint64_t chained = 0x0010000000000000ULL;

template<class Memory>
NativeSettingsRoute::Result apply(Memory &memory, uint64_t image, uint64_t cache, bool relocatedOnly=false, Stage *diagnostic=nullptr) {
    auto at=[&](Stage stage){if(diagnostic)*diagnostic=stage;};
    at(Stage::Arguments);
    using Result = NativeSettingsRoute::Result;
    constexpr uint64_t limit = 0x00007fffffffffffULL;
    if (image < 4096 || (image & 4095) || image > limit - destination - 8 || !memory.permitted())
        return Result::Skipped;
    auto reader = memory.reader();
    uint64_t gate[3]{}, accessory[3]{};
    at(Stage::ReadMetadata);
    if (!reader.read(image + destination - 16,gate,sizeof(gate)) ||
        !reader.read(image + source - 16,accessory,sizeof(accessory))) return Result::Skipped;
    const uint64_t prefix = gate[2] == chained + 0xe04c ? chained : image;
    at(Stage::Relocation);
    if (relocatedOnly && prefix == chained) return Result::Skipped;
    at(Stage::Metadata);
    if (gate[1] != prefix + 0x62eb7 || gate[2] != prefix + 0xe04c ||
        accessory[1] != gate[1] || accessory[2] != prefix + 0x7232) return Result::Skipped;
    if (relocatedOnly) {
        at(Stage::Selector);
        auto nameMatches=[&](uint64_t address,const char *name,size_t size){
            constexpr uint64_t cacheSize=0x700000000ULL;
            const bool inImage=address>=image && address-image<0x6e000 && size<=0x6e000-(address-image);
            const bool inCache=cache>=4096 && cache<=limit-cacheSize+1 && address>=cache &&
                               address-cache<cacheSize && size<=cacheSize-(address-cache);
            return (inImage||inCache) && memory.readOnlySelector(address,size) &&
                   reader.equal(address,reinterpret_cast<const uint8_t *>(name),size);
        };
        if (!nameMatches(gate[0],"isTouchIDSupportedOnHardware",sizeof("isTouchIDSupportedOnHardware")) ||
            !nameMatches(accessory[0],"isSupported",sizeof("isSupported"))) return Result::Skipped;
    } else if (gate[0] != prefix + 0x6154e || accessory[0] != prefix + 0x6152f) return Result::Skipped;
    at(Stage::PrivateSlot);
    if (!memory.privateMethodSlot(image + destination)) return Result::Skipped;

    const uint64_t slot = image + destination;
    uint64_t actual = 0;
    // The cold main thread still owns both the method metadata and its first BK lookup.
    at(Stage::Write);
    if (memory.permitted() && memory.storePointer(slot,accessory[2]) &&
        reader.read(slot,&actual,sizeof(actual)) && actual == accessory[2]) {
        at(Stage::Route);
        auto routed = NativeSettingsRoute::apply(memory,cache);
        if (routed == Result::Routed) {at(Stage::Complete);return routed;}
        at(Stage::Restore);
        if (!memory.storePointer(slot,gate[2]) || !reader.read(slot,&actual,sizeof(actual)) || actual != gate[2])
            return Result::Incomplete;
        return routed;
    }
    at(Stage::Restore);
    if (!reader.read(slot,&actual,sizeof(actual))) return Result::Incomplete;
    if (actual == gate[2]) return Result::Skipped;
    if (actual == accessory[2] && memory.storePointer(slot,gate[2]) &&
        reader.read(slot,&actual,sizeof(actual)) && actual == gate[2]) return Result::Restored;
    return Result::Incomplete;
}
}
