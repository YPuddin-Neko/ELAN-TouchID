#include "NativeMapProtectionABI.h"
#include <assert.h>
#include <stdio.h>
#include <initializer_list>

static constexpr uintptr_t callerOffset = 0x5dcd68, protectionDistance = 0x507e70;
// Independent bytes from the pinned target's _useracc disassembly.
static const uint8_t pinned[] = {
    0x55,0x48,0x89,0xe5,0x48,0x89,0xf8,0x65,0x48,0x8b,0x0c,0x25,0x10,0x00,0x00,0x00,
    0x48,0x8b,0xb9,0x28,0x06,0x00,0x00,0x31,0xc9,0x83,0xfa,0x01,0x0f,0x95,0xc1,0xff,
    0xc1,0x48,0x8d,0x14,0x06,0x4c,0x8d,0x05,0x3c,0xcd,0x5d,0x00,0x48,0x89,0xc6,0x5d,
    0xe9,0x5b,0x81,0xaf,0xff
};
static_assert(sizeof(pinned) == 53, "pinned useracc extent");
struct Fixture {
    uintptr_t address = 0xffffff80008c7ac0ULL;
    uint8_t code[sizeof(pinned)];
    size_t available = sizeof(code), reported = sizeof(code);
    unsigned reads = 0;
    Fixture() { memcpy(code, pinned, sizeof(code)); }
    static size_t read(void *context, uintptr_t address, void *out, size_t length) {
        auto &f = *static_cast<Fixture *>(context);
        assert(address == f.address && length == sizeof(f.code)); ++f.reads;
        const size_t copied = f.available < length ? f.available : length;
        memcpy(out, f.code, copied);
        return f.reported;
    }
    uintptr_t resolve(uintptr_t protection) {
        return nativeMapProtectionCaller(address, protection, read, this);
    }
};
static void relativeArithmetic() {
    const uint8_t negative[] = {0,0,0,0x80}, positive[] = {0xff,0xff,0xff,0x7f}, zero[4] = {};
    uintptr_t result = 0;
    assert(nativeMapProtectionRelative(0x80000001ULL, negative, result) && result == 1);
    assert(!nativeMapProtectionRelative(0x80000000ULL, negative, result));
    assert(!nativeMapProtectionRelative(0x7fffffffULL, negative, result));
    assert(nativeMapProtectionRelative(UINTPTR_MAX - 0x7fffffffULL, positive, result) && result == UINTPTR_MAX);
    assert(!nativeMapProtectionRelative(UINTPTR_MAX - 0x7ffffffeULL, positive, result));
    assert(nativeMapProtectionRelative(1, zero, result) && result == 1);
    assert(!nativeMapProtectionRelative(0, zero, result));
}
int main() {
    unsigned scenarios = 0;
    const uintptr_t addresses[] = {0xffffff80008c7ac0ULL, 0xffffff80028c7ac0ULL,
        0x100000000ULL, protectionDistance + 1, UINTPTR_MAX - callerOffset};
    for (uintptr_t address : addresses) {
        Fixture f; f.address = address;
        assert(f.resolve(address - protectionDistance) == address + callerOffset);
        assert(f.reads == 1); ++scenarios;
    }
    {
        Fixture f; f.address=0xffffff80009afac0ULL;
        f.code[40]=0x3c; f.code[41]=0xdd; f.code[42]=0x86; f.code[43]=0xff;
        assert(f.resolve(0xffffff80004a7c50ULL)==0xffffff800021d828ULL); ++scenarios;
        uint8_t collection[sizeof(pinned)]; memcpy(collection,f.code,sizeof(collection));
        for(size_t byte=0;byte<sizeof(pinned);++byte) for(unsigned value=0;value<256;++value){
            if(value==collection[byte])continue;
            memcpy(f.code,collection,sizeof(collection)); f.code[byte]=value;
            assert(!f.resolve(0xffffff80004a7c50ULL)); ++scenarios;
        }
    }
    // Every altered byte value, including either displacement, must reject.
    for (size_t byte = 0; byte < sizeof(pinned); ++byte) for (unsigned value = 0; value < 256; ++value) {
        if (value == pinned[byte]) continue;
        Fixture f; f.code[byte] = static_cast<uint8_t>(value);
        assert(!f.resolve(f.address - protectionDistance) && f.reads == 1); ++scenarios;
    }
    for (size_t length = 0; length < sizeof(pinned); ++length) {
        Fixture f; f.available = f.reported = length;
        assert(!f.resolve(f.address - protectionDistance) && f.reads == 1); ++scenarios;
        // A reader incorrectly reporting a full short read still cannot pass the byte pin.
        f.reported = sizeof(pinned);
        assert(!f.resolve(f.address - protectionDistance) && f.reads == 2); ++scenarios;
    }
    {
        Fixture f; f.reported = sizeof(pinned) + 1;
        assert(!f.resolve(f.address - protectionDistance)); ++scenarios;
    }
    for (uintptr_t address : {uintptr_t(0), protectionDistance - 1, protectionDistance}) {
        Fixture f; f.address = address;
        assert(!f.resolve(1)); ++scenarios;
    }
    for (size_t offset = 0; offset < sizeof(pinned); ++offset) {
        Fixture f; f.address = UINTPTR_MAX - offset;
        assert(!f.resolve(f.address - protectionDistance) && !f.reads); ++scenarios;
    }
    {
        Fixture f; f.address = UINTPTR_MAX - sizeof(pinned);
        assert(!f.resolve(f.address - protectionDistance) && f.reads == 1); ++scenarios;
        f.address = UINTPTR_MAX - callerOffset + 1;
        assert(!f.resolve(f.address - protectionDistance)); ++scenarios;
    }
    {
        Fixture f;
        assert(!f.resolve(0) && !f.reads);
        assert(!nativeMapProtectionCaller(f.address, f.address - protectionDistance, nullptr, &f) && !f.reads);
        assert(!f.resolve(f.address - protectionDistance - 1));
        assert(!f.resolve(f.address - protectionDistance + 1)); scenarios += 4;
    }
    relativeArithmetic(); scenarios += 7;
    printf("map protection ABI: %u pin, reader and arithmetic scenarios passed\n", scenarios);
}
