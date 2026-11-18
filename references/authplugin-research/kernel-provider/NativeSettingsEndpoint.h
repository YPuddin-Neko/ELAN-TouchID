#pragma once
#include "../agent-integration-candidate/early-shared-region/CurrentCopyinSample.h"

namespace NativeSettingsEndpoint {
constexpr char appleName[] = "com.apple.biometrickitd";
constexpr char serviceName[] = "io.hackmac.elan.touchid";
static_assert(sizeof(appleName) == sizeof(serviceName), "CFConstantString length");

struct Location {
    uint64_t slot;
    uint64_t original;
    uint64_t platformFunction;
};

// All addresses are relative to the 24H32 Intel shared cache returned to dyld.
// The early caller can use copyin without loading Objective-C or BiometricKit.
inline bool locate(CurrentCopyinSample::Reader reader, uint64_t base, Location &out) {
    out = {};
    constexpr uint64_t cacheStart = 0x7ff800000000ULL;
    if (base < cacheStart || base - cacheStart > 0x1ae68000 || (base & 4095)) return false;
    const uint8_t cacheUUID[] = {0x42,0xec,0x28,0x90,0xbc,0x40,0x31,0x7e,0xbb,0x27,0x45,0x14,0x2b,0xff,0x7f,0x26};
    if (!reader.equal(base + 88, cacheUUID, sizeof(cacheUUID))) return false;
    const uint64_t image = base + 0x10a5b0000ULL;
    if (!reader.equal(image, TargetImagePins::header, sizeof(TargetImagePins::header))) return false;
    const uint64_t method = image + 0x69cf;
    const uint64_t object = image + 0x366f14e0;
    const uint64_t text = image + 0x39858;
    uint8_t code[0x83];
    const uint8_t typeOne[] = {0x48,0x83,0xf8,0x01,0x74,0x13};
    const uint8_t load[] = {0x4c,0x8d,0x35};
    const uint8_t arguments[] = {0x4c,0x89,0xf2,0x31,0xc9};
    if (!reader.read(method,code,sizeof(code)) || memcmp(code+0x48,typeOne,sizeof(typeOne)) ||
        memcmp(code+0x61,load,sizeof(load)) || memcmp(code+0x7e,arguments,sizeof(arguments))) return false;
    int32_t displacement;
    memcpy(&displacement,code+0x64,sizeof(displacement));
    if (static_cast<int64_t>(method + 0x68) + displacement != static_cast<int64_t>(object)) return false;
    uint64_t fields[4];
    if (!reader.read(object,fields,sizeof(fields)) || fields[1] != 0x7c8 || fields[2] != text ||
        fields[3] != sizeof(appleName)-1 ||
        !reader.equal(text,reinterpret_cast<const uint8_t *>(appleName),sizeof(appleName))) return false;
    out = {object + 2*sizeof(uint64_t), text, image + 0x238d1};
    return true;
}
}
