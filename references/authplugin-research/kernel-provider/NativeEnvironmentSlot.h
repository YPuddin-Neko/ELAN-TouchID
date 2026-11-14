#pragma once
#include <stddef.h>
#include <stdint.h>

struct NativeEnvironmentSlot {
    uint32_t identifier, type, flags, padding;
    uint64_t getPermissions, setPermissions;
    const void *getPermissionCallback, *setPermissionCallback, *lockerKey, *dataProvider;
    uint64_t timestamp;
    const void *validation, *setCallback, *readCallback;
    uint64_t reserved60, reserved68;
    const void *data;
    size_t length;
};
static_assert(sizeof(NativeEnvironmentSlot) == 128, "ACM environment slot ABI");
static_assert(offsetof(NativeEnvironmentSlot, timestamp) == 0x40, "ACM timestamp offset");
static_assert(offsetof(NativeEnvironmentSlot, validation) == 0x48, "ACM validator offset");
static_assert(offsetof(NativeEnvironmentSlot, data) == 0x70, "ACM data offset");

static inline uint32_t nativeEnvironmentMismatches(const NativeEnvironmentSlot &slot,
                                                   const void *validation, uint64_t provider) {
    uint32_t failures = 0;
    if (slot.identifier != 6 || slot.type || slot.padding) failures |= 1U << 0;
    if (slot.flags) failures |= 1U << 1;
    if (slot.getPermissionCallback || slot.setPermissionCallback) failures |= 1U << 2;
    if (slot.lockerKey) failures |= 1U << 3;
    if (slot.dataProvider) failures |= 1U << 4;
    if (slot.setCallback || slot.readCallback) failures |= 1U << 5;
    if (slot.reserved60 || slot.reserved68) failures |= 1U << 6;
    if (slot.validation != validation) failures |= 1U << 7;
    if (!(slot.setPermissions & provider)) failures |= 1U << 8;
    if (slot.data ? slot.length != 1 : slot.length != 0) failures |= 1U << 9;
    return failures;
}
