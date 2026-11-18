#pragma once
#include <stdint.h>
using mach_vm_address_t = uint64_t;
uintptr_t nativePlatformTestResolve(const char *);
struct KernelPatcher {
    enum { KernelID = 0 };
    mach_vm_address_t solveSymbol(int, const char *name) { return nativePlatformTestResolve(name); }
    void clearError() {}
};
