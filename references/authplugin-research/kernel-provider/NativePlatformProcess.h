#pragma once
#include "NativePlatformCache.h"
#include "NativeLACRetry.h"
#include "NativeSettingsCache.h"
#include "ElanNativeProbe.h"
#include <Headers/kern_patcher.hpp>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/kauth.h>
#include <mach/vm_prot.h>

class NativePlatformProcess {
    using Map = void *;
    static void *(*processTask)(proc_t);
    static Map (*mapReference)(void *);
    static void (*mapRelease)(Map);
    static int (*mapRead)(Map, uint64_t, void *, uint64_t);
    static int (*mapWrite)(Map, const void *, uint64_t, uint64_t);
    static int (*mapProtection)(Map, uint64_t, uint64_t, vm_prot_t);
    static int (*taskSuspended)(void *);
    static bool ready;
    Map map = nullptr;
    int32_t pid = 0;
    NativePlatformCacheState cache {};
    NativeLACRetryState retry {};
    NativeSettingsCacheState settings {};
    static int read(void *map, uint64_t address, void *bytes, size_t length) {
        return mapRead(map, address, bytes, length);
    }
    static int write(void *map, uint64_t address, const void *bytes, size_t length) {
        return mapWrite(map, bytes, address, length);
    }
    static bool writable(void *map, uint64_t address, size_t length) {
        return address <= UINT64_MAX - length && mapProtection(map, address, address + length, VM_PROT_WRITE);
    }
    NativePlatformCacheAPI api() { return {map, read, write, writable}; }
    bool attach(int32_t target, uint32_t user, const char *expectedName) {
        proc_t process = proc_find(target);
        if (!process) return false;
        char name[MAXCOMLEN + 1] = {}, expected[MAXCOMLEN + 1] = {};
        proc_name(target, name, sizeof(name));
        strlcpy(expected, expectedName, sizeof(expected));
        kauth_cred_t credentials = kauth_cred_proc_ref(process);
        bool allowed = credentials && kauth_cred_getuid(credentials) == user && !strcmp(name, expected);
        if (credentials) kauth_cred_unref(&credentials);
        void *task = allowed ? processTask(process) : nullptr;
        // This reference pins the selected map even if the process exits or execs.
        if (task && taskSuspended(task)) map = mapReference(task);
        proc_rele(process);
        if (map) pid = target;
        return map != nullptr;
    }
public:
    static bool initialize(KernelPatcher &patcher) {
        const char *names[] = {"_proc_task", "_get_task_map_reference", "_vm_map_deallocate",
                              "_vm_map_read_user", "_vm_map_write_user", "_vm_map_check_protection", "_get_task_suspended"};
        mach_vm_address_t addresses[7] = {};
        for (unsigned i = 0; i < 7; i++) {
            addresses[i] = patcher.solveSymbol(KernelPatcher::KernelID, names[i]);
            patcher.clearError();
            if (!addresses[i]) return false;
        }
        processTask = reinterpret_cast<decltype(processTask)>(addresses[0]);
        mapReference = reinterpret_cast<decltype(mapReference)>(addresses[1]);
        mapRelease = reinterpret_cast<decltype(mapRelease)>(addresses[2]);
        mapRead = reinterpret_cast<decltype(mapRead)>(addresses[3]);
        mapWrite = reinterpret_cast<decltype(mapWrite)>(addresses[4]);
        mapProtection = reinterpret_cast<decltype(mapProtection)>(addresses[5]);
        taskSuspended = reinterpret_cast<decltype(taskSuspended)>(addresses[6]);
        ready = true;
        return true;
    }
    bool pending() const { return cache.restorePending || retry.restartRequired || settings.restartRequired; }
    bool attached() const { return map != nullptr; }
    int enable(const NativePlatformProcessRequest &request) {
        if (!ready || map || request.abi != 1 || request.user != 501 || request.pid <= 1 || request.reserved)
            return NativePlatformInvalid;
        if (!attach(request.pid, request.user, "coreauthd")) return NativePlatformInvalid;
        NativeLACRetryRequest reset {request.instanceGetter, request.faultGetter, request.permanentGetter, request.helperClass};
        int status = nativeLACRetryPrepare(api(), reset, retry);
        if (!status) status = nativePlatformEnable(api(), request.function, cache);
        if (!status) status = nativeLACRetryTransfer(api(), retry);
        if (status) nativePlatformRestore(api(), cache);
        if (status && !pending()) { mapRelease(map); map = nullptr; pid = 0; retry = {}; }
        return status;
    }
    int enableSettings(const NativeSettingsProcessRequest &request) {
        if (!ready || map || request.abi != 1 || request.user != 501 || request.pid <= 1 || request.reserved)
            return NativePlatformInvalid;
        if (!attach(request.pid, request.user, "Touch ID & Password")) return NativePlatformInvalid;
        int status = nativeSettingsCachePrepare(api(), request.image, settings);
        if (!status) status = nativePlatformEnable(api(), request.function, cache, true);
        if (!status) status = nativeSettingsCacheRetry(api(), settings);
        if (status) nativePlatformRestore(api(), cache);
        if (status && !pending()) { mapRelease(map); map = nullptr; pid = 0; settings = {}; }
        return status;
    }
    int restore() {
        if (!map) return 0;
        proc_t process = proc_find(pid);
        void *task = process ? processTask(process) : nullptr;
        Map current = task ? mapReference(task) : nullptr;
        if (process) proc_rele(process);
        bool same = current == map;
        if (current) mapRelease(current);
        if (!same) {
            // The patched address space is no longer used by this process.
            cache = {};
            retry = {};
            settings = {};
            mapRelease(map); map = nullptr; pid = 0;
            return 0;
        }
        int status = nativePlatformRestore(api(), cache);
        if (retry.restartRequired || settings.restartRequired) return status ? status : NativePlatformRestartRequired;
        if (!cache.restorePending) { mapRelease(map); map = nullptr; pid = 0; retry = {}; settings = {}; }
        return status;
    }
    void report(int status, NativePlatformProcessReport &out) const {
        out = {1, status, ready, pending(), pid, map != nullptr, retry.restartRequired || settings.restartRequired, 0};
    }
};

void *(*NativePlatformProcess::processTask)(proc_t);
NativePlatformProcess::Map (*NativePlatformProcess::mapReference)(void *);
void (*NativePlatformProcess::mapRelease)(Map);
int (*NativePlatformProcess::mapRead)(Map, uint64_t, void *, uint64_t);
int (*NativePlatformProcess::mapWrite)(Map, const void *, uint64_t, uint64_t);
int (*NativePlatformProcess::mapProtection)(Map, uint64_t, uint64_t, vm_prot_t);
int (*NativePlatformProcess::taskSuspended)(void *);
bool NativePlatformProcess::ready;
