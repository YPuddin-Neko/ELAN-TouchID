#pragma once
#include "NativePlatformCache.h"
#include "../agent-integration-candidate/startup-retirement/KernelRuntime.h"
#include "NativeLACRetry.h"
#include "NativeSettingsCache.h"
#include "NativeConnectionImage.h"
#include "NativeSettingsRecovery.h"
#include "NativeProviderABI.h"
#include "NativeMapProtectionABI.h"
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
    static int (*mapProtection)(Map, uint64_t, uint64_t, vm_prot_t, const void *);
    static const void *mapProtectionCaller;
    static int (*taskSuspended)(void *);
    static bool ready;
    Map map = nullptr;
    ExactTaskRetirement::RemoteTicket retainedTask;
    int32_t pid = 0;
    NativePlatformCacheState cache {};
    NativeLACRetryState retry {};
    NativeSettingsCacheState settings {};
    NativeSettingsRecoveryState recovery {};
    static int read(void *map, uint64_t address, void *bytes, size_t length) {
        return mapRead(map, address, bytes, length);
    }
    static int write(void *map, uint64_t address, const void *bytes, size_t length) {
        return mapWrite(map, bytes, address, length);
    }
    static bool writable(void *map, uint64_t address, size_t length) {
        return address <= UINT64_MAX - length &&
            mapProtection(map, address, address + length, VM_PROT_WRITE, mapProtectionCaller);
    }
    static bool executable(void *map, uint64_t address, size_t length) {
        return address <= UINT64_MAX - length &&
            mapProtection(map, address, address + length, VM_PROT_EXECUTE, mapProtectionCaller) &&
            !mapProtection(map, address, address + length, VM_PROT_WRITE, mapProtectionCaller);
    }
    static size_t readKernelCode(void *, uintptr_t address, void *out, size_t length) {
        memcpy(out, reinterpret_cast<const void *>(address), length);
        return length;
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
        if (task && taskSuspended(task) && RetirementRuntime::retainRemote(task, retainedTask)) {
            map = mapReference(task);
            if (!map) RetirementRuntime::releaseRemoteClean(retainedTask);
        }
        proc_rele(process);
        if (map) pid = target;
        return map != nullptr;
    }
public:
    // Startup only, before any process slot can attach.
    static bool initialize(KernelPatcher &patcher, NativeMapProtectionCodeReader codeReader = readKernelCode,
                           void *readerContext = nullptr) {
        ready = false;
        mapProtectionCaller = nullptr;
        const char *names[] = {"_proc_task", "_get_task_map_reference", "_vm_map_deallocate",
                              "_vm_map_read_user", "_vm_map_write_user", "_vm_map_check_protection", "_get_task_suspended", "_useracc"};
        mach_vm_address_t addresses[8] = {};
        for (unsigned i = 0; i < 8; i++) {
            addresses[i] = patcher.solveSymbol(KernelPatcher::KernelID, names[i]);
            patcher.clearError();
            if (!addresses[i] || addresses[i] > UINTPTR_MAX) return false;
        }
        const uintptr_t caller = nativeMapProtectionCaller(static_cast<uintptr_t>(addresses[7]),
            static_cast<uintptr_t>(addresses[5]), codeReader, readerContext);
        if (!caller) return false;
        processTask = reinterpret_cast<decltype(processTask)>(addresses[0]);
        mapReference = reinterpret_cast<decltype(mapReference)>(addresses[1]);
        mapRelease = reinterpret_cast<decltype(mapRelease)>(addresses[2]);
        mapRead = reinterpret_cast<decltype(mapRead)>(addresses[3]);
        mapWrite = reinterpret_cast<decltype(mapWrite)>(addresses[4]);
        mapProtection = reinterpret_cast<decltype(mapProtection)>(addresses[5]);
        taskSuspended = reinterpret_cast<decltype(taskSuspended)>(addresses[6]);
        mapProtectionCaller = reinterpret_cast<const void *>(caller);
        ready = true;
        return true;
    }
    bool pending() const { return cache.restorePending || retry.restartRequired || settings.restartRequired || nativeSettingsRecoveryPending(recovery); }
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
        if (status && !pending()) { mapRelease(map); map = nullptr; pid = 0; RetirementRuntime::releaseRemoteClean(retainedTask); retry = {}; }
        return status;
    }
    int inspectSettings(const NativeSettingsProcessRequest &request, NativeSettingsInspectionReport &out) {
        out = {2, NativePlatformInvalid, 0, 0, 0, {0, 0, 0}};
        if (!ready || map || request.abi != 1 || request.user != 501 || request.pid <= 1 || request.reserved)
            return out.status;
        if (!attach(request.pid, request.user, "Touch ID & Password")) return out.status;
        NativeConnectionImageReport observation {};
        uint64_t getter = 0;
        // Inspection cannot write target memory, even if the parser changes later.
        NativePlatformCacheAPI readOnly {map, read, nullptr, nullptr};
        out.status = nativeConnectionImageInspect(readOnly, request.function, executable, observation, getter);
        out.observation = static_cast<uint32_t>(observation.observation);
        out.imageMatched = observation.imageMatched;
        out.stage = static_cast<uint32_t>(observation.stage);
        mapRelease(map); map = nullptr; pid = 0; RetirementRuntime::releaseRemoteClean(retainedTask);
        return out.status;
    }
    int recoverSettingsConnection(const NativeSettingsProcessRequest &request, NativeSettingsRecoveryReport *snapshot = nullptr) {
        if (snapshot) { *snapshot = {}; snapshot->transactionStatus = NativePlatformInvalid; }
        if (!NativeSettingsRecoveryRuntimeReady) {
            if (snapshot) snapshot->transactionStatus = NativeSettingsRecoveryUnavailable;
            return NativeSettingsRecoveryUnavailable;
        }
        if (!ready || map || request.abi != 1 || request.user != 501 || request.pid <= 1 || request.reserved)
            return NativePlatformInvalid;
        if (!attach(request.pid, request.user, "Touch ID & Password")) return NativePlatformInvalid;
        // Re-inspect and modify through this one pinned, suspended map, never a prior PID-only observation.
        int status = nativeSettingsRecoveryEnable(api(), request.function, request.image, executable, recovery);
        if (snapshot) {
            snapshot->phase = static_cast<uint32_t>(recovery.phase);
            snapshot->transactionStatus = status;
            snapshot->rollbackStatus = recovery.rollbackStatus;
        }
        if (status && !pending()) { mapRelease(map); map = nullptr; pid = 0; RetirementRuntime::releaseRemoteClean(retainedTask); recovery = {}; }
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
        if (status && !pending()) { mapRelease(map); map = nullptr; pid = 0; RetirementRuntime::releaseRemoteClean(retainedTask); settings = {}; }
        return status;
    }
    int retireExact() {
        if (!map && !retainedTask.retained()) return 0;
        if (!retainedTask.retained()) return NativePlatformRestartRequired;
        auto result = RetirementRuntime::retireRemote(retainedTask);
        if (result.outcome != ExactTaskRetirement::Outcome::NoUserResumeVerified)
            return NativePlatformRestartRequired;
        cache = {}; retry = {}; settings = {}; recovery = {};
        if (map) mapRelease(map);
        map = nullptr; pid = 0;
        return 0;
    }
    int restore() {
        if (!map) return 0;
        proc_t process = proc_find(pid);
        void *task = process ? processTask(process) : nullptr;
        Map current = task ? mapReference(task) : nullptr;
        if (process) proc_rele(process);
        // Failure to inspect a live process is not proof that its old map has exited.
        if (process && !current) return NativePlatformChanged;
        bool same = current == map;
        if (current) mapRelease(current);
        // Teardown owns no pause lease. Even a cache-only failed rollback must
        // retire the original map rather than write into a possibly running task.
        if (same && pending()) return NativePlatformRestartRequired;
        // A PID disappearance or new map alone is not a retirement receipt.
        // All lookup references are released before operating on the retained task.
        if (pending()) return retireExact();
        cache = {};
        retry = {};
        settings = {};
        recovery = {};
        mapRelease(map); map = nullptr; pid = 0; RetirementRuntime::releaseRemoteClean(retainedTask);
        return 0;
    }
    void report(int status, NativePlatformProcessReport &out) const {
        out = {1, status, ready, pending(), pid, map != nullptr, pending(), 0};
    }
};

void *(*NativePlatformProcess::processTask)(proc_t);
NativePlatformProcess::Map (*NativePlatformProcess::mapReference)(void *);
void (*NativePlatformProcess::mapRelease)(Map);
int (*NativePlatformProcess::mapRead)(Map, uint64_t, void *, uint64_t);
int (*NativePlatformProcess::mapWrite)(Map, const void *, uint64_t, uint64_t);
int (*NativePlatformProcess::mapProtection)(Map, uint64_t, uint64_t, vm_prot_t, const void *);
const void *NativePlatformProcess::mapProtectionCaller;
int (*NativePlatformProcess::taskSuspended)(void *);
bool NativePlatformProcess::ready;
