#pragma once
#include <sys/kauth.h>
#include <stdint.h>

// Include in one translation unit. Lifecycle calls must be serialized by the
// owner. No instance pointers, vnode pointers, paths or task identities escape
// the notification callback. This namespace's storage must outlive callbacks;
// this prototype does not establish that a containing kext can unload safely.
namespace NativeStartupObserverKernel {
static constexpr bool RuntimeEnabled = false;
static kauth_listener_t listener = nullptr;
static uint32_t enabled = 0;
static uint64_t execNotifications = 0;

struct Report {
    bool enabled;
    uint64_t execNotifications;
    bool targetBound;
    bool signatureVerified;
    bool sharedRegionObserved;
};

static int onFileOperation(kauth_cred_t, void *, kauth_action_t action,
                          uintptr_t, uintptr_t, uintptr_t, uintptr_t) {
    if (action == KAUTH_FILEOP_EXEC && __atomic_load_n(&enabled, __ATOMIC_ACQUIRE))
        __atomic_fetch_add(&execNotifications, uint64_t{1}, __ATOMIC_RELAXED);
    return KAUTH_RESULT_DEFER;
}

// Disabled unless explicitly requested. Registration is never performed at
// static initialization, and no KernelPatcher routes are installed here.
static inline bool start(bool requested = false) {
    if (!requested) return false;
    if (listener) return true;
    listener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, onFileOperation, nullptr);
    if (!listener) return false;
    __atomic_store_n(&enabled, uint32_t{1}, __ATOMIC_RELEASE);
    return true;
}
static inline void stop() {
    __atomic_store_n(&enabled, uint32_t{0}, __ATOMIC_RELEASE);
    if (listener) {
        kauth_unlisten_scope(listener);
        listener = nullptr;
    }
}
static inline Report snapshot() {
    return {__atomic_load_n(&enabled, __ATOMIC_ACQUIRE) != 0,
            __atomic_load_n(&execNotifications, __ATOMIC_RELAXED), false, false, false};
}
// EXEC notifications precede process_signature in the inspected spawn path.
// current_proc may be the spawn parent. Counting this notification does not
// bind new_task, validate a signature, or observe shared_region_check_np.
}
