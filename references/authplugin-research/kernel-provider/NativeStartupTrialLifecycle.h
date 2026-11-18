#pragma once

static bool nativeStartupTrialEligible(OSObject *client) {
    return client && providerOwner == client && providerState.active && providerState.user == 501 &&
        providerState.identityCount == 0 && providerState.lastSequence == 0 &&
        !providerState.quarantined && !startupTrialCommitted && !availabilityRestorePending && !startupTrialRecoveryPending &&
        !providerGate.snapshot().recoveryOnly && providerPlatform.attached() && !settingsPlatform.attached();
}
static void nativeStartupTrialReport(int status, NativeStartupTrialReport &report) {
    report = {1, status, startupTrial.armed(), startupTrial.token() != 0, startupTrial.cancelled(),
              startupTrialRecoveryPending || providerGate.snapshot().recoveryOnly, startupTrial.nonce()};
}

IOReturn ELANNativeProbe::startupTrialArm(OSObject *client, const NativeStartupTrialRequest &request,
                                        NativeStartupTrialReport &report) {
    if (request.abi != 1 || request.user != 501 || !request.nonce) return kIOReturnBadArgument;
    // providerRun owns the operation gate here. The ACM work-loop query is never
    // performed with providerLock held and cannot be replaced by a registry flag.
    if (!nativeStartupTrialEligible(client)) { report = {1, NativeProviderNotActive, 0, 0, 0, 0, request.nonce}; return kIOReturnNotOpen; }
    NativeStartupTrialReport availability {};
    IOReturn result = providerACM(ElanProviderStartupTrialArm, nullptr, &availability);
    IOLockLock(providerLock);
    auto *owner = OSDynamicCast(ELANNativeProbeClient, client);
    bool ready = !result && !availability.status && owner && !owner->isClosing() &&
        nativeStartupTrialEligible(client) && startupTrial.arm(reinterpret_cast<uintptr_t>(client), request.nonce);
    nativeStartupTrialReport(ready ? 0 : NativeProviderBusy, report);
    IOLockUnlock(providerLock);
    return ready ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn ELANNativeProbe::startupTrialCancel(OSObject *client, const NativeStartupTrialRequest &request,
                                           NativeStartupTrialReport &report) {
    if (request.abi != 1 || request.user != 501 || !request.nonce) return kIOReturnBadArgument;
    auto *nativeClient = OSDynamicCast(ELANNativeProbeClient, client);
    if (!nativeClient || !providerLock) return kIOReturnNotAttached;
    NativeProviderOperationReferences references(this, client);
    uint64_t identity = reinterpret_cast<uintptr_t>(client);
    IOLockLock(providerLock);
    bool inFlight = startupTrial.token() && startupTrial.owner() == identity;
    bool gateBusy = providerGate.snapshot().active && !inFlight;
    // providerOwner is read only when no foreign operation can mutate it.
    bool owner = !nativeClient->isClosing() && !gateBusy && (inFlight || providerOwner == client);
    bool accepted = owner && ((!startupTrial.armed() && !startupTrial.token()) || startupTrial.cancel(identity, request.nonce));
    if (accepted && inFlight) providerGate.ownerClosed(identity);
    nativeStartupTrialReport(accepted ? 0 : NativeProviderNotActive, report);
    if (accepted) { report.cancelled = 1; report.nonce = request.nonce; }
    IOLockUnlock(providerLock);
    return accepted ? kIOReturnSuccess : gateBusy ? kIOReturnBusy : kIOReturnNotOpen;
}

IOReturn ELANNativeProbe::startupTrialLease(NativeStartupTrialLeaseRequest &request) {
    if (request.abi != 1 || request.reserved || request.operation > NativeStartupTrialLeaseFinish ||
        (request.operation != NativeStartupTrialLeaseFinish && request.outcome) ||
        request.outcome > NativeStartupTrialLeaseRecoveryRequired) return kIOReturnBadArgument;
    if (!providerLock) return kIOReturnNotReady;
    if (request.operation == NativeStartupTrialLeasePeek || request.operation == NativeStartupTrialLeaseAcquire) {
        if (request.token) return kIOReturnBadArgument;
        IOLockLock(providerLock);
        auto *owner = OSDynamicCast(ELANNativeProbeClient, providerGate.snapshot().active ? nullptr : static_cast<OSObject *>(providerOwner));
        bool ready = owner && !owner->isClosing() && startupTrial.armed() &&
            startupTrial.owner() == reinterpret_cast<uintptr_t>(owner) && nativeStartupTrialEligible(owner);
        if (request.operation == NativeStartupTrialLeasePeek || !ready) {
            IOLockUnlock(providerLock);
            return ready ? kIOReturnSuccess : kIOReturnNotReady;
        }
        uint64_t identity = reinterpret_cast<uintptr_t>(owner);
        uint64_t token = providerGate.begin(identity, true);
        if (!token || !startupTrial.reserve(identity, token)) {
            IOLockUnlock(providerLock); return kIOReturnBusy;
        }
        // retain() only increments the reference count; destruction/release stays
        // outside the mutex. Closing cannot free the captured owner during ACM IO.
        owner->retain(); retain(); startupLeaseOwner = owner;
        IOLockUnlock(providerLock);
        NativeStartupTrialReport availability {};
        IOReturn result = providerACM(ElanProviderStartupTrialArm, nullptr, &availability);
        IOLockLock(providerLock);
        ready = !result && !availability.status && !owner->isClosing() &&
            providerGate.mayProceed(token, identity) && nativeStartupTrialEligible(owner) && startupTrial.acquired(token, identity);
        IOLockUnlock(providerLock);
        if (!ready) {
            NativeStartupTrialLeaseRequest finish {1, NativeStartupTrialLeaseFinish, token, NativeStartupTrialLeaseClean, 0};
            startupTrialLease(finish);
            return kIOReturnNotReady;
        }
        request.token = token;
        return kIOReturnSuccess;
    }
    IOLockLock(providerLock);
    OSObject *ownerObject = startupLeaseOwner;
    auto *owner = OSDynamicCast(ELANNativeProbeClient, ownerObject);
    uint64_t identity = reinterpret_cast<uintptr_t>(ownerObject);
    if (!owner || !request.token || startupTrial.token() != request.token || startupTrial.owner() != identity) {
        IOLockUnlock(providerLock); return kIOReturnNotOpen;
    }
    bool valid = !owner->isClosing() && providerGate.mayProceed(request.token, identity) &&
        startupTrial.valid(request.token, identity) && nativeStartupTrialEligible(owner);
    if (request.operation == NativeStartupTrialLeaseCheck) {
        IOLockUnlock(providerLock); return valid ? kIOReturnSuccess : kIOReturnAborted;
    }
    // A failed committed finish retains the lease: the writer must retire its
    // exact captured target before retrying Finish(Retired/RecoveryRequired).
    if (request.outcome == NativeStartupTrialLeaseCommitted && !valid) {
        IOLockUnlock(providerLock); return kIOReturnAborted;
    }
    if (request.outcome == NativeStartupTrialLeaseCommitted) {
        // Commit and gate release are one mutex-protected decision. A later close
        // belongs to the committed session; it cannot retroactively accept this lease.
        startupTrialCommitted = true;
        startupTrial.finish(request.token, identity);
        startupLeaseOwner = nullptr;
        providerGate.finish(request.token, identity, false);
        IOLockUnlock(providerLock);
        ownerObject->release(); release();
        return kIOReturnSuccess;
    }
    if (request.outcome == NativeStartupTrialLeaseRecoveryRequired) {
        startupTrialRecoveryPending = true;
        providerGate.requireRecovery(request.token, identity);
    }
    bool cleanup = !valid || request.outcome == NativeStartupTrialLeaseRecoveryRequired;
    if (cleanup) providerGate.requireRecovery(request.token, identity);
    IOLockUnlock(providerLock);
    if (cleanup) providerCleanup();
    for (;;) {
        providerPublish();
        IOLockLock(providerLock);
        // A close before gate release belongs to this lease and must be cleaned
        // before dropping its retained owner. No check/unlock/finish gap exists.
        bool cancelled = owner->isClosing() || !providerGate.mayProceed(request.token, identity);
        if (cancelled && !cleanup) {
            IOLockUnlock(providerLock);
            providerCleanup(); cleanup = true;
            continue;
        }
        startupTrial.finish(request.token, identity);
        startupLeaseOwner = nullptr;
        providerGate.finish(request.token, identity, nativeProviderStateClean() && !availabilityRestorePending);
        IOLockUnlock(providerLock);
        ownerObject->release(); release();
        return kIOReturnSuccess;
    }
}
