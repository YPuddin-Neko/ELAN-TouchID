#include "ProviderOperationFixture.h"
#include "NativeProviderOperationLifecycle.h"
#include <initializer_list>
IOReturn ELANNativeProbeClient::externalMethod(uint32_t, IOExternalMethodArguments *, IOExternalMethodDispatch *, OSObject *, void *) { return 0; }
struct Fixture {
    ELANNativeProbe service;
    ELANNativeProbeClient client, foreign;
    NativeProviderInput input {};
    NativeProviderOutput output {};
    Fixture() {
        assert(!providerGate.snapshot().active);
        providerGate = {}; startupTrial = {}; startupLeaseOwner = nullptr; startupTrialRecoveryPending = false; startupTrialCommitted = false;
        providerState = {}; providerOwner = nullptr; providerPlatform.seed(false); settingsPlatform.seed(false);
        callback = {}; events.clear(); stopFails = mapFails = enableFails = recoverLeavesPending = false;
        missingMatching = missingService = missingWorkLoop = availabilityRestorePending = studyRestoreFails = false;
        acmFailureSelector = -1; providerReady = studyReady = startSuccess = true; symbolsReady = 1; startupAvailability = 1;
        service.label = "provider"; client.label = "client"; foreign.label = "foreign";
        client.provider = foreign.provider = &service;
    }
    IOReturn call(uint32_t selector, ELANNativeProbeClient *who = nullptr) {
        return service.providerOperation(who ? who : &client, selector, &input, &output);
    }
    void begin() {
        assert(call(ElanProviderCatalogBegin) == 0);
        assert(call(ElanProviderPlatformEnable) == 0);
    }
    IOReturn arm(uint64_t nonce = 41) { input.startupTrial = {1,501,nonce}; return call(ElanProviderStartupTrialArm); }
    IOReturn cancel(uint64_t nonce = 41, ELANNativeProbeClient *who = nullptr) { input.startupTrial = {1,501,nonce}; return call(ElanProviderStartupTrialCancel, who); }
    IOReturn lease(uint32_t operation, uint64_t &token, uint32_t outcome = 0) {
        NativeStartupTrialLeaseRequest r {1,operation,token,outcome,0}; auto result = service.startupTrialLease(r); token=r.token; return result;
    }
    ~Fixture() {
        callback = {}; client.clientClose(); foreign.clientClose();
        assert(!providerGate.snapshot().active && !startupLeaseOwner);
        assert(service.references == 1 && client.references == 1 && foreign.references == 1);
        providerOwner = nullptr;
    }
};
int main() {
    unsigned checks=0;
    {
        Fixture f; uint64_t token=0;
        assert(f.lease(NativeStartupTrialLeasePeek,token)==kIOReturnNotReady); ++checks;
        assert(f.arm()==kIOReturnNotOpen); ++checks;
        assert(f.call(ElanProviderCatalogBegin)==0); assert(f.arm()==kIOReturnNotOpen); ++checks;
        assert(f.call(ElanProviderPlatformEnable)==0); assert(f.arm()==0); ++checks;
        assert(f.output.startupTrial.armed && f.output.startupTrial.nonce==41);
        assert(f.lease(NativeStartupTrialLeasePeek,token)==0 && !token && startupTrial.armed()); ++checks;
        assert(f.lease(NativeStartupTrialLeaseAcquire,token)==0 && token && !startupTrial.armed()); ++checks;
        assert(f.call(ElanProviderEnd)==kIOReturnBusy); ++checks;
        assert(f.lease(NativeStartupTrialLeaseCheck,token)==0); ++checks;
        assert(f.lease(NativeStartupTrialLeaseFinish,token,NativeStartupTrialLeaseCommitted)==0); ++checks;
        token=0; assert(f.lease(NativeStartupTrialLeaseAcquire,token)==kIOReturnNotReady); ++checks;
        assert(f.arm()==kIOReturnNotOpen); ++checks;
    }
    for (unsigned reason=0; reason<6; ++reason) {
        Fixture f; f.begin();
        if(reason==0) providerState.identityCount=1;
        if(reason==1) providerState.lastSequence=1;
        if(reason==2) providerState.user=502;
        if(reason==3) providerState.quarantined=true;
        if(reason==4) settingsPlatform.seed(true);
        if(reason==5) startupAvailability=0;
        assert(f.arm()!=0); ++checks;
    }
    {
        Fixture f; f.begin(); assert(f.arm()==0); uint64_t token=0;
        startupAvailability=0; assert(f.lease(NativeStartupTrialLeaseAcquire,token)!=0 && !token); ++checks;
        assert(!providerGate.snapshot().active && startupTrial.armed()); ++checks;
        startupAvailability=1; assert(f.lease(NativeStartupTrialLeaseAcquire,token)==0); ++checks;
        assert(f.cancel(42)!=0); assert(f.cancel(41,&f.foreign)!=0); ++checks;
        assert(f.cancel()==0); ++checks;
        assert(f.lease(NativeStartupTrialLeaseCheck,token)==kIOReturnAborted); ++checks;
        assert(f.lease(NativeStartupTrialLeaseFinish,token,NativeStartupTrialLeaseCommitted)==kIOReturnAborted && providerGate.snapshot().active); ++checks;
        assert(f.lease(NativeStartupTrialLeaseFinish,token,NativeStartupTrialLeaseRetired)==0); ++checks;
    }
    {
        Fixture f; f.begin(); assert(f.arm()==0); uint64_t token=0; assert(f.lease(1,token)==0);
        f.client.clientClose(); assert(providerGate.snapshot().active && startupLeaseOwner); ++checks;
        assert(f.lease(3,token,1)==kIOReturnAborted); ++checks;
        assert(f.lease(3,token,2)==0 && !startupLeaseOwner && !providerGate.snapshot().active); ++checks;
    }
    {
        Fixture f; f.begin(); assert(f.arm()==0); uint64_t token=0; assert(f.lease(1,token)==0);
        assert(f.lease(3,token,3)==0); assert(startupTrialRecoveryPending && providerGate.snapshot().recoveryOnly); ++checks;
        assert(f.arm(42)!=0); ++checks;
    }
    {
        Fixture f; f.begin(); providerState.active=false; providerState.restorePending=true;
        assert(f.cancel()==0); assert(f.cancel(41,&f.foreign)==kIOReturnNotOpen); checks+=2;
    }
    {
        Fixture f; f.begin(); assert(f.arm()==0);
        assert(f.call(ElanProviderSettingsInspect)==0); uint64_t token=0;
        assert(f.lease(1,token)==kIOReturnNotReady); ++checks;
    }
    printf("startup trial lifecycle: %u production owner/lease/cancel/close/one-shot checks passed\n",checks);
}
