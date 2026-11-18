#include "NativeStartupObservation.h"
#include <initializer_list>
#include <cassert>
#include <cstdio>
using namespace NativeStartupObservation;
static Policy policy() { return {91, {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}}; }
static Target target() {
    Target t {{91,1,31,41,51}, 501, TargetPath, {}, true};
    auto p = policy(); memcpy(t.executableUUID, p.executableUUID, 16); return t;
}
static Check check() { return {0,true,false,true,true,Observation::Cold}; }
int main() {
    auto p=policy(); auto t=target(); auto c=check();
    State s;
    assert(!observe(s,p,t,c)); // existing instance has no exec admission
    assert(!onExec(s,p,t,false)); assert(!observe(s,p,t,c));
    for (auto value : {Observation::Cold,Observation::CompletedEmpty,Observation::Live,Observation::Initializing}) {
        State a; assert(onExec(a,p,t,true)); c.observation=value;
        assert(observe(a,p,t,c)); assert(a.observation==value);
        assert(!observe(a,p,t,c)); // exactly once
        assert(!onExec(a,p,t,true)); assert(!observe(a,p,t,c)); // replayed exec
    }
    c=check();
    for (int n=0;n<10;n++) {
        State a; auto bad=t;
        switch(n) {
            case 0: bad.uid=0;break; case 1: bad.path="/tmp/Touch ID & Password";break;
            case 2: bad.path=nullptr;break; case 3: bad.executableUUID[0]^=1;break;
            case 4: bad.trustedSignature=false;break; case 5: bad.identity.bootNonce++;break;
            case 6: bad.identity.execGeneration=0;break; case 7: bad.identity.procUniqueID=0;break;
            case 8: bad.identity.task=0;break; case 9: bad.identity.map=0;break;
        }
        assert(!onExec(a,p,bad,true)); assert(!observe(a,p,bad,c));
    }
    for (int n=0;n<6;n++) {
        State a; assert(onExec(a,p,t,true)); auto bad=c;
        switch(n) {case 0:bad.status=-1;break;case 1:bad.outputArgumentNonNull=false;break;
            case 2:bad.specialArgument=true;break;case 3:bad.outputReadSucceeded=false;break;
            case 4:bad.cacheAddressNonZero=false;break;case 5:bad.observation=Observation::Unknown;break;}
        assert(!observe(a,p,t,bad)); assert(!a.recorded); assert(observe(a,p,t,c));
    }
    for (int n=0;n<5;n++) {
        State a;assert(onExec(a,p,t,true)); auto changed=t;
        switch(n) {case 0:changed.identity.bootNonce++;break;case 1:changed.identity.execGeneration++;break;
            case 2:changed.identity.procUniqueID++;break;case 3:changed.identity.task++;break;case 4:changed.identity.map++;break;}
        assert(!observe(a,p,changed,c));
        if (n == 2) { assert(a.armed); assert(observe(a,p,t,c)); }
        else { assert(!a.armed); assert(!observe(a,p,t,c)); }
    }
    assert(onExec(s,p,t,true)); auto other=t.identity;other.procUniqueID++;
    onExit(s,other);assert(s.armed);onExit(s,t.identity);assert(!s.armed);
    assert(!onExec(s,p,t,true)); // exit cannot permit replay
    t.identity.execGeneration++;assert(onExec(s,p,t,true));assert(observe(s,p,t,c));
    targetChanged(s);assert(!s.armed && !s.recorded && s.observation==Observation::Unknown);
    assert(!onExec(s,p,t,true));
    t.identity.execGeneration++;assert(onExec(s,p,t,true));
    auto invalid=t;invalid.trustedSignature=false;assert(!observe(s,p,invalid,c));assert(!s.armed);
    {
        State a; auto incumbent=target(); assert(onExec(a,p,incumbent,true));
        auto unrelated=incumbent; unrelated.identity.procUniqueID=999;
        unrelated.identity.execGeneration=2; unrelated.path="/bin/other";
        assert(!onExec(a,p,unrelated,true)); assert(a.armed && same(a.binding,incumbent.identity));
        assert(!observe(a,p,unrelated,c)); assert(a.armed && !a.recorded);
        auto contender=incumbent; contender.identity.procUniqueID=888; contender.identity.execGeneration=3;
        assert(!onExec(a,p,contender,true)); assert(same(a.binding,incumbent.identity));
        assert(!observe(a,p,contender,c)); assert(a.armed);
        assert(observe(a,p,incumbent,c));
        unrelated.identity.execGeneration=4;
        assert(!onExec(a,p,unrelated,true)); assert(a.recorded);
        assert(!observe(a,p,incumbent,c));
        auto replaced=incumbent; replaced.identity.execGeneration=5; replaced.path="/bin/other";
        assert(!onExec(a,p,replaced,true)); assert(!a.armed && !a.recorded);
        assert(!observe(a,p,incumbent,c));
        // A rejected competing exec must not become admissible by replay after exit.
        assert(!onExec(a,p,contender,true));
        replaced=incumbent; replaced.identity.execGeneration=6;
        assert(onExec(a,p,replaced,true));
        auto changed=replaced; changed.executableUUID[0]^=1;
        assert(!observe(a,p,changed,c)); assert(!a.armed);
    }
    puts("startup observation model: identity, lifecycle, syscall filtering and once-only cases passed");
}
