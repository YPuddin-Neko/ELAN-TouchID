#include <IOKit/IOKitLib.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include "../kernel-provider/NativeDirectEnrollment.h"

namespace {
uid_t user=501, effective=501;
io_service_t service=31;
IOReturn openStatus=0,callStatus=0;
ElanDirectEnrollmentReply answer={1,1};
ElanDirectOperationReply opAnswer={1,0};
size_t answerSize=sizeof(answer);
unsigned opens=0,calls=0,closes=0,releases=0;
struct Event { std::string stage; int status; };
std::vector<Event> events;
void diagnostic(const char *stage,int status){events.push_back({stage,status});}
uid_t mockUID(){return user;}
uid_t mockEUID(){return effective;}
CFMutableDictionaryRef mockMatching(const char *name){assert(!strcmp(name,"ELANNativeProbe"));return nullptr;}
io_service_t mockFind(mach_port_t,CFDictionaryRef){return service;}
kern_return_t mockOpen(io_service_t s,task_port_t,uint32_t type,io_connect_t *out){
    assert(s==service&&type==ElanEnrollmentConnectionType);++opens;
    if(!openStatus)*out=51;return openStatus;
}
kern_return_t mockRelease(io_object_t s){assert(s==service);++releases;return 0;}
kern_return_t mockClose(io_connect_t c){assert(c==51);++closes;return 0;}
kern_return_t mockCall(mach_port_t c,uint32_t selector,const void *input,size_t inputSize,void *out,size_t *outSize){
    assert(c==51);++calls;
    if(selector==ElanCheckEnrollment){
        assert(inputSize==16&&*outSize==sizeof(answer));
        assert(static_cast<const uint8_t*>(input)[0]==0x42);
        memcpy(out,&answer,sizeof(answer));*outSize=answerSize;return callStatus;
    }
    if(selector==ElanSyncProviderCatalog){
        assert(inputSize==sizeof(ElanDirectCatalogSync)&&*outSize==sizeof(opAnswer));
        memcpy(out,&opAnswer,sizeof(opAnswer));*outSize=answerSize;return callStatus;
    }
    if(selector==ElanDispatchUnlockKeystrokes){
        assert(inputSize==sizeof(ElanDirectUnlockRequest)&&*outSize==sizeof(opAnswer));
        memcpy(out,&opAnswer,sizeof(opAnswer));*outSize=answerSize;return callStatus;
    }
    assert(selector==ElanSubmitDirectMatch&&inputSize==sizeof(ElanDirectMatchSubmission)&&*outSize==sizeof(opAnswer));
    memcpy(out,&opAnswer,sizeof(opAnswer));*outSize=answerSize;return callStatus;
}
void reset(){user=effective=501;service=31;openStatus=callStatus=0;answer={1,1};opAnswer={1,0};answerSize=sizeof(answer);
    opens=calls=closes=releases=0;events.clear();}
void expect(const char *stage,int status){assert(events.size()==1&&events[0].stage==stage&&events[0].status==status);}
}
#define ELAN_SETTINGS_DIAGNOSTIC(stage,status) diagnostic(stage,(int)(status))
#define getuid mockUID
#define geteuid mockEUID
#define IOServiceMatching mockMatching
#define IOServiceGetMatchingService mockFind
#define IOServiceOpen mockOpen
#define IOObjectRelease mockRelease
#define IOServiceClose mockClose
#define IOConnectCallStructMethod mockCall
#include "DirectEnrollmentPolicy.h"
#undef getuid
#undef geteuid
#undef IOServiceMatching
#undef IOServiceGetMatchingService
#undef IOServiceOpen
#undef IOObjectRelease
#undef IOServiceClose
#undef IOConnectCallStructMethod

int main(){
    const uint8_t context[16]={0x42};
    reset();assert(elanCheckDirectEnrollment(nullptr)==kIOReturnBadArgument);expect("direct-input",kIOReturnBadArgument);assert(!opens&&!calls);
    reset();user=0;assert(elanCheckDirectEnrollment(context)==kIOReturnNotPrivileged);expect("direct-uid",kIOReturnNotPrivileged);assert(!opens);
    reset();effective=502;assert(elanCheckDirectEnrollment(context)==kIOReturnNotPrivileged);expect("direct-uid",kIOReturnNotPrivileged);assert(!opens);
    reset();service=0;assert(elanCheckDirectEnrollment(context)==kIOReturnNotReady);expect("direct-service",kIOReturnNotReady);assert(!opens);
    reset();openStatus=kIOReturnNotPermitted;assert(elanCheckDirectEnrollment(context)==(int)openStatus);expect("direct-open",openStatus);assert(opens==1&&releases==1&&!calls&&!closes);
    reset();callStatus=kIOReturnNotReady;assert(elanCheckDirectEnrollment(context)==(int)callStatus);expect("direct-call",callStatus);assert(opens==1&&calls==1&&closes==1&&releases==1);
    for(size_t bad:{size_t(0),sizeof(answer)-1,sizeof(answer)+1}){
        reset();answerSize=bad;assert(elanCheckDirectEnrollment(context)==kIOReturnNotPrivileged);expect("direct-reply-size",kIOReturnNotPrivileged);assert(closes==1);
    }
    reset();answer.abi=2;assert(elanCheckDirectEnrollment(context)==kIOReturnNotPrivileged);expect("direct-reply-abi",kIOReturnNotPrivileged);assert(closes==1);
    for(uint32_t denied:{uint32_t(0),uint32_t(2),UINT32_MAX}){
        reset();answer.authorized=denied;assert(elanCheckDirectEnrollment(context)==kIOReturnNotPrivileged);expect("direct-denied",kIOReturnNotPrivileged);assert(closes==1);
    }
    reset();assert(elanCheckDirectEnrollment(context)==0);expect("direct-authorized",0);assert(opens==1&&calls==1&&closes==1&&releases==1);
    const uint8_t identity[16]={0x11};
    reset();assert(elanSyncDirectCatalog(nullptr,0)==0);expect("catalog-synced",0);
    reset();assert(elanSyncDirectCatalog(identity,1)==0);expect("catalog-synced",1);
    reset();assert(elanSyncDirectCatalog(nullptr,1)==kIOReturnBadArgument);expect("catalog-sync-input",kIOReturnBadArgument);
    reset();assert(elanSubmitDirectMatch(1,identity,context,1)==0);expect("match-submitted",1);
    reset();assert(elanSubmitDirectMatch(0,identity,context,1)==kIOReturnBadArgument);expect("match-submit-input",kIOReturnBadArgument);
    const uint8_t secret[6]={'1','2','3','4','5','6'};
    reset();assert(elanDispatchDirectUnlock(secret,6)==0);expect("unlock-dispatched",6);
    reset();assert(elanDispatchDirectUnlock(nullptr,6)==kIOReturnBadArgument);assert(!opens);
    reset();assert(elanDispatchDirectUnlock(secret,0)==kIOReturnBadArgument);assert(!opens);
    reset();assert(elanDispatchDirectUnlock(secret,129)==kIOReturnBadArgument);assert(!opens);
    puts("Direct enrollment diagnostics and unchanged return contract passed (mock IOKit only)");
}
