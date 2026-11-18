#include "NativeProviderABI.h"
#include "NativePasswordPrincipal.h"
#include <assert.h>
#include <stdio.h>
#include <initializer_list>
#include <vector>
struct Credential {uint32_t uid=501;int propertyStatus=0;size_t length=4;bool nullProperty=false;};
static std::vector<Credential> credentials[2];
static unsigned copies,properties,policies,deleted,allocated,released;
static int copyStatus;static bool nullEntry,nullList,zeroCountList;
static bool ownerAccepted=true;static int policyStatus,cleanupStatus;
static const uint8_t handle[16]={0x51,0x22};
static int copy(const void*context,unsigned type,unsigned includeGlobal,void***out,uint32_t*count){assert(!memcmp(context,handle,16));assert(type==1||type==10);assert(includeGlobal==0);++copies;*out=nullptr;*count=0;if(copyStatus){void**partial=new void*[1];++allocated;delete[]partial;++released;return copyStatus;}auto&v=credentials[type==1?0:1];*count=(uint32_t)v.size();if(v.empty()||nullList)return 0;*out=new void*[v.size()];++allocated;for(size_t i=0;i<v.size();++i)(*out)[i]=nullEntry?nullptr:&v[i];if(zeroCountList)*count=0;return 0;}
static void release(void**list,uint32_t count){assert(list);(void)count;delete[]list;++released;}
static int property(const void*value,unsigned type,const void**out,size_t*length){assert(type==5);++properties;auto*c=(const Credential*)value;*out=c->nullProperty?nullptr:&c->uid;*length=c->length;return c->propertyStatus;}
static int password(const uint8_t*context,uint32_t user,uint32_t*types,uint32_t*verified,NativeEnrollmentDiagnostic*diag){return nativePasswordPrincipals({copy,release,property},context,user,types,verified,diag);}
static int policy(void*context,const char*name,const NativeACMParameter*p,unsigned count,unsigned age,bool*satisfied,void**requirement){assert(!memcmp(context,handle,16));assert(!strcmp(name,"TouchIdEnrollment")&&count==1&&age==0&&p->type==4&&p->length==4);assert(*(uint32_t*)p->value==501);++policies;*satisfied=ownerAccepted;*requirement=new unsigned(1);return policyStatus;}
static int destroy(void*r){delete (unsigned*)r;++deleted;return cleanupStatus;}
static NativeEnrollmentAPI api(){NativeEnrollmentAPI a{};a.privatePasswordContext=password;a.acm.verifyPolicy=policy;a.acm.deleteRequirement=destroy;return a;}
static void reset(){assert(allocated==released);credentials[0].clear();credentials[1].clear();copies=properties=policies=deleted=allocated=released=0;copyStatus=0;nullEntry=nullList=zeroCountList=false;ownerAccepted=true;policyStatus=cleanupStatus=0;}
static NativeEnrollmentReport run(){NativeProviderState s{};s.active=true;s.user=501;NativeEnrollmentRequest q{3,501,1,{}};memcpy(q.context,handle,16);NativeEnrollmentReport r{};nativeAuthorizeEnrollment(api(),s,q,r);assert(r.abi==3&&r.sequence==1&&policies==deleted&&allocated==released);return r;}
int main(){
 reset();auto r=run();assert(r.operationStatus==NativeEnrollmentNotAuthorized&&!r.authorized&&!policies&&copies==2);
 for(unsigned mask=1;mask<=3;mask++){reset();for(unsigned i=0;i<2;i++)if(mask&(1<<i))credentials[i].resize(3);r=run();assert(!r.operationStatus&&r.authorized&&r.passwordCredentialTypes==mask&&r.principalVerifiedTypes==mask&&policies==1);}
 // No first-match shortcut: both orderings and every same-type instance matter.
 for(unsigned index=0;index<2;index++)for(unsigned position=0;position<3;position++)for(uint32_t uid:{0U,502U,UINT32_MAX}){reset();credentials[0].resize(3);credentials[1].resize(3);credentials[index][position].uid=uid;r=run();assert(r.operationStatus==NativeEnrollmentNotAuthorized&&!r.authorized&&!policies);assert(!(r.principalVerifiedTypes&(1U<<index)));}
 for(unsigned index=0;index<2;index++)for(unsigned fault=0;fault<7;fault++){reset();credentials[0].resize(2);credentials[1].resize(2);auto&c=credentials[index][1];switch(fault){case 0:c.propertyStatus=-55;break;case 1:c.nullProperty=true;break;case 2:c.length=0;break;case 3:c.length=3;break;case 4:c.length=8;break;case 5:nullEntry=true;break;case 6:copyStatus=-66;break;}r=run();assert(r.operationStatus&&!r.authorized&&!policies);assert(!(r.principalVerifiedTypes&(1U<<index)));}
 reset();credentials[0].resize(1);zeroCountList=true;r=run();assert(r.operationStatus&&!r.authorized&&!properties&&allocated==released);
 reset();credentials[0].resize(65);r=run();assert(r.operationStatus&&!r.authorized&&!policies&&properties==0&&allocated==released);
 reset();credentials[0].resize(64);credentials[0][63].uid=502;r=run();assert(r.operationStatus&&!r.authorized&&!policies&&properties==64);
 reset();credentials[0].resize(64);r=run();assert(r.authorized&&properties==64);
 reset();credentials[0].resize(1);nullList=true;r=run();assert(r.operationStatus&&!r.authorized&&!policies);
 reset();credentials[0].resize(1);ownerAccepted=false;r=run();assert(r.operationStatus==NativeEnrollmentNotAuthorized&&r.principalVerifiedTypes==1&&!r.ownerPolicy&&policies==1);
 reset();credentials[0].resize(1);policyStatus=-40;r=run();assert(r.operationStatus==-40&&!r.authorized&&policies==1&&deleted==1);
 reset();credentials[0].resize(1);cleanupStatus=-41;r=run();assert(r.operationStatus==-41&&!r.authorized&&deleted==1);
 reset();credentials[0].resize(1);NativeProviderState s{};s.active=true;s.user=501;NativeEnrollmentRequest q{3,501,1,{}};memcpy(q.context,handle,16);nativeAuthorizeEnrollment(api(),s,q,r);assert(r.authorized);credentials[0][0].uid=502;q.sequence=2;nativeAuthorizeEnrollment(api(),s,q,r);assert(!r.authorized&&r.principalVerifiedTypes==0&&properties==2&&policies==1&&allocated==released);
 unsigned before=copies;nativeAuthorizeEnrollment(api(),s,q,r);assert(r.operationStatus==NativeProviderInvalid&&copies==before);
 q.sequence=3;q.abi=1;nativeAuthorizeEnrollment(api(),s,q,r);assert(r.operationStatus==NativeProviderInvalid&&copies==before&&s.lastSequence==2);
 q.abi=3;q.user=502;nativeAuthorizeEnrollment(api(),s,q,r);assert(r.operationStatus==NativeProviderInvalid&&copies==before);
 q.user=501;memset(q.context,0,16);nativeAuthorizeEnrollment(api(),s,q,r);assert(r.operationStatus==NativeProviderInvalid&&copies==before);
 s.active=false;nativeAuthorizeEnrollment(api(),s,q,r);assert(r.operationStatus==NativeProviderNotActive&&copies==before);
 uint32_t present=99,verified=99;assert(nativePasswordPrincipals({copy,release,property},nullptr,501,&present,&verified)==NativeProviderInvalid&&present==0&&verified==0);
 reset();
 credentials[0].resize(1);
 NativeEnrollmentReport direct{};
 nativeCheckEnrollmentContext(api(), 501, handle, direct);
 assert(direct.authorized && !direct.active);
 uint8_t emptyHandle[16]{};
 unsigned priorCopies = copies;
 nativeCheckEnrollmentContext(api(), 501, emptyHandle, direct);
 assert(!direct.authorized && !direct.ownerPolicy && !direct.principalVerifiedTypes && copies == priorCopies);
 credentials[0][0].uid=502;
 nativeCheckEnrollmentContext(api(), 501, handle, direct);
 assert(!direct.authorized);
 assert(sizeof(NativeEnrollmentRequest)==32&&sizeof(NativeEnrollmentReport)==56);
 puts("enrollment ABI3: all local password instances, mixed principals, bounds and release, fresh reread, policy failure, replay and ABI1 rejection passed; no real authentication");
return 0;
}
