#include "NativeSettingsEnrollmentAuthorization.h"
#include <assert.h>
#include <stdio.h>
#include <vector>
using namespace NativeSettingsEnrollmentAuthorization;
struct Credential{uint32_t principal=UINT32_MAX,flags=2;};
static std::vector<Credential> entries;
static std::vector<void*> pointers;
static int copies,frees,policies,copyStatus,propertyStatus,policyStatus;
static bool matched,nullList,nullProperty,nullEntry;
static size_t propertySize;
static unsigned seenType,seenGlobal;
static int copy(const void*,unsigned type,unsigned global,void***out,unsigned*n){
 ++copies;seenType=type;seenGlobal=global;if(copyStatus)return copyStatus;
 pointers.clear();for(auto &c:entries)pointers.push_back(&c);
 if(nullEntry&&!pointers.empty())pointers.back()=nullptr;
 *out=nullList||pointers.empty()?nullptr:pointers.data();*n=entries.size();return 0;
}
static void freeList(void**,unsigned){++frees;}
static int property(const void*c,unsigned p,const void**out,size_t*n){
 if(propertyStatus)return propertyStatus;
 assert(p==5||p==101);auto &entry=*static_cast<const Credential*>(c);
 *out=nullProperty?nullptr:(p==5?&entry.principal:&entry.flags);*n=propertySize;return 0;
}
static int policy(const uint8_t*h,uint32_t user,bool*out){++policies;assert(h[0]==42&&user==501);*out=matched;return policyStatus;}
static API api(){return {copy,freeList,property,policy};}
static Input reset(){entries.assign(1,Credential{});copies=frees=policies=copyStatus=propertyStatus=policyStatus=0;
 matched=true;nullList=nullProperty=nullEntry=false;propertySize=4;Input i{};i.trustedSettingsSource=i.privateContext=true;i.expectedUser=501;i.context[0]=42;return i;}
int main(){
 for(uint32_t p:{501U,UINT32_MAX}){auto i=reset();entries[0].principal=p;auto r=authorize(api(),i);assert(r.authorized&&r.exactUIDSeen==(p==501)&&r.wildcardSeen==(p==UINT32_MAX)&&frees==1&&policies==1&&seenType==1&&!seenGlobal);}
 for(unsigned index=0;index<3;++index)for(uint32_t p:{0U,502U,500U}){auto i=reset();entries.resize(3);entries[index].principal=p;auto r=authorize(api(),i);assert(!r.authorized&&r.reject==Reject::Principal&&frees==1&&!policies);}
 for(unsigned index=0;index<3;++index){auto i=reset();entries.resize(3);entries[index].flags=3;assert(authorize(api(),i).reject==Reject::Flags&&!policies&&frees==1);}
 {auto i=reset();entries.resize(64);assert(authorize(api(),i).authorized);entries.back().principal=502;assert(!authorize(api(),i).authorized);}
 {auto i=reset();entries.resize(65);assert(authorize(api(),i).reject==Reject::Shape&&frees==1&&!policies);}
 {auto i=reset();entries.clear();assert(!authorize(api(),i).authorized&&!policies);}
 for(unsigned fault=0;fault<10;++fault){auto i=reset();switch(fault){case 0:i.trustedSettingsSource=false;break;case 1:i.privateContext=false;break;case 2:i.expectedUser=502;break;case 3:i.context[0]=0;break;case 4:nullList=true;break;case 5:nullEntry=true;break;case 6:nullProperty=true;break;case 7:propertySize=8;break;case 8:copyStatus=-7;break;case 9:propertyStatus=-8;break;}assert(!authorize(api(),i).authorized&&!policies);}
 for(size_t size:{size_t(0),size_t(3),size_t(5)}){auto i=reset();propertySize=size;assert(authorize(api(),i).reject==Reject::Shape);}
 {auto i=reset();matched=false;assert(authorize(api(),i).reject==Reject::Policy&&policies==1);}
 {auto i=reset();policyStatus=-9;auto r=authorize(api(),i);assert(r.reject==Reject::Policy&&r.operationStatus==-9&&!r.authorized);}
 {auto i=reset();entries[0].flags=0x80000002U;assert(authorize(api(),i).authorized);}
 {auto i=reset();auto a=api();a.policy=nullptr;assert(authorize(a,i).reject==Reject::API&&!copies);}
 puts("Offline trusted-Settings authorization candidate passed; no native authentication");
}
