#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Offline candidate: source and private-context premises need a trusted adapter.
namespace NativeSettingsEnrollmentAuthorization {
enum class Reject {None,Source,Context,API,Copy,Shape,Principal,Flags,Property,Policy};
struct Input {
 bool trustedSettingsSource=false,privateContext=false;
 uint32_t expectedUser=0;
 uint8_t context[16]{};
};
struct API {
 int (*copy)(const void*,unsigned,unsigned,void***,unsigned*);
 void (*freeList)(void**,unsigned);
 int (*property)(const void*,unsigned,const void**,size_t*);
 // Must evaluate native TouchIdEnrollment on this exact context, preserving matched.
 int (*policy)(const uint8_t*,uint32_t,bool*);
};
struct Result {
 bool authorized=false,exactUIDSeen=false,wildcardSeen=false;
 Reject reject=Reject::None;
 int operationStatus=0;
};
inline Result authorize(const API&a,const Input&input){
 Result r{};
 if(!input.trustedSettingsSource||input.expectedUser!=501){r.reject=Reject::Source;return r;}
 uint8_t any=0;for(auto b:input.context)any|=b;
 if(!input.privateContext||!any){r.reject=Reject::Context;return r;}
 if(!a.copy||!a.freeList||!a.property||!a.policy){r.reject=Reject::API;return r;}
 void**list=nullptr;unsigned count=0;
 r.operationStatus=a.copy(input.context,1,0,&list,&count);
 if(r.operationStatus){r.reject=Reject::Copy;return r;}
 if(!list||!count||count>64){if(list)a.freeList(list,count);r.reject=Reject::Shape;return r;}
 for(unsigned i=0;i<count;++i){
  if(!list[i]){r.reject=Reject::Shape;break;}
  uint32_t principal=0,flags=0;
  const unsigned properties[]={5,101};
  for(unsigned j=0;j<2;++j){
   const void*value=nullptr;size_t size=0;
   r.operationStatus=a.property(list[i],properties[j],&value,&size);
   if(r.operationStatus){r.reject=Reject::Property;break;}
   if(!value||size!=4){r.reject=Reject::Shape;break;}
   memcpy(j?&flags:&principal,value,4);
  }
  if(r.reject!=Reject::None)break;
  if(principal!=input.expectedUser&&principal!=UINT32_MAX){r.reject=Reject::Principal;break;}
  if(flags&1){r.reject=Reject::Flags;break;}
  r.exactUIDSeen|=principal==input.expectedUser;
  r.wildcardSeen|=principal==UINT32_MAX;
 }
 a.freeList(list,count);
 if(r.reject!=Reject::None)return r;
 bool matched=false;
 r.operationStatus=a.policy(input.context,input.expectedUser,&matched);
 if(r.operationStatus||!matched){r.reject=Reject::Policy;return r;}
 r.authorized=true;return r;
}
}
