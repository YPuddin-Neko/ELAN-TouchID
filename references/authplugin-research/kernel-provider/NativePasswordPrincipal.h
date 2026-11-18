#pragma once
#include "NativeEnrollmentAuthorization.h"
struct NativePasswordPrincipalAPI {
 int (*copyCredentials)(const void*,unsigned,unsigned,void***,unsigned*);
 void (*deallocList)(void**,unsigned);
 int (*getProperty)(const void*,unsigned,const void**,size_t*);
};
static constexpr unsigned NativePasswordPrincipalLimit=64;
// Copies remain inside the ACM workloop and are scrubbed/freed by ACM's paired
// deallocator. Only property 5 is read; no payload is logged or exported.
static inline int nativePasswordPrincipals(const NativePasswordPrincipalAPI&api,
 const uint8_t*handle,uint32_t expectedUser,uint32_t*present,uint32_t*verified,NativeEnrollmentDiagnostic*diagnostic=nullptr){
 NativeEnrollmentDiagnostic local{};auto&d=diagnostic?*diagnostic:local;d=NativeEnrollmentDiagnostic{};
 if(!present||!verified){d.rejectKind=NativeEnrollmentShape;return NativeProviderInvalid;}
 *present=0;*verified=0;
 if(!handle||expectedUser==UINT32_MAX||!api.copyCredentials||!api.deallocList||!api.getProperty){d.rejectKind=NativeEnrollmentContext;return NativeProviderInvalid;}
 const unsigned types[]={1,10};
 for(unsigned i=0;i<2;++i){
  d.type=types[i];d.index=UINT32_MAX;d.count=0;
  void**list=nullptr;unsigned count=0;
  int status=api.copyCredentials(handle,types[i],0,&list,&count);
  // The pinned API owns and frees partial copies on error; outputs are untouched.
  if(status){d.rejectKind=NativeEnrollmentCopyError;return status;}
  d.count=count;
  if(!list){if(count){d.rejectKind=NativeEnrollmentShape;return NativeStudyUnexpected;}continue;}
  // A successful nonnull list is owned, even when its count violates our bound.
  int checked=(!count||count>NativePasswordPrincipalLimit)?NativeStudyUnexpected:0;
  if(checked)d.rejectKind=NativeEnrollmentShape;
  if(count)*present|=1U<<i;
  for(unsigned j=0;!checked&&j<count;++j){
   d.index=j;
   if(!list[j]){d.rejectKind=NativeEnrollmentShape;checked=NativeStudyUnexpected;break;}
   const void*value=nullptr;size_t length=0;
   checked=api.getProperty(list[j],5,&value,&length);
   if(checked){d.rejectKind=NativeEnrollmentPropertyError;break;}
   if(!value||length!=sizeof(uint32_t)){d.rejectKind=NativeEnrollmentShape;checked=NativeStudyUnexpected;break;}
   uint32_t principal=UINT32_MAX;memcpy(&principal,value,sizeof(principal));
   if(principal==UINT32_MAX||principal!=expectedUser){
    d.rejectKind=principal==UINT32_MAX?NativeEnrollmentWildcard:principal==0?NativeEnrollmentZero:NativeEnrollmentOtherPrincipal;
    checked=NativeEnrollmentNotAuthorized;
   }
  }
  api.deallocList(list,count);
  if(checked)return checked;
  *verified|=1U<<i;
 }
 d=NativeEnrollmentDiagnostic{};d.rejectKind=NativeEnrollmentMatch;return 0;
}
