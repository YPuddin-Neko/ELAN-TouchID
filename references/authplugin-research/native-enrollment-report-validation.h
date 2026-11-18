#pragma once
#include "kernel-provider/NativeEnrollmentAuthorization.h"
// Scalar diagnostic shape validation never grants authorization on its own.
static inline bool nativeEnrollmentReportValid(const NativeEnrollmentReport&r,uint64_t sequence) {
 if(r.abi!=3||r.reserved||r.active!=1||!sequence||r.sequence!=sequence||r.authorized>1||r.ownerPolicy>1||(r.passwordCredentialTypes&~3U)||(r.principalVerifiedTypes&~r.passwordCredentialTypes))return false;
 const auto&d=r.diagnostic;
 const bool aggregate=d.type==0&&d.index==UINT32_MAX&&d.count==0;
 const bool typed=d.type==1||d.type==10;
 const bool entry=typed&&d.count>0&&d.count<=64&&d.index<d.count;
 bool shape=false;
 switch(d.rejectKind){
 case 0:case 7:case 8:case 9:case 10:case 11:case 12:shape=aggregate;break;
 case 1:shape=typed&&d.index==UINT32_MAX&&!d.count;break;
 case 2:case 4:case 5:case 6:shape=entry;break;
 case 3:shape=typed&&(d.index==UINT32_MAX||entry);break;
 default:return false;
 }
 if(!shape)return false;
 if(!r.operationStatus)return r.authorized==1&&r.passwordCredentialTypes&&r.principalVerifiedTypes==r.passwordCredentialTypes&&r.ownerPolicy==1&&d.rejectKind==7;
 if(r.authorized||d.rejectKind==7||d.rejectKind==0)return false;
 if(d.rejectKind>=1&&d.rejectKind<=6){
  const uint32_t bit=d.type==1?1U:2U;
  if(r.ownerPolicy||(r.principalVerifiedTypes&bit))return false;
  if((d.rejectKind!=1&&!(d.rejectKind==3&&d.index==UINT32_MAX))&&d.count&&!(r.passwordCredentialTypes&bit))return false;
  if(d.rejectKind>=4&&r.operationStatus!=NativeEnrollmentNotAuthorized)return false;
 }
 if(d.rejectKind==8&&(!r.passwordCredentialTypes||r.principalVerifiedTypes!=r.passwordCredentialTypes))return false;
 if(d.rejectKind>=9&&r.ownerPolicy)return false;
 if(d.rejectKind==12&&(r.passwordCredentialTypes||r.principalVerifiedTypes||r.operationStatus!=NativeEnrollmentNotAuthorized))return false;
 return true;
}
