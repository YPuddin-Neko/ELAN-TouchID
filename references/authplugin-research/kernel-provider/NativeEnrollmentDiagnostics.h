#pragma once
#include <stdint.h>
namespace NativeEnrollmentDiagnostics {
struct Snapshot {
 uint32_t operationStatus=0, rejectKind=0, passwordTypes=0, principalTypes=0;
 bool ownerPolicy=false, authorized=false, observed=false;
};
inline uint64_t pack(const Snapshot &s) {
 return (uint64_t{1}<<56)|uint64_t(s.operationStatus)|(uint64_t(s.rejectKind&255)<<32)|
  (uint64_t(s.passwordTypes&15)<<40)|(uint64_t(s.principalTypes&15)<<44)|
  (uint64_t(s.ownerPolicy)<<48)|(uint64_t(s.authorized)<<49)|(uint64_t(s.observed)<<50);
}
inline Snapshot decode(uint64_t word) {
 Snapshot s{};
 if ((word>>56)!=1) return s;
 s.operationStatus=uint32_t(word);s.rejectKind=(word>>32)&255;
 s.passwordTypes=(word>>40)&15;s.principalTypes=(word>>44)&15;
 s.ownerPolicy=(word>>48)&1;s.authorized=(word>>49)&1;s.observed=(word>>50)&1;
 return s;
}
struct State {
 uint64_t last=uint64_t{1}<<56;
 void record(int32_t status,uint32_t reject,uint32_t password,uint32_t principal,bool owner,bool authorized) {
  Snapshot s{};s.operationStatus=static_cast<uint32_t>(status);s.rejectKind=reject;
  s.passwordTypes=password;s.principalTypes=principal;s.ownerPolicy=owner;s.authorized=authorized;s.observed=true;
  __atomic_store_n(&last,pack(s),__ATOMIC_RELEASE);
 }
 uint64_t snapshot()const{return __atomic_load_n(&last,__ATOMIC_ACQUIRE);}
};
}
