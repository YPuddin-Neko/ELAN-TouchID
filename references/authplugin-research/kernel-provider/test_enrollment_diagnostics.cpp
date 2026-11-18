#include "NativeEnrollmentDiagnostics.h"
#include <assert.h>
#include <stdio.h>
using namespace NativeEnrollmentDiagnostics;
int main(){
 State state;assert(!decode(state.snapshot()).observed);
 const int32_t statuses[]={0,-32004,-1,INT32_MIN,INT32_MAX};
 for(auto status:statuses)for(unsigned reject=0;reject<=12;++reject)
 for(unsigned password=0;password<4;++password)for(unsigned principal=0;principal<4;++principal)
 for(unsigned flags=0;flags<4;++flags){
  state.record(status,reject,password,principal,flags&1,flags&2);
  auto s=decode(state.snapshot());
  assert(s.observed&&s.operationStatus==static_cast<uint32_t>(status)&&s.rejectKind==reject);
  assert(s.passwordTypes==password&&s.principalTypes==principal&&s.ownerPolicy==bool(flags&1)&&s.authorized==bool(flags&2));
 }
 state.record(-1,UINT32_MAX,UINT32_MAX,UINT32_MAX,true,true);
 auto s=decode(state.snapshot());assert(s.rejectKind==255&&s.passwordTypes==15&&s.principalTypes==15&&s.operationStatus==UINT32_MAX&&s.authorized&&s.observed);
 assert(!decode(0).observed&&!decode(uint64_t{2}<<56).observed);
 state.record(0,7,1,1,true,true);state.record(-32004,4,1,0,false,false);
 s=decode(state.snapshot());assert(!s.authorized&&!s.ownerPolicy&&s.principalTypes==0&&s.rejectKind==4);
 puts("Enrollment diagnostic packing and replacement passed");
}
