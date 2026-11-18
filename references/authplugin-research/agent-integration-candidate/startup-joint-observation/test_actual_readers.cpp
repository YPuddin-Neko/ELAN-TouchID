#include "StartupObservation.h"
#include <map>
#include <vector>
#include <cassert>
#include <cstdio>
#include <climits>
#include <assert.h>
#include <stdio.h>
#define main caller_fixture_selftest
namespace CallerFixture {
#include "../early-boundary-observation/test.cpp"
}
#undef main
#define main settings_fixture_selftest
namespace SettingsFixture {
#include "../settings-fresh-observation/test.cpp"
}
#undef main
#define main outer_fixture_selftest
namespace OuterFixture {
#include "../early-shared-region/test_copyin.cpp"
}
#undef main
using namespace StartupObservation;
static int proc,thread;static void*task=reinterpret_cast<void*>(0xffff800000001000ULL);
struct Fixture {
 std::map<uint64_t,std::vector<uint8_t>> memory;CallerEvidence::Registers regs{};
 unsigned copies=0,bytes=0,fail=0,leafCalls=0;bool mutateGeneration=false;int version=7;
 uint64_t output=0;
 Fixture(bool cached){
  CallerFixture::Fixture caller;if(cached)caller.cached();
  constexpr uint64_t delta=0x100000000ULL;
  regs=caller.regs;regs.rip+=delta;output=regs.rbp-0x28;
  for(auto&entry:caller.mem){auto address=entry.first;auto data=entry.second;
   if(address>=CallerFixture::Fixture::base&&address<CallerFixture::Fixture::base+0x100000)address+=delta;
   if(entry.first>=CallerFixture::Fixture::sp)for(size_t off=0;off+8<=data.size();off+=8){uint64_t value;memcpy(&value,data.data()+off,8);if(value>=CallerFixture::Fixture::base&&value<CallerFixture::Fixture::base+0x100000){value+=delta;memcpy(data.data()+off,&value,8);}}
   memory[address]=data;
  }
  SettingsFixture::Fixture settings;memory[SettingsFixture::Fixture::base]=settings.bytes;
  OuterFixture::Fixture outer;for(auto&entry:outer.blocks)memory[entry.first==OuterFixture::output?output:entry.first]=entry.second;
 }
 static int copy(void*c,uint64_t address,void*out,size_t n){auto&f=*static_cast<Fixture*>(c);++f.copies;f.bytes+=unsigned(n);if(f.copies==f.fail)return 14;
  for(auto&entry:f.memory)if(address>=entry.first&&address-entry.first<=entry.second.size()&&n<=entry.second.size()-(address-entry.first)){memcpy(out,entry.second.data()+address-entry.first,n);return 0;}return 14;
 }
};
static Fixture*active;
void*current(void*){return task;}void*procTask(void*,void*p){assert(p==&proc);return task;}
uint64_t processUnique(void*,void*){return 1;}uint64_t taskUnique(void*,void*){return 2;}int pidVersion(void*c,void*){return static_cast<Fixture*>(c)->version;}
void*currentThread(void*){return &thread;}uint16_t tag(void*,void*){return 1;}
bool readKernel(void*,uint64_t a,void*out,size_t n){assert(a==reinterpret_cast<uint64_t>(task)+0x618&&n==8);uint64_t base=SettingsFixture::Fixture::base;memcpy(out,&base,8);return true;}
CurrentThreadCapture::Result capture(CallerEvidence::Copy copy,void*context,uint64_t output){CurrentThreadCapture::Result result;result.stage=CurrentThreadCapture::Stage::Captured;result.count=42;result.caller=CallerEvidence::inspect(copy,context,active->regs,output);return result;}
LeafCowSample::Result leaf(void*t,uint64_t address){assert(t==task&&address==OuterFixture::image+0x38e1b028);++active->leafCalls;if(active->mutateGeneration)++active->version;LeafCowSample::Result result;result.status=LeafCowSample::Status::Cow;return result;}
Result run(Fixture&f){active=&f;API api{{&f,current,procTask,processUnique,pidVersion,taskUnique},nullptr,currentThread,tag,{true},readKernel,nullptr,Fixture::copy,&f,capture,SettingsSample::inspect,leaf,CurrentCopyinSample::inspect};return inspect(api,&proc,task,f.output);}
#ifndef ELAN_ACTUAL_READERS_FIXTURE_ONLY
int main(){for(bool cached:{false,true}){
 Fixture f(cached);auto result=run(f);unsigned count=cached?176:179,bytes=cached?6594:6618;
 assert(result.stage==Stage::Complete&&result.jointlyCold&&result.leafResult.cow());
 assert(f.copies==count&&f.bytes==bytes&&result.userCopies==count&&result.userBytes==bytes&&f.leafCalls==1);
 assert(result.profile==(cached?CallerEvidence::Profile::Cached:CallerEvidence::Profile::Disk));
 for(unsigned fail=1;fail<=count;++fail){Fixture bad(cached);bad.fail=fail;auto rejected=run(bad);assert(rejected.stage!=Stage::Complete&&!rejected.jointlyCold&&!bad.leafCalls);}
 Fixture changed(cached);changed.mutateGeneration=true;auto rejected=run(changed);assert(rejected.stage==Stage::FinalIdentity&&!rejected.jointlyCold);
 printf("actual combined %s: %u copies/%u bytes, every copy failure and post-reader generation change rejected\n",cached?"cached":"disk",count,bytes);
}}

#endif
