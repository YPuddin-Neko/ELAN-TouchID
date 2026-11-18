#include "../agent-integration-candidate/startup-fresh-writer/runtime/Admission.h"
#define ELAN_ACTUAL_READERS_FIXTURE_ONLY 1
#include "../agent-integration-candidate/startup-joint-observation/test_actual_readers.cpp"
#undef ELAN_ACTUAL_READERS_FIXTURE_ONLY
constexpr uint64_t CallerFixture::Fixture::base;
constexpr uint64_t CallerFixture::Fixture::sp;
constexpr uint64_t SettingsFixture::Fixture::base;
struct LateFixture:Fixture {
 bool nonMain=false;
 LateFixture():Fixture(true){
  memory.clear();CallerFixture::Fixture caller;caller.cached();caller.endMwl();
  const uint64_t delta=OuterFixture::base+NativeLateCacheBase::dyldOffset-CallerFixture::Fixture::base;
  regs=caller.regs;regs.rip+=delta;output=UINT64_MAX;
  for(auto entry:caller.mem){auto address=entry.first;auto data=entry.second;
   if(address>=CallerFixture::Fixture::base&&address<CallerFixture::Fixture::base+0x100000)address+=delta;
   if(entry.first>=CallerFixture::Fixture::sp)for(size_t off=0;off+8<=data.size();off+=8){uint64_t value;memcpy(&value,data.data()+off,8);if(value>=CallerFixture::Fixture::base&&value<CallerFixture::Fixture::base+0x100000){value+=delta;memcpy(data.data()+off,&value,8);}}
   memory[address]=data;
  }
  SettingsFixture::Fixture settings;memory[SettingsFixture::Fixture::base]=settings.bytes;
  OuterFixture::Fixture outer;for(auto entry:outer.blocks)if(entry.first!=OuterFixture::output)memory[entry.first]=entry.second;
 }
};
StartupAdmission::Result runLate(LateFixture&f,StartupAdmission::Receipt&receipt){
 active=&f;StartupAdmission::API api{{&f,current,procTask,processUnique,pidVersion,taskUnique},&f,currentThread,
 [](void*ctx,void*)->uint16_t{return static_cast<LateFixture*>(ctx)->nonMain?0:1;},
 {true},readKernel,nullptr,Fixture::copy,&f,capture,SettingsSample::inspect,leaf,CurrentCopyinSample::inspect};
 return StartupAdmission::inspect(api,&proc,task,f.output,receipt);
}
int main(){
 LateFixture f;StartupAdmission::Receipt receipt{};auto result=runLate(f,receipt);
 assert(receipt.accepted&&result.jointlyCold&&receipt.cacheBase==OuterFixture::base&&receipt.mainBase==SettingsFixture::Fixture::base);
 assert(result.callerResult.caller.lateBoundary&&result.callerResult.caller.imageBase==OuterFixture::base+NativeLateCacheBase::dyldOffset);
 unsigned copies=f.copies;assert(copies<=179&&f.bytes<=6618);
 for(unsigned fail=1;fail<=copies;++fail){LateFixture bad;bad.fail=fail;runLate(bad,receipt);assert(!receipt.accepted);}
 {LateFixture bad;bad.nonMain=true;runLate(bad,receipt);assert(!receipt.accepted&&!bad.copies);}
 {LateFixture bad;bad.mutateGeneration=true;runLate(bad,receipt);assert(!receipt.accepted);}
 {LateFixture bad;bad.memory[SettingsFixture::Fixture::base][0x7b858]=1;runLate(bad,receipt);assert(!receipt.accepted);}
 {LateFixture bad;bad.memory[OuterFixture::image+0x38e1b028][0]=1;runLate(bad,receipt);assert(!receipt.accepted);}
 {LateFixture bad;bad.memory[OuterFixture::base][88]^=1;runLate(bad,receipt);assert(!receipt.accepted);}
 {LateFixture bad;bad.regs.rip+=4096;runLate(bad,receipt);assert(!receipt.accepted);}
 printf("Late admission: %u actual reader copies, all read faults, cold state, identity and main-thread rejection passed\n",copies);
}
