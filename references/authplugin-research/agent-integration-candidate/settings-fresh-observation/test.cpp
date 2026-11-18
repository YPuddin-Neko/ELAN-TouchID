#include "SettingsSample.h"
#include <vector>
#include <assert.h>
#include <stdio.h>
using namespace SettingsSample;
struct Fixture {
 static constexpr uint64_t base=0x100000000ULL;
 std::vector<uint8_t> bytes=std::vector<uint8_t>(0x7b868);unsigned calls=0,fail=0;bool change=false;
 Fixture(){memcpy(bytes.data(),SettingsPins::header,32);for(const auto&c:SettingsPins::commands)memcpy(bytes.data()+c[0],c+1,8);memcpy(bytes.data()+SettingsPins::uuidOffset,SettingsPins::uuid,16);memcpy(bytes.data()+0x6fb1,SettingsPins::getter,17);}
 static int copy(void*context,uint64_t address,void*out,size_t size){auto&f=*static_cast<Fixture*>(context);++f.calls;if(f.calls==f.fail)return 1;if(address<base||address-base>f.bytes.size()||size>f.bytes.size()-(address-base))return 1;memcpy(out,f.bytes.data()+address-base,size);if(f.change&&address==base+0x7b858)f.bytes[0x7b858]=1;return 0;}
 Result run(){return inspect(copy,this,base);}
 void state(uint64_t once,uint64_t object){memcpy(bytes.data()+0x7b858,&once,8);memcpy(bytes.data()+0x7b860,&object,8);}
};
int main(){
 Fixture good;auto result=good.run();assert(result.stage==Stage::Complete&&result.state==State::Cold);assert(result.reads==99&&result.bytes==890); // exact finite callback budget
 for(unsigned i=1;i<=result.reads;++i){Fixture f;f.fail=i;assert(f.run().stage!=Stage::Complete);}
 for(auto offset:{size_t(0),size_t(SettingsPins::uuidOffset),size_t(0x6fb1),size_t(0x6fb1+3),size_t(0x6fb1+13)}){Fixture f;f.bytes[offset]^=1;assert(f.run().stage!=Stage::Complete);}
 for(const auto&c:SettingsPins::commands){Fixture f;f.bytes[c[0]]^=1;assert(f.run().stage!=Stage::Complete);}
 Fixture completed;completed.state(UINT64_MAX,0);assert(completed.run().state==State::CompletedEmpty);
 Fixture live;live.state(0,1);assert(live.run().state==State::Live);
 Fixture initializing;initializing.state(1,0);assert(initializing.run().state==State::Initializing);
 Fixture changed;changed.change=true;assert(changed.run().stage==Stage::Changed);
 Fixture invalid;assert(inspect(Fixture::copy,&invalid,Fixture::base+1).stage==Stage::Argument&&invalid.calls==0);
 assert(inspect(nullptr,nullptr,Fixture::base).stage==Stage::Header);
 printf("settings read-only bounded sampler passed: %u reads, %u bytes\n",result.reads,result.bytes);
return 0;}
