#include "CurrentCopyinSample.h"
#include <map>
#include <vector>
#include <cassert>
#include <cstdio>
using namespace CurrentCopyinSample;
constexpr uint64_t output=0x10001000,base=0x7ff800000000ULL,image=base+0x10a5b0000ULL;
struct Fixture{
 std::map<uint64_t,std::vector<uint8_t>> blocks;unsigned calls=0,fail=0,pairReads=0;bool mutate=false;
 template<class T>void put(uint64_t a,T v){blocks[a]=std::vector<uint8_t>(sizeof(v));memcpy(blocks[a].data(),&v,sizeof(v));}
 Fixture(){put(output,base);auto&h=blocks[base];h.resize(248);memcpy(h.data(),"dyld_v1 x86_64h",15);
 const uint8_t uuid[]={0x42,0xec,0x28,0x90,0xbc,0x40,0x31,0x7e,0xbb,0x27,0x45,0x14,0x2b,0xff,0x7f,0x26};memcpy(h.data()+88,uuid,16);
 auto store=[&](unsigned o,uint64_t v,unsigned n){memcpy(h.data()+o,&v,n);};store(16,0x228,4);store(20,4,4);store(224,base,8);store(232,0x700000000ULL,8);store(240,0x1ae68000,8);
 const uint64_t addresses[]={140703128616960ULL,140704202358784ULL,140704259440640ULL,140705276100608ULL};const uint64_t sizes[]={622428160,57081856,14958592,169213952};const uint64_t offsets[]={0,622428160,679510016,694468608};const uint32_t max[]={5,3,3,1},initial[]={5,1,3,1};
 for(unsigned i=0;i<4;++i){auto&r=blocks[base+0x228+i*32];r.resize(32);memcpy(r.data(),addresses+i,8);memcpy(r.data()+8,sizes+i,8);memcpy(r.data()+16,offsets+i,8);memcpy(r.data()+24,max+i,4);memcpy(r.data()+28,initial+i,4);}
 blocks[image]={TargetImagePins::header,TargetImagePins::header+sizeof(TargetImagePins::header)};
 blocks[image+0x183f]={TargetImagePins::getter,TargetImagePins::getter+sizeof(TargetImagePins::getter)};
 blocks[image+0x238d1]={TargetImagePins::platform,TargetImagePins::platform+sizeof(TargetImagePins::platform)};
 blocks[image+0x38b0da98].resize(16);blocks[image+0x38e1b028].resize(2);
 }
 static int copy(void*c,uint64_t a,void*out,size_t n){auto&f=*static_cast<Fixture*>(c);if(++f.calls==f.fail)return 14;
  if(a==image+0x38b0da98&&++f.pairReads==2&&f.mutate)f.blocks[a][0]=1;
  for(auto&b:f.blocks)if(a>=b.first&&a-b.first<=b.second.size()&&n<=b.second.size()-(a-b.first)){memcpy(out,b.second.data()+(a-b.first),n);return 0;}
  return 14;
 }
 Result sample(){return inspect({this,copy},output);}
};
int main(){Fixture good;auto r=good.sample();assert(r.stage==Stage::Complete&&r.state==State::NotStarted&&!r.checked&&!r.result);unsigned reads=good.calls;
 for(unsigned fail=1;fail<=reads;++fail){Fixture f;f.fail=fail;r=f.sample();assert(r.stage!=Stage::Complete&&r.state==State::Unknown);}
 for(uint64_t bad:{uint64_t{0},UINT64_MAX,uint64_t{0x800000000000ULL},base+1}){Fixture f;f.put(output,bad);assert(f.sample().stage==Stage::Base);}
 for(unsigned offset:{10U,88U,16U,20U,224U,232U,240U}){Fixture f;f.blocks[base][offset]^=1;assert(f.sample().stage==Stage::CacheHeader);}
 {Fixture f;f.blocks[base+0x228][0]^=1;assert(f.sample().stage==Stage::CacheLayout);}
 for(auto address:{image,image+0x183f,image+0x238d1}){Fixture f;f.blocks[address][0]^=1;assert(f.sample().stage!=Stage::Complete);}
 {Fixture f;f.mutate=true;assert(f.sample().stage==Stage::Changed);}
 for(uint64_t once:{UINT64_MAX,uint64_t{1},uint64_t{0}}){Fixture f;memcpy(f.blocks[image+0x38b0da98].data()+8,&once,8);r=f.sample();assert(r.stage==Stage::Complete&&r.state==(once==UINT64_MAX?State::CompletedEmpty:once?State::Initializing:State::NotStarted));}
 {Fixture f;f.blocks[image+0x38b0da98][0]=1;r=f.sample();assert(r.stage==Stage::Complete&&r.state==State::LiveObject);}
 {Fixture f;f.blocks[image+0x38e1b028][0]=2;assert(f.sample().stage==Stage::Changed);}
 {Fixture f;Reader reader{&f,Fixture::copy};uint64_t out;assert(!reader.read(UINT64_MAX,&out,8)&&!reader.read(0x7fffffffffffULL,&out,8)&&f.calls==0);}
 printf("Current-thread reader: valid cold/warm/live states, %u injected copy errors, UUID/layout/code/range/change rejection passed\n",reads);
return 0;}
