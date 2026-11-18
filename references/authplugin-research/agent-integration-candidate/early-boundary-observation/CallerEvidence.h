#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
namespace CallerEvidence {
using Copy=int(*)(void*,uint64_t,void*,size_t);
struct Registers {uint64_t rip,rsp,rbp;};
enum class Stage:uint32_t {Registers,Header,UUID,Code,Stack,Matched};
enum class Reason:uint8_t {None,RipRange,FrameRange,OutputMismatch,StackRange,BaseAlignment,HeaderRead,HeaderMismatch};
enum class Profile:uint8_t {Unknown,Disk,Cached};
struct Result {Stage stage=Stage::Registers;uint32_t reads=0,bytes=0;Reason reason=Reason::None;uint8_t headerDifference=0;Profile profile=Profile::Unknown;uint64_t imageBase=0;bool lateBoundary=false;};
// Fixed work budget, not an elapsed-time guarantee for a faulting copyin.
struct Reader {
 void*context;Copy copy;Result&out;
 bool read(uint64_t a,void*b,size_t n) {
  if(!copy||!n||n>4096||a<4096||a>0x7fffffffffffULL||n-1>0x7fffffffffffULL-a||out.reads>=30||out.bytes+n>286)return false;
  ++out.reads;out.bytes+=static_cast<uint32_t>(n);return copy(context,a,b,n)==0;
 }
};
inline Result inspect(Copy copy,void*context,Registers s,uint64_t output) {
 Result out{};Reader r{context,copy,out};
 if(s.rip<0x6491e){out.reason=Reason::RipRange;return out;}
 if(s.rbp<0x28){out.reason=Reason::FrameRange;return out;}
 const bool endMwl=output==UINT64_MAX;
 if(!endMwl&&output!=s.rbp-0x28){out.reason=Reason::OutputMismatch;return out;}
 if(s.rsp>s.rbp||s.rbp-s.rsp>4096){out.reason=Reason::StackRange;return out;}
 const uint64_t base=s.rip-0x6391e;if(base&4095){out.reason=Reason::BaseAlignment;return out;}
 out.stage=Stage::Header;uint8_t h[32];if(!r.read(base,h,sizeof(h))){out.reason=Reason::HeaderRead;return out;}
 const uint8_t headerPin[]={0xcf,0xfa,0xed,0xfe,0x7,0x0,0x0,0x1,0x3,0x0,0x0,0x0,0x7,0x0,0x0,0x0,0x13,0x0,0x0,0x0,0xe8,0x8,0x0,0x0,0x85,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
 for(unsigned i=0;i<8;++i)if(memcmp(h+i*4,headerPin+i*4,4))out.headerDifference|=uint8_t(1U<<i);
 const uint8_t cachedHeaderPin[]={0xcf,0xfa,0xed,0xfe,0x7,0x0,0x0,0x1,0x3,0x0,0x0,0x0,0x7,0x0,0x0,0x0,0x10,0x0,0x0,0x0,0xb8,0x8,0x0,0x0,0x85,0x0,0x0,0x80,0x0,0x0,0x0,0x0};
 if(!out.headerDifference)out.profile=Profile::Disk;
 else if(!memcmp(h,cachedHeaderPin,sizeof(h))){out.profile=Profile::Cached;out.headerDifference=0;}
 else{out.reason=Reason::HeaderMismatch;return out;}
 out.stage=Stage::UUID;
 const uint32_t commands[][3]={{0x20,0x19,0x228},{0x248,0x19,0x98},{0x2e0,0x19,0x188},{0x468,0x19,0x1d8},{0x640,0x19,0x98},{0x6d8,0x19,0x48},{0x720,0x80000034,0x10},{0x730,0x80000033,0x10},{0x740,0x2,0x18},{0x758,0xb,0x50},{0x7a8,0xf,0x20},{0x7c8,0x1b,0x18},{0x7e0,0x32,0x20},{0x800,0x2a,0x10},{0x810,0x5,0xb8},{0x8c8,0x1e,0x10},{0x8d8,0x26,0x10},{0x8e8,0x29,0x10},{0x8f8,0x1d,0x10}};
 const uint32_t cachedCommands[][3]={{0x20,0x19,0x228},{0x248,0x19,0x98},{0x2e0,0x19,0x188},{0x468,0x19,0x1d8},{0x640,0x19,0x98},{0x6d8,0x19,0x48},{0x720,0x80000033,0x10},{0x730,0x2,0x18},{0x748,0xb,0x50},{0x798,0xf,0x20},{0x7b8,0x1b,0x18},{0x7d0,0x32,0x20},{0x7f0,0x2a,0x10},{0x800,0x5,0xb8},{0x8b8,0x26,0x10},{0x8c8,0x29,0x10}};
 const bool cached=out.profile==Profile::Cached;
 const auto*selected=cached?cachedCommands:commands;
 const unsigned commandCount=cached?16:19;
 for(unsigned i=0;i<commandCount;++i){const auto&c=selected[i];uint32_t pair[2];if(!r.read(base+c[0],pair,8)||pair[0]!=c[1]||pair[1]!=c[2])return out;}
 uint8_t uuid[16];const uint8_t expected[]={0x22,0xe1,0x53,0x25,0x4d,0xf0,0x3b,0xa4,0x88,0x2c,0x31,0x4a,0x2a,0x7a,0x32,0x39};
 if(!r.read(base+(cached?0x7c0:0x7d0),uuid,16)||memcmp(uuid,expected,16))return out;
 out.stage=Stage::Code;
 const uint64_t offsets[]={0x63914,0x2bbab,0x2adc1,0x27dce,0xaff0};
 const uint8_t pins[][10]={{0xb8,0x26,1,0,2,0x49,0x89,0xca,0x0f,5},{0xe8,0x64,0x7d,3,0},{0xe8,0xcc,0x0d,0,0},{0xe8,0xb8,0x2f,0,0},{0xe8,0x81,0xcd,1,0}};
 const uint64_t endMwlOffsets[]={0x63914,0x28022,0x35821,0x762e,0x681a};
 const uint8_t endMwlPins[][10]={{0xb8,0x26,1,0,2,0x49,0x89,0xca,0x0f,5},{0xe9,0xed,0xb8,3,0},{0xe8,0xf0,0x27,0xff,0xff},{0xff,0x90,0x30,3,0},{0xe8,0x12,0,0,0}};
 const auto*codeOffsets=endMwl?endMwlOffsets:offsets;
 const auto*codePins=endMwl?endMwlPins:pins;
 for(unsigned i=0;i<5;++i){uint8_t b[10];size_t n=i?5:10;if(!r.read(base+codeOffsets[i],b,n)||memcmp(b,codePins[i],n))return out;}
 out.stage=Stage::Stack;uint64_t ret=0;if(!r.read(s.rsp,&ret,8)||ret!=base+(endMwl?0x35826:0x2bbb0))return out;
 const uint64_t returns[]={0x2adc6,0x27dd3,0xaff5};
 const uint64_t endMwlReturns[]={0x7634,0x681f,0x64da};
 const auto*expectedReturns=endMwl?endMwlReturns:returns;
 uint64_t frame=s.rbp;
 for(unsigned i=0;i<3;++i){uint64_t pair[2];// Intel dyld prepare() keeps a large local frame around runAllInitializersForMain().
  // The exact 24H32 call sites still determine which three return addresses are accepted.
  const uint64_t spanLimit=endMwl && i>0 ? 40*1024 : 8192;
  if(frame&7||frame<s.rsp||frame-s.rsp>spanLimit||!r.read(frame,pair,16)||pair[1]!=base+expectedReturns[i])return out;
  const uint64_t stepLimit=endMwl && i==0 ? 32*1024 : 4096;
  if(i<2&&(pair[0]<=frame||pair[0]-frame>stepLimit))return out;
  frame=pair[0];
 }
 out.stage=Stage::Matched;out.imageBase=base;out.lateBoundary=endMwl;return out;
}
}
