#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
namespace MainImageBase {
using Read=bool(*)(void*,uint64_t,void*,size_t);
struct Layout {bool verified=false;};
inline Layout verify(Read read,void*context,uint64_t setter,uint64_t slide,const uint8_t*uuid){
 constexpr uint64_t address=0xffffff8000418fb0ULL;
 const uint8_t expectedUUID[]={0xb7,0xb3,0xe8,0xad,0x9c,0xa6,0x38,0x2c,0xbd,0x56,0x8d,0x52,0x13,0x93,0x42,0xa4};
 const uint8_t expected[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x89,0xf3,0x49,0x89,0xfe,0xe8,0x3e,0x69,0x11,0,0x49,0x89,0x9e,0x18,0x06,0,0,0x4c,0x89,0xf7,0x5b,0x41,0x5e,0x5d,0xe9,0x7b,0x6c,0x11,0};
 uint8_t actual[sizeof(expected)];
 if(!read||!uuid||(slide&0xfffff)||address>UINT64_MAX-slide||setter!=address+slide||memcmp(uuid,expectedUUID,16))return {};
 return {read(context,setter,actual,sizeof(actual))&&!memcmp(actual,expected,sizeof(actual))};
}
enum class Outcome:uint32_t {Unverified,InvalidTask,ReadFailed,Changed,InvalidBase,Observed};
struct Result {Outcome outcome=Outcome::Unverified;uint64_t base=0;};
// Caller supplies a retained exact current task and must surround this with
// generation/identity validation. No task ownership is acquired or released here.
inline Result inspect(Layout layout,Read read,void*context,uint64_t retainedTask){
 if(!layout.verified||!read)return {};
 if(retainedTask<0xffff800000000000ULL||retainedTask>UINT64_MAX-0x61f||(retainedTask&7))return {Outcome::InvalidTask,0};
 uint64_t a=0,b=0;if(!read(context,retainedTask+0x618,&a,8)||!read(context,retainedTask+0x618,&b,8))return {Outcome::ReadFailed,0};
 if(a!=b)return {Outcome::Changed,0};
 if(a<4096||a>0x7fffffffffffULL||(a&4095))return {Outcome::InvalidBase,0};
 return {Outcome::Observed,a};
}
}
