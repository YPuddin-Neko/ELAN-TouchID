#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "SettingsPins.h"
namespace SettingsSample {
using Copy=int(*)(void*,uint64_t,void*,size_t);
enum class Stage {Argument,Header,Commands,UUID,Getter,State,Changed,Complete};
enum class State {Unknown,Cold,CompletedEmpty,Live,Initializing};
struct Result {Stage stage=Stage::Argument;State state=State::Unknown;unsigned reads=0,bytes=0;};
struct Reader {
 Copy copy;void*context;Result&result;
 bool read(uint64_t address,void*out,size_t size){
  if(!copy||!out||!size||size>32||address<4096||address>0x7fffffffffffULL||size-1>0x7fffffffffffULL-address||result.reads>=99||result.bytes+size>890)return false;
  ++result.reads;result.bytes+=unsigned(size);return copy(context,address,out,size)==0;
 }
 bool equal(uint64_t address,const void*pin,size_t size){uint8_t bytes[32];return read(address,bytes,size)&&!memcmp(bytes,pin,size);}
};
// The caller supplies an independently identified main executable base, not a cache slide.
inline Result inspect(Copy copy,void*context,uint64_t image){
 Result out;Reader r{copy,context,out};
 if(image<4096||(image&4095)||image>0x7fffffffffffULL-0x7b868)return out;
 out.stage=Stage::Header;if(!r.equal(image,SettingsPins::header,32))return out;
 out.stage=Stage::Commands;
 for(const auto&command:SettingsPins::commands)if(!r.equal(image+command[0],command+1,8))return out;
 out.stage=Stage::UUID;if(!r.equal(image+SettingsPins::uuidOffset,SettingsPins::uuid,16))return out;
 out.stage=Stage::Getter;if(!r.equal(image+0x6fb1,SettingsPins::getter,17))return out;
 out.stage=Stage::State;uint64_t pair[2],again[2];if(!r.read(image+0x7b858,pair,16))return out;
 out.stage=Stage::Changed;
 if(!r.read(image+0x7b858,again,16)||memcmp(pair,again,16)||!r.equal(image,SettingsPins::header,32)||
    !r.equal(image+SettingsPins::uuidOffset,SettingsPins::uuid,16)||!r.equal(image+0x6fb1,SettingsPins::getter,17))return out;
 out.stage=Stage::Complete;
 out.state=pair[1]?State::Live:!pair[0]?State::Cold:pair[0]==UINT64_MAX?State::CompletedEmpty:State::Initializing;
 return out;
}
}
