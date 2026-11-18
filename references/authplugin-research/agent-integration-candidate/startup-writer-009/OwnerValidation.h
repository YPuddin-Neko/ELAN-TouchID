#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <mach-o/loader.h>
#include "Exact24H32.h"
namespace OwnerValidation {
using Resolve=uintptr_t(*)(void*,const char*);
using Read=bool(*)(void*,uint64_t,void*,size_t);
struct Memory{void*context;Resolve resolve;Read read;};
struct Validated{uint64_t header=0,entry=0,slotBegin=0,slotEnd=0;};
enum class Reason:uint32_t {None,API,HeaderAddress,Slide,SymbolLookup,SymbolAddress,SymbolRead,SymbolBytes,HeaderRead,HeaderLayout,CommandBounds,CommandRead,UUID,Entry,CopyinSymbol,IdentityBind,Configure,EntryLookup};
inline bool preflight(const Memory&m,uint64_t entry,Validated&out,Reason*reason=nullptr){
 out={};if(reason)*reason=Reason::None;
 auto reject=[&](Reason why){if(reason)*reason=why;return false;};
 if(!m.resolve||!m.read)return reject(Reason::API);
 auto h=m.resolve(m.context,"__mh_execute_header");if(!h||h<Exact24H32::Symbols[0].address)return reject(Reason::HeaderAddress);
 auto slide=h-Exact24H32::Symbols[0].address;if(slide&0xfffff)return reject(Reason::Slide);
 for(const auto&s:Exact24H32::Symbols){auto a=m.resolve(m.context,s.name);uint8_t bytes[16];
  if(!a)return reject(Reason::SymbolLookup);
  if(s.address>UINT64_MAX-slide||a!=s.address+slide)return reject(Reason::SymbolAddress);
  if(!m.read(m.context,a,bytes,sizeof(bytes)))return reject(Reason::SymbolRead);
  if(memcmp(bytes,s.bytes,sizeof(bytes)))return reject(Reason::SymbolBytes);
 }
 mach_header_64 mh{};if(!m.read(m.context,h,&mh,sizeof(mh)))return reject(Reason::HeaderRead);
 if(mh.magic!=MH_MAGIC_64||mh.sizeofcmds>0x100000||mh.ncmds>4096)return reject(Reason::HeaderLayout);
 size_t at=sizeof(mh),end=at+mh.sizeofcmds;bool found=false;
 if(h>UINT64_MAX-end-0xfff)return reject(Reason::CommandBounds);
 for(uint32_t i=0;i<mh.ncmds;++i){
  if(at>end||end-at<sizeof(load_command))return reject(Reason::CommandBounds);
  load_command c{};if(!m.read(m.context,h+at,&c,sizeof(c)))return reject(Reason::CommandRead);
  if(c.cmdsize<sizeof(c)||c.cmdsize>end-at)return reject(Reason::CommandBounds);
  if(c.cmd==LC_UUID){uuid_command u{};if(found||c.cmdsize!=sizeof(u)||!m.read(m.context,h+at,&u,sizeof(u))||memcmp(u.uuid,Exact24H32::KernelUUID,16))return reject(Reason::UUID);found=true;}
  at+=c.cmdsize;
 }
 if(!found||at!=end)return reject(Reason::UUID);
 if(entry!=Exact24H32::Symbols[1].address+slide)return reject(Reason::Entry);
 out={h,entry,h+end,(h+end+0xfff)&~uint64_t{0xfff}};return true;
}
inline bool readback(const Memory&m,const Validated&v,uint64_t wrapper){
 if(!m.read||!v.header||!v.entry||!wrapper||v.slotBegin<v.header||v.slotEnd<v.slotBegin||v.entry>UINT64_MAX-6)return false;
 uint8_t bytes[14];if(!m.read(m.context,v.entry,bytes,sizeof(bytes))||bytes[0]!=0xff||bytes[1]!=0x25)return false;
 int32_t d;memcpy(&d,bytes+2,4);uint64_t destination=0;
 if(!d)memcpy(&destination,bytes+6,8);
 else{uint64_t base=v.entry+6;uint64_t n=d<0?static_cast<uint64_t>(-static_cast<int64_t>(d)):static_cast<uint64_t>(d);
  if((d<0&&base<n)||(d>0&&base>UINT64_MAX-n))return false;
  uint64_t slot=d<0?base-n:base+n;
  if(slot<v.slotBegin||slot>v.slotEnd||v.slotEnd-slot<8||!m.read(m.context,slot,&destination,8))return false;
 }
 return destination==wrapper;
}
}
