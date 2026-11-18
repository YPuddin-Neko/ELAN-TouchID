#pragma once
#include "KernelRuntime.h"
#include <mach-o/loader.h>
namespace RetirementRuntime {
inline bool inspectKernelHeader(RetirementPins::Resolve resolve,void*context,
 RetirementPins::Read read,void*readContext,uint64_t&slide,uint8_t(&uuid)[16]) {
 slide=0;memset(uuid,0,sizeof(uuid));
 if(!resolve||!read)return false;
 constexpr uint64_t base=0xffffff80002e8000ULL;
 auto address=resolve(context,"__mh_execute_header");
 if(address<base||((address-base)&0xfffff))return false;
 mach_header_64 h{};
 if(!read(readContext,address,&h,sizeof(h))||h.magic!=MH_MAGIC_64||
    h.cputype!=CPU_TYPE_X86_64||h.filetype!=MH_EXECUTE||
    !h.ncmds||h.ncmds>4096||h.sizeofcmds>0x100000)return false;
 size_t at=sizeof(h),end=at+h.sizeofcmds;
 if(address>UINTPTR_MAX-end)return false;
 bool found=false;
 for(uint32_t i=0;i<h.ncmds;++i){
  load_command c{};
  if(at>end||end-at<sizeof(c)||!read(readContext,address+at,&c,sizeof(c))||
     c.cmdsize<sizeof(c)||c.cmdsize>end-at)return false;
  if(c.cmd==LC_UUID){uuid_command u{};
   if(found||c.cmdsize!=sizeof(u)||!read(readContext,address+at,&u,sizeof(u)))return false;
   memcpy(uuid,u.uuid,16);found=true;
  }
  at+=c.cmdsize;
 }
 if(!found||at!=end)return false;
 slide=address-base;return true;
}
}
