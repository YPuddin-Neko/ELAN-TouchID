#pragma once
#include <Headers/kern_patcher.hpp>
#include "KernelBootstrap.h"
namespace RetirementRuntime {
inline bool configureFromPatcher(KernelPatcher&patcher) {
 if(configured())return true;
 auto resolve=[](void*c,const char*name)->uintptr_t{
  auto&p=*static_cast<KernelPatcher*>(c);p.clearError();
  auto address=p.solveSymbol(KernelPatcher::KernelID,name);
  return p.getError()==KernelPatcher::Error::NoError?address:0;
 };
 auto read=[](void*,uintptr_t address,void*out,size_t size)->bool{
  memcpy(out,reinterpret_cast<const void*>(address),size);return true;
 };
 uint64_t slide=0;uint8_t uuid[16]{};
 return inspectKernelHeader(resolve,&patcher,read,nullptr,slide,uuid)&&
        configure(resolve,&patcher,slide,uuid);
}
}
