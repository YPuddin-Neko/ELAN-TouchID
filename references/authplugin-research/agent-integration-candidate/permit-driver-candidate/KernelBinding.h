#pragma once
#include "RemoteIdentity.h"
#include "KernelPins.h"
namespace ElanPermitKernelBinding {
using Resolve=uintptr_t(*)(void*,const char*);
using Read=size_t(*)(void*,uintptr_t,void*,size_t);
struct Bound {
 ElanPermitIdentity::API current{};ElanPermitRemote::API remote{};
 int(*random)(void*,size_t)=nullptr;uint64_t(*continuousTime)()=nullptr;void(*toNanoseconds)(uint64_t,uint64_t*)=nullptr;bool ready=false;
};
inline bool bind(Resolve resolve,Read read,void*context,uintptr_t slide,const uint8_t uuid[16],Bound&out){
 out={};if(!resolve||!read||!uuid||memcmp(uuid,PermitKernelPins::kernelUUID,16))return false;
 uintptr_t addresses[24]{};
 for(unsigned i=0;i<24;i++){
  const auto&p=PermitKernelPins::pins[i];if(p.address>UINTPTR_MAX-slide)return false;
  uintptr_t address=resolve(context,p.name);if(address!=p.address+slide||p.length>UINTPTR_MAX-address)return false;
  uint8_t bytes[64];for(size_t offset=0;offset<p.length;offset+=sizeof(bytes)){
   size_t length=p.length-offset;if(length>sizeof(bytes))length=sizeof(bytes);
   if(read(context,address+offset,bytes,length)!=length||memcmp(bytes,p.bytes+offset,length))return false;
  }addresses[i]=address;
 }
 Bound b{};
#define ELAN_PERMIT_SET(field,index) field=reinterpret_cast<decltype(field)>(addresses[index])
 ELAN_PERMIT_SET(b.current.binary.self,0);ELAN_PERMIT_SET(b.current.binary.release,1);ELAN_PERMIT_SET(b.current.binary.flags,2);
 ELAN_PERMIT_SET(b.current.binary.task,3);ELAN_PERMIT_SET(b.current.binary.currentTask,4);ELAN_PERMIT_SET(b.current.binary.unique,5);
 ELAN_PERMIT_SET(b.current.binary.uuid,6);ELAN_PERMIT_SET(b.current.binary.vnode,7);ELAN_PERMIT_SET(b.current.binary.putVnode,8);
 ELAN_PERMIT_SET(b.current.binary.path,9);ELAN_PERMIT_SET(b.current.binary.offset,10);ELAN_PERMIT_SET(b.current.binary.hash,11);
 ELAN_PERMIT_SET(b.current.binary.credential,12);ELAN_PERMIT_SET(b.current.binary.uid,13);ELAN_PERMIT_SET(b.current.binary.unrefCredential,14);ELAN_PERMIT_SET(b.current.taskInfo,18);
 ELAN_PERMIT_SET(b.remote.find,15);ELAN_PERMIT_SET(b.remote.releaseProc,1);ELAN_PERMIT_SET(b.remote.task,3);ELAN_PERMIT_SET(b.remote.unique,5);ELAN_PERMIT_SET(b.remote.version,16);
 ELAN_PERMIT_SET(b.remote.flags,17);ELAN_PERMIT_SET(b.remote.uuid,6);ELAN_PERMIT_SET(b.remote.vnode,7);ELAN_PERMIT_SET(b.remote.putVnode,8);ELAN_PERMIT_SET(b.remote.path,9);ELAN_PERMIT_SET(b.remote.offset,10);ELAN_PERMIT_SET(b.remote.hash,11);ELAN_PERMIT_SET(b.remote.taskInfo,18);ELAN_PERMIT_SET(b.remote.retainTask,19);ELAN_PERMIT_SET(b.remote.releaseTask,20);ELAN_PERMIT_SET(b.random,21);ELAN_PERMIT_SET(b.continuousTime,22);ELAN_PERMIT_SET(b.toNanoseconds,23);
#undef ELAN_PERMIT_SET
 b.ready=true;out=b;return true;
}
}
