#pragma once
#include <stdint.h>
namespace NativeSettingsStartupDiagnostics {
enum class Event:uint8_t {None,AuditRejected,APIMissing,AdmissionRejected,RouteReturned};
struct State {
 uint64_t last=uint64_t{1}<<56;
 uint32_t attempts=0,routed=0;
 static void increment(uint32_t&value){
  uint32_t old=__atomic_load_n(&value,__ATOMIC_RELAXED);
  while(old!=UINT32_MAX&&!__atomic_compare_exchange_n(&value,&old,old+1,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED)){}
 }
 void record(Event event,uint8_t admission=0,uint8_t caller=0,uint8_t settings=0,uint8_t outer=0,
             uint8_t route=255,bool cold=false,bool accepted=false,bool late=false,uint8_t gate=0){
  uint64_t word=(uint64_t{1}<<56)|uint64_t(event)|(uint64_t(admission)<<8)|(uint64_t(caller)<<16)|
   (uint64_t(settings)<<24)|(uint64_t(outer)<<32)|(uint64_t(route)<<40)|
   (uint64_t(cold)<<48)|(uint64_t(accepted)<<49)|(uint64_t(late)<<50)|(uint64_t(gate&31)<<51);
  __atomic_store_n(&last,word,__ATOMIC_RELEASE);increment(attempts);
  if(event==Event::RouteReturned&&route==1)increment(routed);
 }
 uint64_t snapshot()const{return __atomic_load_n(&last,__ATOMIC_ACQUIRE);}
 uint32_t count()const{return __atomic_load_n(&attempts,__ATOMIC_ACQUIRE);}
 uint32_t successes()const{return __atomic_load_n(&routed,__ATOMIC_ACQUIRE);}
};
}
