#include "NativeSettingsHardwareGate.h"
#include "NativeSettingsMemoryPolicy.h"
#include <cassert>
#include <cstdio>
#include <initializer_list>
namespace {
constexpr uint64_t base=0x7ff800000000ULL, image=base+0x10a5b0000ULL, object=image+0x366f14e0;
constexpr uint64_t text=image+0x39858, platform=image+0x38e1b028, scratch=0x100000;
constexpr uint8_t uuid[]={0x42,0xec,0x28,0x90,0xbc,0x40,0x31,0x7e,0xbb,0x27,0x45,0x14,0x2b,0xff,0x7f,0x26};
enum Fault { None, WrongName, Warm, NoCow, NoListener, Allocation, Seal, PartialFlags, Disconnect, RefuseRollback };
struct RouteMemory {
    uint64_t fields[4]={1,0x7c8,text,23};
    uint8_t code[0x83]{}, flags[2]{}, name[24]{};
    bool allocated=false, readOnly=true, sealed=false;
    Fault fault;
    explicit RouteMemory(Fault f):fault(f) {
        const uint8_t type[]={0x48,0x83,0xf8,0x01,0x74,0x13}, load[]={0x4c,0x8d,0x35}, args[]={0x4c,0x89,0xf2,0x31,0xc9};
        int32_t displacement=static_cast<int32_t>(object-(image+0x69cf+0x68));
        memcpy(code+0x48,type,sizeof(type));memcpy(code+0x61,load,sizeof(load));
        memcpy(code+0x64,&displacement,4);memcpy(code+0x7e,args,sizeof(args));
        if (f==WrongName) fields[3]=12;
        if (f==Warm) flags[0]=1;
    }
    CurrentCopyinSample::Reader reader() { return {this,[](void *ctx,uint64_t addr,void *out,size_t size) {
        auto &m=*static_cast<RouteMemory *>(ctx);
        struct Span {uint64_t address; const void *data; size_t size;};
        const Span spans[]={{base+88,uuid,sizeof(uuid)},{image,TargetImagePins::header,sizeof(TargetImagePins::header)},
            {image+0x69cf,m.code,sizeof(m.code)},{object,m.fields,sizeof(m.fields)},{text,NativeSettingsEndpoint::appleName,24},
            {platform,m.flags,2},{scratch,m.name,m.allocated?sizeof(m.name):0}};
        for (const auto &span:spans) {
            if (addr<span.address || size>span.size || addr-span.address>span.size-size) continue;
            memcpy(out,static_cast<const uint8_t *>(span.data)+(addr-span.address),size);
            return 0;
        }
        return 14;
    }}; }
    bool permitted() const {return fault!=NoListener && !(fault==Disconnect && fields[2]==scratch);}
    bool cowSlot(uint64_t a) const {return a==object+16 && fault!=NoCow && readOnly;}
    bool readOnlySlot(uint64_t a) const {return a==object+16 && readOnly;}
    bool writableData(uint64_t a) const {return a==platform;}
    bool allocate(uint64_t &address) {if(fault==Allocation)return false;address=scratch;allocated=true;return true;}
    bool release(uint64_t address) {assert(address==scratch && fields[2]!=scratch);allocated=false;return true;}
    bool seal(uint64_t address) {assert(address==scratch);return sealed=fault!=Seal;}
    bool makeCopyWritable(uint64_t page) {assert(page==(object&~4095ULL));readOnly=false;return true;}
    bool protectSlot(uint64_t page) {assert(page==(object&~4095ULL));readOnly=true;return true;}
    bool storePointer(uint64_t dest,uint64_t val) {
        assert(dest==object+16 && !readOnly);
        if(fault==RefuseRollback && val==text)return false;
        fields[2]=val;return true;
    }
    bool write(uint64_t addr,const uint8_t *src,size_t n) {
        if(addr==scratch){assert(allocated && !sealed && n==24);memcpy(name,src,n);return true;}
        assert(addr==platform && n==2);
        flags[0]=src[0];
        if ((fault==PartialFlags || fault==RefuseRollback) && src[0]) return false;
        flags[1]=src[1];return true;
    }
};
}
namespace {
constexpr uint64_t settingsImage=0x100000000ULL;
struct Memory : RouteMemory {
 uint64_t gate[3],accessory[3];
 bool selectorReadOnly=true, corruptSelector=false, privateSlot=true,deny=false,failWrite=false,failRestore=false,unreadable=false,lateFailure=false;
 unsigned writes=0, slotReads=0, failSlotRead=0;
 explicit Memory(Fault f=None,bool chained=false):RouteMemory(f){
  uint64_t p=chained?NativeSettingsHardwareGate::chained:settingsImage;
  gate[0]=p+0x6154e;gate[1]=p+0x62eb7;gate[2]=p+0xe04c;
  accessory[0]=p+0x6152f;accessory[1]=gate[1];accessory[2]=p+0x7232;
 }
 CurrentCopyinSample::Reader reader(){return {this,[](void *ctx,uint64_t addr,void *out,size_t n){
  auto&m=*static_cast<Memory*>(ctx);
  const uint64_t starts[]={settingsImage+NativeSettingsHardwareGate::destination-16,settingsImage+NativeSettingsHardwareGate::source-16};
  const uint64_t*data[]={m.gate,m.accessory};
  for(unsigned i=0;i<2;++i)if(addr>=starts[i]&&n<=24&&addr-starts[i]<=24-n){
   if(m.unreadable)return 14;
   if(addr==settingsImage+NativeSettingsHardwareGate::destination && n==8 && ++m.slotReads==m.failSlotRead)return 14;
   memcpy(out,reinterpret_cast<const uint8_t*>(data[i])+(addr-starts[i]),n);return 0;
  }
  const char gateName[]="isTouchIDSupportedOnHardware",sourceName[]="isSupported";
  const uint64_t selectorAddresses[]={settingsImage+0x6154e,settingsImage+0x6152f,base+0x200000,base+0x200080};
  for(unsigned i=0;i<4;++i)if(addr==selectorAddresses[i]&&n==(i%2?sizeof(sourceName):sizeof(gateName))){
   memcpy(out,i%2?sourceName:gateName,n);if(m.corruptSelector)static_cast<char*>(out)[n-1]='x';return 0;
  }
  auto r=m.RouteMemory::reader();return r.copy(r.context,addr,out,n);
 }};}
 bool permitted()const{return !deny&&RouteMemory::permitted();}
 bool readOnlySelector(uint64_t,size_t)const{return selectorReadOnly;}
 bool privateMethodSlot(uint64_t a)const{return privateSlot&&a==settingsImage+NativeSettingsHardwareGate::destination;}
 bool storePointer(uint64_t a,uint64_t v){
  if(a!=settingsImage+NativeSettingsHardwareGate::destination)return RouteMemory::storePointer(a,v);
  ++writes;if((failWrite&&v==accessory[2])||(failRestore&&v!=accessory[2]))return false;
  gate[2]=v;return !(lateFailure&&v==accessory[2]);
 }
};
}
int main(){
 using R=NativeSettingsRoute::Result;
 {Memory m(None,true);NativeSettingsHardwareGate::Stage stage{};assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true,&stage)==R::Skipped);assert(stage==NativeSettingsHardwareGate::Stage::Relocation);}
 {Memory m;NativeSettingsHardwareGate::Stage stage{};assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true,&stage)==R::Routed);assert(stage==NativeSettingsHardwareGate::Stage::Complete);}
 {Memory m;m.privateSlot=false;NativeSettingsHardwareGate::Stage stage{};assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true,&stage)==R::Skipped);assert(stage==NativeSettingsHardwareGate::Stage::PrivateSlot);}
 {Memory m;m.gate[0]=base+0x200000;m.accessory[0]=base+0x200080;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Routed);}
 {Memory m;m.selectorReadOnly=false;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Skipped);assert(!m.writes);}
 {Memory m;m.corruptSelector=true;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Skipped);assert(!m.writes);}
 {Memory m;m.gate[0]=0x400000000ULL;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Skipped);assert(!m.writes);}
 for(uint32_t protection=0;protection<16;++protection)
  for(uint32_t maximum=0;maximum<16;++maximum)
   for(bool cow:{false,true})
    assert(NativeSettingsMemoryPolicy::writableData(protection,maximum,cow)==
           (cow&&protection==3&&(maximum==3||maximum==7)));
 for(bool chained:{false,true}){Memory m(None,chained);
  assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Routed);
  assert(m.gate[2]==m.accessory[2]&&m.flags[0]==1&&m.flags[1]==1&&m.readOnly);
 }
 {Memory m(None,true);assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Skipped);assert(!m.writes&&!m.allocated);}
 {Memory m;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base,true)==R::Routed);}
 for(unsigned i=0;i<6;++i){Memory m;(i<3?m.gate[i]:m.accessory[i-3])^=1;
  assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Skipped);assert(!m.writes&&!m.allocated);
 }
 for(auto f:{WrongName,Warm,NoCow,NoListener,Allocation,Seal,PartialFlags,Disconnect,RefuseRollback}){
  Memory m(f);auto old=m.gate[2];auto r=NativeSettingsHardwareGate::apply(m,settingsImage,base);
  assert(r!=R::Routed&&m.gate[2]==old&&m.readOnly);if(f==RefuseRollback)assert(r==R::Incomplete);
 }
 for(unsigned i=0;i<4;++i){Memory m;m.privateSlot=i!=0;m.deny=i==1;m.unreadable=i==2;
  assert(NativeSettingsHardwareGate::apply(m,i==3?settingsImage+1:settingsImage,base)==R::Skipped);
  assert(!m.writes&&!m.allocated);
 }
 {Memory m;m.failWrite=true;auto old=m.gate[2];assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Skipped);assert(m.gate[2]==old&&!m.allocated);}
 {Memory m;m.lateFailure=true;auto old=m.gate[2];assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Restored);assert(m.gate[2]==old&&!m.allocated);}
 {Memory m(WrongName);m.failRestore=true;assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Incomplete);assert(m.gate[2]==m.accessory[2]);}
 {Memory m;m.failSlotRead=1;auto old=m.gate[2];assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Restored);assert(m.gate[2]==old&&!m.allocated);}
 {Memory m(WrongName);m.failSlotRead=2;auto old=m.gate[2];assert(NativeSettingsHardwareGate::apply(m,settingsImage,base)==R::Incomplete);assert(m.gate[2]==old&&!m.allocated);}
 for(uint64_t bad:{uint64_t(0),uint64_t(4095),uint64_t(0x7ffffffff000ULL),UINT64_MAX}){Memory m;assert(NativeSettingsHardwareGate::apply(m,bad,base)==R::Skipped);assert(!m.writes&&!m.allocated);}
 puts("Settings hardware gate metadata, rejection, routing and rollback passed");
}
