#include "NativeSettingsRoute.h"
#include <cassert>
#include <cstdio>
#include <initializer_list>

namespace {
constexpr uint64_t base=0x7ff800000000ULL, image=base+0x10a5b0000ULL, object=image+0x366f14e0;
constexpr uint64_t text=image+0x39858, platform=image+0x38e1b028, scratch=0x100000;
constexpr uint8_t uuid[]={0x42,0xec,0x28,0x90,0xbc,0x40,0x31,0x7e,0xbb,0x27,0x45,0x14,0x2b,0xff,0x7f,0x26};
enum Fault { None, WrongName, Warm, NoCow, NoListener, Allocation, Seal, PartialFlags, Disconnect, RefuseRollback };
struct Memory {
    uint64_t fields[4]={1,0x7c8,text,23};
    uint8_t code[0x83]{}, flags[2]{}, name[24]{};
    bool allocated=false, readOnly=true, sealed=false;
    Fault fault;
    explicit Memory(Fault f):fault(f) {
        const uint8_t type[]={0x48,0x83,0xf8,0x01,0x74,0x13}, load[]={0x4c,0x8d,0x35}, args[]={0x4c,0x89,0xf2,0x31,0xc9};
        int32_t displacement=static_cast<int32_t>(object-(image+0x69cf+0x68));
        memcpy(code+0x48,type,sizeof(type));memcpy(code+0x61,load,sizeof(load));
        memcpy(code+0x64,&displacement,4);memcpy(code+0x7e,args,sizeof(args));
        if (f==WrongName) fields[3]=12;
        if (f==Warm) flags[0]=1;
    }
    CurrentCopyinSample::Reader reader() { return {this,[](void *ctx,uint64_t addr,void *out,size_t size) {
        auto &m=*static_cast<Memory *>(ctx);
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
int main() {
    using R=NativeSettingsRoute::Result;
    for (auto fault:{None,WrongName,Warm,NoCow,NoListener,Allocation,Seal,PartialFlags,Disconnect,RefuseRollback}) {
        Memory m(fault);
        auto result=NativeSettingsRoute::apply(m,base);
        assert(m.readOnly);
        if (fault==None) {
            assert(result==R::Routed && m.allocated && m.sealed && m.fields[2]==scratch && m.flags[0]==1 && m.flags[1]==1);
        } else if (fault==RefuseRollback) {
            assert(result==R::Incomplete && m.allocated && m.sealed && m.fields[2]==scratch && !m.flags[0] && !m.flags[1]);
        } else {
            assert(result==(fault==Seal || fault==PartialFlags || fault==Disconnect ? R::Restored : R::Skipped));
            assert(!m.allocated && m.fields[2]==text && m.flags[0]==(fault==Warm) && m.flags[1]==0);
        }
    }
    puts("Settings startup routing and rollback passed");
}
