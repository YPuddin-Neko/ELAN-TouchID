#include "NativeSettingsAgentGate.h"
#include <cassert>
#include <cstdio>
#include <initializer_list>
#include <vector>

namespace {
constexpr uint64_t base=0x7ff800000000ULL, image=base+0x10a5b0000ULL, object=image+0x366f14e0;
constexpr uint64_t text=image+0x39858, platform=image+0x38e1b028, scratch=0x100000;
constexpr uint64_t agentImage=0x100000000ULL;
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

struct AgentMemory : RouteMemory {
    std::vector<uint8_t> binary;
    bool codeRX = true, deny = false, failCopy = false, failWrite = false, failSeal = false, failRestore = false;
    explicit AgentMemory(Fault f = None) : RouteMemory(f), binary(0x4000, 0) {
        memcpy(binary.data(), NativeSettingsAgentSample::header, sizeof(NativeSettingsAgentSample::header));
        for (const auto &cmd : NativeSettingsAgentSample::commands)
            memcpy(binary.data() + cmd[0], cmd + 1, 8);
        memcpy(binary.data() + NativeSettingsAgentSample::uuidOffset, NativeSettingsAgentSample::uuid, sizeof(NativeSettingsAgentSample::uuid));
        memcpy(binary.data() + NativeSettingsAgentSample::codeOffset, NativeSettingsAgentSample::codeOriginal, sizeof(NativeSettingsAgentSample::codeOriginal));
    }
    CurrentCopyinSample::Reader reader() {
        return {this, [](void *ctx, uint64_t addr, void *out, size_t n) {
            auto &m = *static_cast<AgentMemory *>(ctx);
            if (addr >= agentImage && n <= m.binary.size() && addr - agentImage <= m.binary.size() - n) {
                memcpy(out, m.binary.data() + (addr - agentImage), n);
                return 0;
            }
            auto r = m.RouteMemory::reader();
            return r.copy(r.context, addr, out, n);
        }};
    }
    bool permitted() const { return !deny && RouteMemory::permitted(); }
    bool executablePage(uint64_t page) const { return page == (agentImage + 0x1000) && codeRX; }
    bool makeCopyWritable(uint64_t page) {
        if (page == (agentImage + 0x1000)) {
            if (failCopy) return false;
            codeRX = false;
            return true;
        }
        return RouteMemory::makeCopyWritable(page);
    }
    bool protectExecutablePage(uint64_t page) {
        assert(page == (agentImage + 0x1000));
        if (failSeal) return false;
        codeRX = true;
        return true;
    }
    bool storePointer(uint64_t dest, uint64_t val) {
        if (dest == agentImage + NativeSettingsAgentSample::codeOffset) {
            assert(!codeRX);
            uint64_t orig = 0;
            memcpy(&orig, NativeSettingsAgentSample::codeOriginal, 8);
            if ((failWrite && val != orig) || (failRestore && val == orig)) return false;
            memcpy(binary.data() + NativeSettingsAgentSample::codeOffset, &val, 8);
            return true;
        }
        return RouteMemory::storePointer(dest, val);
    }
};
} // namespace

int main() {
    using R = NativeSettingsRoute::Result;
    {
        AgentMemory m;
        auto sample = NativeSettingsAgentSample::inspect(m.reader().copy, &m, agentImage);
        assert(sample.stage == SettingsSample::Stage::Complete && sample.state == SettingsSample::State::Cold);
        NativeSettingsAgentGate::Stage stage{};
        assert(NativeSettingsAgentGate::apply(m, agentImage, base, &stage) == R::Routed);
        assert(stage == NativeSettingsAgentGate::Stage::Complete && m.codeRX && m.flags[0] == 1 && m.flags[1] == 1);
        assert(!memcmp(m.binary.data() + NativeSettingsAgentSample::codeOffset, NativeSettingsAgentSample::codePatched, sizeof(NativeSettingsAgentSample::codePatched)));
        // A second inspection sees patched code and rejects re-entry.
        auto warm = NativeSettingsAgentSample::inspect(m.reader().copy, &m, agentImage);
        assert(warm.stage != SettingsSample::Stage::Complete);
    }
    for (auto f : {WrongName, Warm, NoCow, NoListener, Allocation, Seal, PartialFlags, Disconnect}) {
        AgentMemory m(f);
        auto r = NativeSettingsAgentGate::apply(m, agentImage, base);
        assert(r != R::Routed && m.codeRX);
        assert(!memcmp(m.binary.data() + NativeSettingsAgentSample::codeOffset, NativeSettingsAgentSample::codeOriginal, sizeof(NativeSettingsAgentSample::codeOriginal)));
    }
    {
        AgentMemory m; m.failCopy = true;
        assert(NativeSettingsAgentGate::apply(m, agentImage, base) == R::Skipped && m.codeRX);
    }
    {
        AgentMemory m; m.failWrite = true;
        assert(NativeSettingsAgentGate::apply(m, agentImage, base) == R::Skipped && m.codeRX);
    }
    {
        AgentMemory m(WrongName); m.failRestore = true;
        assert(NativeSettingsAgentGate::apply(m, agentImage, base) == R::Incomplete);
    }
    puts("Settings agent sample, code gate, route and rollback passed");
}
