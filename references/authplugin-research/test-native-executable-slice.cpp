#include "native-executable-slice.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <stdio.h>
static void u32(std::vector<uint8_t> &b, size_t at, uint32_t v, bool big=false) {
    for (unsigned i=0; i<4; i++) b[at+i]=uint8_t(v >> (big ? 24-i*8 : i*8));
}
static void macho(std::vector<uint8_t> &b,size_t at,uint32_t cpu) {
    u32(b,at,0xfeedfacf);u32(b,at+4,cpu);u32(b,at+12,2);
}
static std::vector<uint8_t> fat(bool wide=false,bool big=true) {
    std::vector<uint8_t> b(32768);u32(b,0,wide?0xcafebabf:0xcafebabe,big);u32(b,4,1,big);
    u32(b,8,0x01000007,big);
    if(wide){u32(b,16+(big?4:0),16384,big);u32(b,24+(big?4:0),16384,big);u32(b,32,14,big);}
    else {u32(b,16,16384,big);u32(b,20,16384,big);u32(b,24,14,big);}
    macho(b,16384,0x01000007);return b;
}
static bool parse(const std::vector<uint8_t>&b,uint64_t &offset,uint32_t cpu=0x01000007) {
    return nativeExecutableSlice(b.size(),cpu,[&](uint64_t at,void*out,size_t n){
        if(at>b.size() || n>b.size()-at)return false;
        memcpy(out,b.data()+at,n);return true;
    },offset);
}
int main(){
    uint64_t offset=999;std::vector<uint8_t> thin(32);macho(thin,0,0x01000007);
    assert(parse(thin,offset)&&offset==0);assert(!parse(thin,offset,0x0100000c));
    for(bool wide:{false,true})for(bool big:{false,true}){auto b=fat(wide,big);assert(parse(b,offset)&&offset==16384);}
    auto b=fat();u32(b,4,65,true);assert(!parse(b,offset));
    b=fat();u32(b,4,0,true);assert(!parse(b,offset));
    b=fat();u32(b,16,0,true);assert(!parse(b,offset));
    b=fat();u32(b,20,32768,true);assert(!parse(b,offset));
    b=fat();u32(b,24,32,true);assert(!parse(b,offset));
    b=fat();u32(b,16,16385,true);assert(!parse(b,offset));
    b=fat();u32(b,16384+4,0x0100000c);assert(!parse(b,offset));
    b=fat();u32(b,16384+12,6);assert(!parse(b,offset));
    b=fat();u32(b,16384+20,32768);assert(!parse(b,offset));
    b=fat();u32(b,4,2,true);memcpy(b.data()+28,b.data()+8,20);assert(!parse(b,offset));
    b=fat(true);u32(b,36,1,true);assert(!parse(b,offset));
    b.resize(16);assert(!parse(b,offset));
    assert(!nativeExecutableSlice(32768,0x01000007,[](uint64_t,void*,size_t){return false;},offset));
    puts("executable slice: thin, FAT32/FAT64 endian variants, architecture, ambiguity, bounds and malformed input passed");
}
