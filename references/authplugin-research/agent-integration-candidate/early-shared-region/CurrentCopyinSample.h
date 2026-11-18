#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "TargetImagePins.h"
namespace CurrentCopyinSample {
enum class Stage:uint32_t {Argument,Base,CacheHeader,CacheLayout,Image,Getter,PlatformCode,State,Changed,Complete};
enum class State:uint32_t {Unknown,NotStarted,CompletedEmpty,LiveObject,Initializing};
struct Result {Stage stage=Stage::Argument;State state=State::Unknown;uint8_t checked=0,result=0;};
using Copy=int(*)(void*,uint64_t,void*,size_t);
struct Reader {
 void*context;Copy copy;
 bool read(uint64_t a,void*out,size_t n)const{
  constexpr uint64_t limit=0x00007fffffffffffULL;
  if(!copy||!out||!n||n>4096||a<4096||a>limit||n-1>limit-a)return false;
  return copy(context,a,out,n)==0;
 }
 bool equal(uint64_t a,const uint8_t*pin,size_t n)const{
  if(!pin||!n||n>4096||a>UINT64_MAX-n)return false;
  uint8_t chunk[128];for(size_t at=0;at<n;at+=sizeof(chunk)){
   size_t bytes=n-at<sizeof(chunk)?n-at:sizeof(chunk);
   if(!read(a+at,chunk,bytes)||memcmp(chunk,pin+at,bytes))return false;
  }return true;
 }
};
inline Result inspectBase(Reader r,uint64_t base,uint64_t outputAddress=0){
 Result out{};
 out.stage=Stage::Base;
 constexpr uint64_t start=0x7ff800000000ULL,maxSlide=0x1ae68000ULL;
 if(base<start||base-start>maxSlide||(base&4095))return out;
 out.stage=Stage::CacheHeader;uint8_t h[248];if(!r.read(base,h,sizeof(h)))return out;
 const char magic[16]="dyld_v1 x86_64h";
 const uint8_t uuid[16]={0x42,0xec,0x28,0x90,0xbc,0x40,0x31,0x7e,0xbb,0x27,0x45,0x14,0x2b,0xff,0x7f,0x26};
 uint32_t off=0,count=0;uint64_t region=0,size=0,max=0;
 memcpy(&off,h+16,4);memcpy(&count,h+20,4);memcpy(&region,h+224,8);memcpy(&size,h+232,8);memcpy(&max,h+240,8);
 if(memcmp(h,magic,16)||memcmp(h+88,uuid,16)||off!=0x228||count!=4||region!=start||size!=0x700000000ULL||max!=maxSlide)return out;
 out.stage=Stage::CacheLayout;
 const uint64_t addr[]={140703128616960ULL,140704202358784ULL,140704259440640ULL,140705276100608ULL};
 const uint64_t sizes[]={622428160,57081856,14958592,169213952};
 const uint64_t offsets[]={0,622428160,679510016,694468608};
 const uint32_t maxima[]={5,3,3,1},initial[]={5,1,3,1};
 for(unsigned i=0;i<4;++i){uint8_t row[32],pin[32];memcpy(pin,addr+i,8);memcpy(pin+8,sizes+i,8);memcpy(pin+16,offsets+i,8);memcpy(pin+24,maxima+i,4);memcpy(pin+28,initial+i,4);
  if(!r.read(base+off+i*32,row,32)||memcmp(row,pin,32))return out;
 }
 constexpr uint64_t imageOffset=0x10a5b0000ULL;
 const uint64_t image=base+imageOffset;
 out.stage=Stage::Image;if(!r.equal(image,TargetImagePins::header,sizeof(TargetImagePins::header)))return out;
 out.stage=Stage::Getter;if(!r.equal(image+0x183f,TargetImagePins::getter,sizeof(TargetImagePins::getter)))return out;
 out.stage=Stage::PlatformCode;if(!r.equal(image+0x238d1,TargetImagePins::platform,sizeof(TargetImagePins::platform)))return out;
 out.stage=Stage::State;
 uint64_t pair[2],again[2];uint8_t platform[2],pAgain[2];
 if(!r.read(image+0x38b0da98,pair,sizeof(pair))||!r.read(image+0x38e1b028,platform,2))return out;
 uint64_t baseAgain=0;uint8_t headerAgain[248];
 out.stage=Stage::Changed;
 if(!r.read(image+0x38b0da98,again,sizeof(again))||!r.read(image+0x38e1b028,pAgain,2)||
    !r.read(base,headerAgain,sizeof(headerAgain))||(outputAddress&&!r.read(outputAddress,&baseAgain,8))||
    memcmp(pair,again,sizeof(pair))||memcmp(platform,pAgain,2)||memcmp(h,headerAgain,sizeof(h))||(outputAddress&&baseAgain!=base)||platform[0]>1||platform[1]>1)return out;
 out.stage=Stage::Complete;out.checked=platform[0];out.result=platform[1];
 out.state=pair[0]?State::LiveObject:!pair[1]?State::NotStarted:pair[1]==UINT64_MAX?State::CompletedEmpty:State::Initializing;
 return out;
}
inline Result inspect(Reader r,uint64_t outputAddress){
 uint64_t base=0;if(!r.read(outputAddress,&base,8))return {};
 return inspectBase(r,base,outputAddress);
}
inline Result inspectKnownBase(Reader r,uint64_t base){return inspectBase(r,base);}
}
