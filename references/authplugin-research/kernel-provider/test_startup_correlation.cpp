#include "NativeStartupCorrelation.h"
#include <cassert>
#include <cstdio>
using namespace NativeStartupCorrelation;
struct Fake {
    int refs=0,retains=0,releases=0;bool fail=false;
    static bool retain(void *p,Task){auto &f=*static_cast<Fake*>(p);f.retains++;if(f.fail)return false;f.refs++;return true;}
    static void release(void *p,Task){auto &f=*static_cast<Fake*>(p);assert(f.refs>0);f.refs--;f.releases++;}
    Backend backend(){return {this,retain,release};}
};
static const uint8_t uuid[16]={1,2,3};
static const uint8_t hash[20]={4,5,6};
static FinalIdentity identity(){FinalIdentity i{99,88,501,NativeStartupObservation::TargetPath,true,{},"24H32",true,"com.apple.Touch-ID-Settings.extension",{}};memcpy(i.uuid,uuid,16);memcpy(i.cdhash,hash,20);return i;}
static Check normal(){return {true,true,true,0,Observation::Cold};}
int main(){
    Task t{100,1};auto id=identity();auto ck=normal();
    {
        Fake f;Chain<2> c(f.backend(),uuid,"24H32",hash);
        assert(!c.qos(1,true,t,1));assert(!c.check(t,id,ck,1));
        assert(c.exec(1,id.path,1,10));assert(!c.qos(2,true,t,2));assert(c.qos(1,true,t,2));
        assert(f.refs==1);assert(!c.check({200,1},id,ck,3));assert(c.check(t,id,ck,3));
        assert(!c.check(t,id,ck,4));assert(c.recorded(t));
        c.exited({100,2});assert(f.refs==1);c.exited(t);assert(f.refs==0);
    }
    for(int n=0;n<11;n++){
        Fake f;Chain<1> c(f.backend(),uuid,"24H32",hash);assert(c.exec(1,id.path,0,10));assert(c.qos(1,true,t,1));auto bad=id;
        switch(n){case 0:bad.uid=0;break;case 1:bad.path="/tmp/fake";break;case 2:bad.appleValidSignature=false;break;
            case 3:bad.uuid[0]^=1;break;case 4:bad.build="other";break;case 5:bad.procUniqueID=0;break;case 6:bad.map=0;break;case 7:bad.path=nullptr;break;case 8:bad.platformBinary=false;break;case 9:bad.signingIdentifier="wrong";break;case 10:bad.cdhash[0]^=1;break;}
        assert(!c.check(t,bad,ck,2));assert(f.refs==0);
    }
    for(int n=0;n<5;n++){
        Fake f;Chain<1> c(f.backend(),uuid,"24H32",hash);assert(c.exec(1,id.path,0,10));assert(c.qos(1,true,t,1));auto bad=ck;
        switch(n){case 0:bad.normalArgument=false;break;case 1:bad.status=-1;break;case 2:bad.outputRead=false;break;case 3:bad.cachePresent=false;break;case 4:bad.observation=Observation::Unknown;break;}
        assert(!c.check(t,id,bad,2));assert(!c.recorded(t));assert(c.check(t,id,ck,3));
    }
    {
        Fake f;Chain<1> c(f.backend(),uuid,"24H32",hash);assert(c.exec(1,id.path,0,10));assert(c.qos(1,true,t,1));
        assert(!c.exec(2,id.path,2,10));assert(f.refs==1); // capacity cannot leak or steal
        assert(!c.check({100,2},id,ck,3));assert(f.refs==0); // pointer reuse
        assert(c.exec(1,id.path,3,10));assert(c.qos(1,true,t,4));
        assert(!c.exec(1,"/bin/other",5,10));assert(f.refs==0); // unrelated exec on SAME thread invalidates
        assert(!c.qos(1,true,t,6));
    }
    {
        Fake f;Chain<2> c(f.backend(),uuid,"24H32",hash);assert(c.exec(1,id.path,0,10));
        assert(!c.qos(1,false,t,1));assert(f.retains==0);
        assert(c.exec(1,id.path,1,10));f.fail=true;assert(!c.qos(1,true,t,2));assert(f.refs==0);f.fail=false;
        assert(c.exec(1,id.path,2,10));assert(c.qos(1,true,t,3));c.failedSpawn(1);assert(f.refs==0);
        assert(c.exec(1,id.path,3,10));assert(c.qos(1,true,t,4));c.expire(10);assert(f.refs==0);
        assert(c.exec(1,id.path,11,20));assert(!c.qos(1,true,t,20));assert(f.refs==0);
        assert(c.exec(1,id.path,21,30));assert(c.qos(1,true,t,22));
        assert(c.exec(2,id.path,22,30));assert(!c.qos(2,true,{100,2},23));assert(f.refs==1);
        c.shutdown();c.shutdown();assert(f.refs==0);
    }
    Fake f;{Chain<1> c(f.backend(),uuid,"24H32",hash);assert(c.exec(1,id.path,0,10));assert(c.qos(1,true,t,1));}assert(f.refs==0);
    puts("startup correlation: isolated identity, callsite, lifecycle, capacity and retain/release tests passed");
}
