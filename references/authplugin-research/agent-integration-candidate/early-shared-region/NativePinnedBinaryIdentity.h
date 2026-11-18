#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
namespace NativePinnedBinaryIdentity {
struct API {
 void *(*self)();int (*release)(void*);uint64_t (*flags)();
 void *(*task)(void*);void *(*currentTask)();uint64_t (*unique)(void*);
 void (*uuid)(void*,unsigned char*,unsigned long);
 void *(*vnode)(void*);int (*putVnode)(void*);int (*path)(void*,char*,int*);
 int64_t (*offset)(void*);int (*hash)(void*,int64_t,unsigned char*,uint8_t*);
 void *(*credential)(void*);uint32_t (*uid)(void*);void (*unrefCredential)(void**);
};
struct Policy { bool verified;uint8_t uuid[16],hash[20],hashType;uint32_t uid;const char *path; };
struct Result { uint64_t uniqueID;uint32_t uid;bool pinnedBinaryMatched; };
using Resolve=uintptr_t(*)(void*,const char*);
inline bool bind(Resolve resolve,void*c,bool kernelVerified,API &out){
 out={};if(!resolve||!kernelVerified)return false;
 const char*n[]={"_proc_self","_proc_rele","_proc_selfcsflags","_proc_task","_current_task","_proc_uniqueid","_proc_getexecutableuuid","_proc_getexecutablevnode","_vnode_put","_vn_getpath","_proc_getexecutableoffset","_vn_getcdhash","_kauth_cred_proc_ref","_kauth_cred_getuid","_kauth_cred_unref"};
 uintptr_t a[15];for(unsigned i=0;i<15;++i){a[i]=resolve(c,n[i]);if(!a[i])return false;}
 API b{};
#define B(f,i) b.f=reinterpret_cast<decltype(b.f)>(a[i])
 B(self,0);B(release,1);B(flags,2);B(task,3);B(currentTask,4);B(unique,5);B(uuid,6);B(vnode,7);B(putVnode,8);B(path,9);B(offset,10);B(hash,11);B(credential,12);B(uid,13);B(unrefCredential,14);
#undef B
 out=b;return true;
}
// Invoke synchronously on a normal returning syscall thread; never from an
// interrupt, worker, or under another lock. These helpers may block. This is
// fixed-binary matching, not a certificate-chain or atomic-state assertion.
inline bool terminated(const char*p,int n){for(int i=0;i<n;++i)if(!p[i])return true;return false;}
using Sample = bool (*)(void*,void*,void*);
inline bool capture(const API&a,const Policy&p,Result&out,Sample sample=nullptr,void *context=nullptr){
 out={};if(!p.verified||!p.path||!p.hashType||!a.self||!a.release||!a.flags||!a.task||!a.currentTask||!a.unique||!a.uuid||!a.vnode||!a.putVnode||!a.path||!a.offset||!a.hash||!a.credential||!a.uid||!a.unrefCredential)return false;
 void*proc=a.self();if(!proc)return false;
 struct PG{const API&a;void*p;~PG(){a.release(p);}}pg{a,proc};
 void*t=a.currentTask();if(!t||a.task(proc)!=t)return false;
 // CS_VALID, CS_SIGNED; reject CS_ADHOC and CS_DEBUGGED.
 auto allowed=[](uint64_t f){return (f&0x20000001ULL)==0x20000001ULL && !(f&0x10000002ULL);};
 if(!allowed(a.flags()))return false;
 uint64_t unique=a.unique(proc);if(!unique)return false;
 uint8_t uuid[16]={};a.uuid(proc,uuid,sizeof(uuid));if(memcmp(uuid,p.uuid,16))return false;
 void*cred=a.credential(proc);if(!cred)return false;
 uint32_t uid=a.uid(cred);a.unrefCredential(&cred);if(uid!=p.uid)return false;
 void*v=a.vnode(proc);if(!v)return false;
 struct VG{const API&a;void*v;~VG(){a.putVnode(v);}}vg{a,v};
 char path[1024];memset(path,0x7f,sizeof(path));int len=sizeof(path);
 if(a.path(v,path,&len)||len<=0||len>int(sizeof(path))||!terminated(path,len)||strcmp(path,p.path))return false;
 int64_t offset=a.offset(proc);if(offset<0)return false;
 uint8_t hash[20]={},type=0;if(a.hash(v,offset,hash,&type)||type!=p.hashType||memcmp(hash,p.hash,20))return false;
 if(!allowed(a.flags())||a.currentTask()!=t||a.task(proc)!=t||a.unique(proc)!=unique)return false;
 // The callback executes before proc/vnode guards release. It must not retain
 // these borrowed handles or return pointers into the target.
 if(sample && !sample(context,proc,t))return false;
 if(!allowed(a.flags())||a.currentTask()!=t||a.task(proc)!=t||a.unique(proc)!=unique)return false;
 out={unique,uid,true};return true;
}
}
