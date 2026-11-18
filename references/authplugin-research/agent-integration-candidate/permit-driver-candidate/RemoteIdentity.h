#pragma once
#include "PermitIdentity.h"
namespace ElanPermitRemote {
using Policy=NativePinnedBinaryIdentity::Policy;
struct API {
 void*(*find)(int);int(*releaseProc)(void*);void*(*task)(void*);uint64_t(*unique)(void*);int(*version)(void*);
 int(*flags)(void*,uint64_t*);void(*uuid)(void*,unsigned char*,unsigned long);
 void*(*vnode)(void*);int(*putVnode)(void*);int(*path)(void*,char*,int*);int64_t(*offset)(void*);int(*hash)(void*,int64_t,unsigned char*,uint8_t*);
 int(*taskInfo)(void*,int,int*,unsigned*);void(*retainTask)(void*);void(*releaseTask)(void*);
};
struct Identity {int pid=0;uint32_t version=0;uint64_t unique=0;void*task=nullptr;audit_token_t audit{};};
inline bool complete(const API&a){return a.find&&a.releaseProc&&a.task&&a.unique&&a.version&&a.flags&&a.uuid&&a.vnode&&a.putVnode&&a.path&&a.offset&&a.hash&&a.taskInfo&&a.retainTask&&a.releaseTask;}
inline bool allowed(uint64_t f){return candidateSigningAllowed(f);}
inline bool sample(const API&a,const Policy&p,int pid,uint32_t version,Identity&out,bool(*consume)(const Identity&,void*)=nullptr,void*context=nullptr){
 out={};if(!complete(a)||!p.verified||p.uid!=501||!p.path||!p.hashType||pid<=1||!version)return false;
 void*proc=a.find(pid);if(!proc)return false;
 struct P{const API&a;void*p;~P(){a.releaseProc(p);}}pg{a,proc};
 void*t=a.task(proc);uint64_t unique=a.unique(proc),flags=0;
 if(!t||!unique||static_cast<uint32_t>(a.version(proc))!=version||a.flags(proc,&flags)||!allowed(flags))return false;
 uint8_t uuid[16]{};a.uuid(proc,uuid,16);if(memcmp(uuid,p.uuid,16))return false;
 audit_token_t token{};unsigned count=TASK_AUDIT_TOKEN_COUNT;
 if(a.taskInfo(t,TASK_AUDIT_TOKEN,reinterpret_cast<int*>(&token),&count)||count!=TASK_AUDIT_TOKEN_COUNT||!ElanPermitIdentity::valid(token)||token.val[5]!=static_cast<uint32_t>(pid)||token.val[7]!=version)return false;
 void*v=a.vnode(proc);if(!v)return false;struct V{const API&a;void*v;~V(){a.putVnode(v);}}vg{a,v};
 char path[1024];memset(path,0x7f,sizeof(path));int length=sizeof(path);
 if(a.path(v,path,&length)||length<=0||length>int(sizeof(path))||!NativePinnedBinaryIdentity::terminated(path,length)||strcmp(path,p.path))return false;
 int64_t offset=a.offset(proc);uint8_t hash[20]{},hashType=0;
 if(offset<0||a.hash(v,offset,hash,&hashType)||hashType!=p.hashType||memcmp(hash,p.hash,20))return false;
 a.retainTask(t);
 audit_token_t after{};count=TASK_AUDIT_TOKEN_COUNT;
 bool same=a.task(proc)==t&&a.unique(proc)==unique&&static_cast<uint32_t>(a.version(proc))==version&&!a.flags(proc,&flags)&&allowed(flags)&&!a.taskInfo(t,TASK_AUDIT_TOKEN,reinterpret_cast<int*>(&after),&count)&&count==TASK_AUDIT_TOKEN_COUNT&&!memcmp(&token,&after,sizeof(token));
 if(!same){a.releaseTask(t);return false;}
 out.pid=pid;out.version=version;out.unique=unique;out.task=t;out.audit=token;
 if(consume&&!consume(out,context)){a.releaseTask(t);out={};return false;}
 return true;
}
class Ticket {
 API api{};Policy policy{};Identity identity{};
 public:
 Ticket()=default;Ticket(const Ticket&)=delete;Ticket&operator=(const Ticket&)=delete;
 ~Ticket(){clear();}
 void clear(){if(identity.task)api.releaseTask(identity.task);identity={};}
 bool bind(const API&a,const Policy&p,int pid,uint32_t version){if(identity.task)return false;Identity captured{};if(!sample(a,p,pid,version,captured))return false;api=a;policy=p;identity=captured;return true;}
 bool unchanged(){if(!identity.task)return false;Identity current{};if(!sample(api,policy,identity.pid,identity.version,current))return false;bool same=current.task==identity.task&&current.unique==identity.unique&&!memcmp(&current.audit,&identity.audit,sizeof(identity.audit));api.releaseTask(current.task);return same;}
 bool consume(bool(*action)(void*),void*context){
  if(!identity.task||!action)return false;
  struct Call {const Identity*expected;bool(*action)(void*);void*context;};Call call{&identity,action,context};
  auto visit=[](const Identity&current,void*opaque)->bool{auto*c=static_cast<Call*>(opaque);return current.task==c->expected->task&&current.unique==c->expected->unique&&!memcmp(&current.audit,&c->expected->audit,sizeof(current.audit))&&c->action(c->context);};
  Identity current{};bool ok=sample(api,policy,identity.pid,identity.version,current,visit,&call);
  if(current.task)api.releaseTask(current.task);return ok;
 }
 uint64_t unique()const{return identity.unique;}void*task()const{return identity.task;}
};
}
