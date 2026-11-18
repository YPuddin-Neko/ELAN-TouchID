#pragma once
#include "NativePinnedBinaryIdentity.h"
#include <mach/task_info.h>
namespace ElanPermitIdentity {
struct Config {NativePinnedBinaryIdentity::Policy binary{};bool configured=false;};
struct Snapshot {uint64_t processUnique=0;audit_token_t audit{};};
struct API {NativePinnedBinaryIdentity::API binary;int (*taskInfo)(void*,int,int*,unsigned*);};
inline bool valid(const audit_token_t&t){return t.val[0]==501&&t.val[1]==501&&t.val[3]==501&&t.val[5]>1&&t.val[5]<=INT32_MAX&&t.val[6]&&t.val[7];}
inline bool capture(const API&a,const Config&config,void*connectionTask,Snapshot&out){
 out={};if(!config.configured||!config.binary.verified||config.binary.uid!=501||!connectionTask||!a.taskInfo||!a.binary.currentTask||a.binary.currentTask()!=connectionTask)return false;
 audit_token_t before{},after{};unsigned n=TASK_AUDIT_TOKEN_COUNT;
 if(a.taskInfo(connectionTask,TASK_AUDIT_TOKEN,reinterpret_cast<int*>(&before),&n)||n!=TASK_AUDIT_TOKEN_COUNT||!valid(before))return false;
 NativePinnedBinaryIdentity::Result binary{};
 if(!NativePinnedBinaryIdentity::capture(a.binary,config.binary,binary))return false;
 n=TASK_AUDIT_TOKEN_COUNT;
 if(a.taskInfo(connectionTask,TASK_AUDIT_TOKEN,reinterpret_cast<int*>(&after),&n)||n!=TASK_AUDIT_TOKEN_COUNT||memcmp(&before,&after,sizeof(before))||a.binary.currentTask()!=connectionTask)return false;
 out.processUnique=binary.uniqueID;out.audit=before;return true;
}
// Default remains disabled until an independently verified signed helper is pinned.
inline Config unconfigured(){return Config{};}
}
