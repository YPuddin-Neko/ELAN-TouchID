#pragma once
#include <stdint.h>
namespace ExecGeneration {
// Inputs and results remain inside the already referenced identity callback.
struct Stamp {void*proc=nullptr;void*task=nullptr;uint64_t processUnique=0,taskUnique=0;uint32_t pidVersion=0;};
struct API {
 void*context=nullptr;
 void*(*currentTask)(void*)=nullptr;
 void*(*procTask)(void*,void*)=nullptr;
 uint64_t(*processUnique)(void*,void*)=nullptr;
 int(*pidVersion)(void*,void*)=nullptr;
 uint64_t(*taskUnique)(void*,void*)=nullptr;
};
enum class Outcome:uint32_t {MissingAPI,WrongTask,InvalidIdentity,Changed,Stable};
inline bool same(const Stamp&a,const Stamp&b){return a.proc==b.proc&&a.task==b.task&&a.processUnique==b.processUnique&&a.taskUnique==b.taskUnique&&a.pidVersion==b.pidVersion;}
inline Outcome sample(const API&a,void*referencedProc,void*borrowedCurrentTask,Stamp&out){
 out={};if(!a.currentTask||!a.procTask||!a.processUnique||!a.pidVersion||!a.taskUnique)return Outcome::MissingAPI;
 if(!referencedProc||!borrowedCurrentTask||a.currentTask(a.context)!=borrowedCurrentTask||a.procTask(a.context,referencedProc)!=borrowedCurrentTask)return Outcome::WrongTask;
 Stamp first{referencedProc,borrowedCurrentTask,a.processUnique(a.context,referencedProc),a.taskUnique(a.context,borrowedCurrentTask),static_cast<uint32_t>(a.pidVersion(a.context,referencedProc))};
 Stamp second{referencedProc,borrowedCurrentTask,a.processUnique(a.context,referencedProc),a.taskUnique(a.context,borrowedCurrentTask),static_cast<uint32_t>(a.pidVersion(a.context,referencedProc))};
 if(a.currentTask(a.context)!=borrowedCurrentTask||a.procTask(a.context,referencedProc)!=borrowedCurrentTask)return Outcome::WrongTask;
 if(!first.processUnique||!first.taskUnique||!second.processUnique||!second.taskUnique)return Outcome::InvalidIdentity;
 if(!same(first,second))return Outcome::Changed;
 out=second;return Outcome::Stable;
}
// Check the same generation around a separate read-only observation. This is not
// an exec event, initial-thread assertion, held task, atomic snapshot or write gate.
inline Outcome revalidate(const API&a,const Stamp&before){
 Stamp after{};auto result=sample(a,before.proc,before.task,after);
 if(result!=Outcome::Stable)return result;
 return same(before,after)?Outcome::Stable:Outcome::Changed;
}
}
