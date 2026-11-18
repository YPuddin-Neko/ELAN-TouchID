#pragma once
#include <stdint.h>
namespace ExactTaskRetirement {
constexpr bool RuntimeWriterEnabled=false;
enum class Outcome {NotAdmitted,AdmittedOffline,NoUserResumeVerified,CorpseNoUserResumeVerified,UnsafeUnresolved};
enum class Reason {None,MissingAPI,WrongCurrent,InactiveBeforeWrite,CorpseBeforeWrite,GenerationChanged,OuterCleanupFailed,CurrentChanged,StillActive};
struct API {
 void*context;
 void*(*currentTask)(void*);void*(*currentThread)(void*);void*(*threadTask)(void*,void*);
 uint64_t(*generation)(void*,void*);
 bool(*taskActive)(void*,void*);bool(*threadActive)(void*,void*);bool(*corpsePending)(void*,void*);
 void(*retain)(void*,void*);void(*release)(void*,void*);
 // Releases ALL caller-owned proc/vnode/map references and locks, but not this ticket's task reference.
 bool(*cleanupOuter)(void*);
 int(*terminate)(void*,void*);
 bool(*isCorpse)(void*,void*);bool(*isHalting)(void*,void*);
 int(*terminateThread)(void*,void*);
};
struct Ticket {void*task=nullptr;void*thread=nullptr;uint64_t generation=0;bool retained=false;};
struct Result {Outcome outcome=Outcome::NotAdmitted;Reason reason=Reason::None;int terminationStatus=-1;bool taskInactive=false,threadInactive=false;bool corpseFallback=false;int threadTerminationStatus=-1;};
inline bool complete(const API&a){return a.currentTask&&a.currentThread&&a.threadTask&&a.generation&&a.taskActive&&a.threadActive&&a.corpsePending&&a.retain&&a.release&&a.cleanupOuter&&a.terminate&&a.isCorpse&&a.isHalting&&a.terminateThread;}
// Must run before ANY target write. Host/injection model only; not runtime authorization.
inline Result admit(const API&a,Ticket&t){
 if(t.retained||!complete(a))return {Outcome::NotAdmitted,Reason::MissingAPI};
 auto task=a.currentTask(a.context),thread=a.currentThread(a.context);
 if(!task||!thread||a.threadTask(a.context,thread)!=task)return {Outcome::NotAdmitted,Reason::WrongCurrent};
 a.retain(a.context,task);t={task,thread,a.generation(a.context,task),true};
 Reason failure=Reason::None;
 if(a.currentTask(a.context)!=task||a.currentThread(a.context)!=thread)failure=Reason::WrongCurrent;
 else if(!a.taskActive(a.context,task)||!a.threadActive(a.context,thread))failure=Reason::InactiveBeforeWrite;
 else if(a.corpsePending(a.context,task))failure=Reason::CorpseBeforeWrite;
 else if(!t.generation||a.generation(a.context,task)!=t.generation)failure=Reason::GenerationChanged;
 if(failure!=Reason::None){a.release(a.context,task);t={};return {Outcome::NotAdmitted,failure};}
 return {Outcome::AdmittedOffline,Reason::None};
}
inline void cancelClean(const API&a,Ticket&t){if(t.retained){a.release(a.context,t.task);t={};}}
// Call only after a write attempt whose result cannot be accepted. No rollback.
// UnsafeUnresolved MUST NOT permit ordinary return to userspace or enable a writer.
inline Result retireDirty(const API&a,Ticket&t){
 Result r{Outcome::UnsafeUnresolved,Reason::MissingAPI};
 if(!t.retained||!complete(a))return r;
 auto finish=[&](){a.release(a.context,t.task);t={};return r;};
 if(!a.cleanupOuter(a.context)){r.reason=Reason::OuterCleanupFailed;return r;}
 if(a.currentTask(a.context)!=t.task||a.currentThread(a.context)!=t.thread||a.threadTask(a.context,t.thread)!=t.task){r.reason=Reason::CurrentChanged;return r;}
 // Even changed generations must not redirect retirement to a replacement task.
 // Only the originally retained, still-current task is passed to the kernel.
 r.terminationStatus=a.terminate(a.context,t.task);
 r.taskInactive=!a.taskActive(a.context,t.task);r.threadInactive=!a.threadActive(a.context,t.thread);
 if(a.currentTask(a.context)==t.task&&a.currentThread(a.context)==t.thread&&r.taskInactive&&r.threadInactive){r.outcome=Outcome::NoUserResumeVerified;r.reason=Reason::None;}
 else if(r.terminationStatus==5&&a.currentTask(a.context)==t.task&&a.currentThread(a.context)==t.thread&&a.isCorpse(a.context,t.task)&&a.isHalting(a.context,t.task)){
  // The original task-termination call acquired the task lock. Its corpse
  // failure follows task_mark_corpse's locked halt of other threads.
  r.corpseFallback=true;r.threadTerminationStatus=a.terminateThread(a.context,t.thread);
  r.taskInactive=!a.taskActive(a.context,t.task);r.threadInactive=!a.threadActive(a.context,t.thread);
  if(a.currentTask(a.context)==t.task&&a.currentThread(a.context)==t.thread&&r.threadInactive&&a.isCorpse(a.context,t.task)&&a.isHalting(a.context,t.task)){
   r.outcome=r.taskInactive?Outcome::NoUserResumeVerified:Outcome::CorpseNoUserResumeVerified;r.reason=Reason::None;
  }else r.reason=Reason::StillActive;
 }else r.reason=Reason::StillActive;
 return r.outcome==Outcome::UnsafeUnresolved?r:finish();
}
inline bool mayFinishSyscall(const Result&r){return r.outcome==Outcome::NoUserResumeVerified||r.outcome==Outcome::CorpseNoUserResumeVerified;}
}
