#include "KernelRuntime.h"
#include <kern/task.h>
#include <kern/thread.h>
namespace RetirementRuntime {
struct Functions {
 task_t(*currentTask)();thread_t(*currentThread)();task_t(*threadTask)(thread_t);
 uint64_t(*generation)(task_t);boolean_t(*taskActive)(task_t);boolean_t(*threadActive)(thread_t);
 void(*retain)(task_t);void(*release)(task_t);kern_return_t(*terminate)(task_t);
 boolean_t(*isCorpse)(task_t);boolean_t(*isHalting)(task_t);kern_return_t(*terminateThread)(thread_t);
};
static Functions fn{};static bool ready=false;
static bool read(void*,uintptr_t address,void*out,size_t n){memcpy(out,reinterpret_cast<const void*>(address),n);return true;}
static void*current(void*){return fn.currentTask();}static void*thread(void*){return fn.currentThread();}
static void*task(void*,void*t){return fn.threadTask(static_cast<thread_t>(t));}
static uint64_t generation(void*,void*t){return fn.generation(static_cast<task_t>(t));}
static bool active(void*,void*t){return fn.taskActive(static_cast<task_t>(t));}static bool threadActive(void*,void*t){return fn.threadActive(static_cast<thread_t>(t));}
static bool pending(void*,void*t){
 // Exact full task-termination body pins its pending-corpse test at task+0x408.
 return (*reinterpret_cast<volatile const uint32_t*>(reinterpret_cast<uintptr_t>(t)+0x408)&0x40)!=0;
}
static void retain(void*,void*t){fn.retain(static_cast<task_t>(t));}static void release(void*,void*t){fn.release(static_cast<task_t>(t));}
static int terminate(void*,void*t){return fn.terminate(static_cast<task_t>(t));}
static bool corpse(void*,void*t){return fn.isCorpse(static_cast<task_t>(t));}static bool halting(void*,void*t){return fn.isHalting(static_cast<task_t>(t));}
static int terminateThread(void*,void*t){return fn.terminateThread(static_cast<thread_t>(t));}
static bool noOwnedOuterResources(void*){return true;}
static ExactTaskRetirement::API api(){return {nullptr,current,thread,task,generation,active,threadActive,pending,retain,release,noOwnedOuterResources,terminate,corpse,halting,terminateThread};}
bool configure(RetirementPins::Resolve resolve,void*c,uint64_t slide,const uint8_t*uuid){
 if(ready)return false;uintptr_t v[13]{};if(!RetirementPins::verify(resolve,c,read,nullptr,slide,uuid,v))return false;
 Functions candidate{};
#define B(field,index) candidate.field=reinterpret_cast<decltype(candidate.field)>(v[index])
 B(currentTask,0);B(currentThread,1);B(threadTask,2);B(generation,3);B(taskActive,4);B(threadActive,5);B(retain,6);B(release,7);B(terminate,8);B(isCorpse,9);B(isHalting,10);B(terminateThread,11);
#undef B
 fn=candidate;ready=true;return true;
}
bool configured(){return ready;}
ExactTaskRetirement::Result admitCurrent(ExactTaskRetirement::Ticket&t){if(!ready)return {ExactTaskRetirement::Outcome::NotAdmitted,ExactTaskRetirement::Reason::MissingAPI};return ExactTaskRetirement::admit(api(),t);}
void cancelClean(ExactTaskRetirement::Ticket&t){if(ready)ExactTaskRetirement::cancelClean(api(),t);}
ExactTaskRetirement::Result retireAfterOuterScope(ExactTaskRetirement::Ticket&t){if(!ready)return {ExactTaskRetirement::Outcome::UnsafeUnresolved,ExactTaskRetirement::Reason::MissingAPI};return ExactTaskRetirement::retireDirty(api(),t);}
bool retainRemote(void*task,ExactTaskRetirement::RemoteTicket&t){return ready&&t.retainBorrowed(api(),task);}
bool duplicateCurrent(const ExactTaskRetirement::Ticket&source,ExactTaskRetirement::RemoteTicket&t){return ready&&t.duplicateCurrent(api(),source);}
bool releaseRemoteClean(ExactTaskRetirement::RemoteTicket&t){return ready&&t.releaseClean(api());}
ExactTaskRetirement::Result retireRemote(ExactTaskRetirement::RemoteTicket&t){if(!ready)return {ExactTaskRetirement::Outcome::UnsafeUnresolved,ExactTaskRetirement::Reason::MissingAPI};return t.retire(api());}
}
