#pragma once
#include "NativeStartupObservation.h"
#include <stddef.h>
namespace NativeStartupCorrelation {
using NativeStartupObservation::Observation;
struct Task { uint64_t address, incarnation; };
inline bool same(Task a, Task b) { return a.address==b.address && a.incarnation==b.incarnation; }
struct Backend {
    void *context;
    bool (*retain)(void *, Task);
    void (*release)(void *, Task);
};
struct FinalIdentity {
    uint64_t procUniqueID, map;
    uint32_t uid;
    const char *path;
    bool appleValidSignature;
    uint8_t uuid[16];
    const char *build;
    bool platformBinary;
    const char *signingIdentifier;
    uint8_t cdhash[20];
};
struct Check {
    bool normalArgument, outputRead, cachePresent;
    int status;
    Observation observation;
};
struct Slot {
    uint64_t thread=0, expires=0;
    bool pending=false, retained=false, recorded=false;
    Task task {};
    uint64_t procUniqueID=0, map=0;
    Observation observation=Observation::Unknown;
};
// Model only. Task incarnation and execution-thread tokens must be trusted, non-reused identities.
// Owner serializes callbacks and calls shutdown before destroying the backend.
template<size_t Capacity> class Chain {
    static_assert(Capacity>0,"positive capacity");
    Backend backend;
    uint8_t uuid[16], cdhash[20];
    const char *build;
    Slot slots[Capacity] {};
    void clear(Slot &s) { if(s.retained) backend.release(backend.context,s.task); s={}; }
public:
    Chain(Backend b,const uint8_t (&expected)[16],const char *expectedBuild,const uint8_t (&expectedHash)[20]):backend(b),build(expectedBuild) {
        memcpy(uuid,expected,16); memcpy(cdhash,expectedHash,20);
    }
    Chain(const Chain&)=delete;
    Chain& operator=(const Chain&)=delete;
    ~Chain() { shutdown(); }
    void shutdown() { for(auto &s:slots) clear(s); }
    void expire(uint64_t now) { for(auto &s:slots) if(s.pending && now>=s.expires) clear(s); }
    void failedSpawn(uint64_t thread) { for(auto &s:slots) if(s.thread==thread) clear(s); }
    void exited(Task task) { for(auto &s:slots) if(s.retained && same(s.task,task)) clear(s); }
    bool exec(uint64_t thread,const char *pathHint,uint64_t now,uint64_t deadline) {
        // Every exec invalidates that thread's earlier correlation, including non-target execs.
        failedSpawn(thread); expire(now);
        if(!thread || deadline<=now || !pathHint || strcmp(pathHint,NativeStartupObservation::TargetPath)) return false;
        for(auto &s:slots) if(!s.pending) { s.thread=thread;s.expires=deadline;s.pending=true;return true; }
        return false;
    }
    bool qos(uint64_t thread,bool trustedExecCallsite,Task newTask,uint64_t now) {
        expire(now);
        for(auto &s:slots) if(s.pending && s.thread==thread) {
            if(!trustedExecCallsite || s.retained || !newTask.address || !newTask.incarnation) { clear(s);return false; }
            for(const auto &other:slots) if(other.retained && other.task.address==newTask.address) { clear(s);return false; }
            if(!backend.retain || !backend.release || !backend.retain(backend.context,newTask)) { clear(s);return false; }
            s.task=newTask;s.retained=true;return true;
        }
        return false;
    }
    bool check(Task currentTask,const FinalIdentity &id,const Check &c,uint64_t now) {
        expire(now);
        for(auto &s:slots) if(s.retained && s.task.address==currentTask.address) {
            if(!same(s.task,currentTask)) { clear(s);return false; }
            if(s.recorded) return false;
            bool valid=id.procUniqueID && id.map && id.uid==501 && id.path &&
                !strcmp(id.path,NativeStartupObservation::TargetPath) && id.appleValidSignature &&
                !memcmp(id.uuid,uuid,16) && build && id.build && !strcmp(build,id.build) &&
                id.platformBinary && id.signingIdentifier &&
                !strcmp(id.signingIdentifier,"com.apple.Touch-ID-Settings.extension") &&
                !memcmp(id.cdhash,cdhash,20);
            if(!valid) { clear(s);return false; }
            if(!c.normalArgument || c.status || !c.outputRead || !c.cachePresent) return false;
            switch(c.observation) {
                case Observation::Cold:case Observation::CompletedEmpty:case Observation::Live:case Observation::Initializing:break;
                default:return false;
            }
            s.procUniqueID=id.procUniqueID;s.map=id.map;s.observation=c.observation;s.recorded=true;return true;
        }
        return false;
    }
    size_t retainedCount() const { size_t n=0;for(const auto &s:slots) n+=s.retained;return n; }
    bool recorded(Task task) const { for(const auto &s:slots) if(s.retained&&same(task,s.task)) return s.recorded;return false; }
};
}
