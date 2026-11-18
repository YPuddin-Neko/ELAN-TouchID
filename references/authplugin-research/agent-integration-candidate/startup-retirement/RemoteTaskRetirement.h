#pragma once
#include "ExactTaskRetirement.h"

namespace ExactTaskRetirement {
// A reference is transferred here while the current-task ticket is still owned.
// Retirement later runs on the controller thread, never through a PID lookup.
class RemoteTicket {
    void *task_ = nullptr;
    uint64_t generation_ = 0;
public:
    RemoteTicket() = default;
    RemoteTicket(const RemoteTicket &) = delete;
    RemoteTicket &operator=(const RemoteTicket &) = delete;
    bool retained() const { return task_ != nullptr; }
    void *task() const { return task_; }
    uint64_t generation() const { return generation_; }

    bool adoptCurrent(Ticket &source) {
        if (task_ || !source.retained || !source.task || !source.generation) return false;
        task_ = source.task;
        generation_ = source.generation;
        source = {};
        return true;
    }
    // The current ticket remains owned until the provider commits its gate.
    bool duplicateCurrent(const API &api, const Ticket &source) {
        if (task_ || !source.retained || !source.task || !source.generation ||
            !api.currentTask || !api.currentThread || !api.retain ||
            api.currentTask(api.context) != source.task ||
            api.currentThread(api.context) != source.thread) return false;
        api.retain(api.context, source.task);
        task_ = source.task;
        generation_ = source.generation;
        return true;
    }
    bool retainBorrowed(const API &api, void *task) {
        if (task_ || !task || !api.currentTask || !api.retain || !api.release ||
            !api.generation || !api.taskActive || !api.corpsePending ||
            task == api.currentTask(api.context)) return false;
        api.retain(api.context, task);
        const auto generation = api.generation(api.context, task);
        if (!generation || !api.taskActive(api.context, task) ||
            api.corpsePending(api.context, task) ||
            generation != api.generation(api.context, task) ||
            task == api.currentTask(api.context)) {
            api.release(api.context, task);
            return false;
        }
        task_ = task;
        generation_ = generation;
        return true;
    }
    // Only for an unmodified admission that has not been published to a writer.
    bool releaseClean(const API &api) {
        if (!task_) return true;
        if (!api.release) return false;
        api.release(api.context, task_);
        task_ = nullptr;
        generation_ = 0;
        return true;
    }
    Result retire(const API &api) {
        Result result {Outcome::UnsafeUnresolved, Reason::MissingAPI};
        if (!task_ || !api.currentTask || !api.terminate || !api.taskActive || !api.release)
            return result;
        if (api.currentTask(api.context) == task_) {
            result.reason = Reason::WrongCurrent;
            return result;
        }
        // The retained task is the target even after exec changes its generation.
        // Remote KERN_FAILURE does not prove its other threads finished teardown.
        result.terminationStatus = api.terminate(api.context, task_);
        result.taskInactive = !api.taskActive(api.context, task_);
        if (result.terminationStatus || !result.taskInactive) {
            result.reason = Reason::StillActive;
            return result;
        }
        result.outcome = Outcome::NoUserResumeVerified;
        result.reason = Reason::None;
        releaseClean(api);
        return result;
    }
};
}
