#include "NativeOperationGate.h"
#include <assert.h>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>
#include <stdio.h>
int main() {
    NativeOperationGate gate;
    assert(!gate.begin(0));
    auto first = gate.begin(1);
    assert(first && !gate.begin(2));
    gate.ownerClosed(2); assert(gate.mayProceed(first, 1));
    gate.ownerClosed(1); assert(!gate.mayProceed(first, 1));
    assert(!gate.finish(first, 2, true));
    assert(gate.finish(first, 1, false));
    assert(!gate.finish(first, 1, true));
    assert(gate.snapshot().pending && !gate.begin(1));
    auto recovery = gate.begin(2, true);
    assert(recovery && recovery != first);
    assert(!gate.mayProceed(first, 2));
    assert(gate.finish(recovery, 2, true));
    assert(!gate.snapshot().pending && !gate.snapshot().recoveryOnly);
    assert(!gate.requireRecovery(recovery, 2));
    auto ending = gate.begin(2);
    assert(ending && !gate.requireRecovery(ending, 1) && !gate.requireRecovery(ending - 1, 2));
    assert(gate.requireRecovery(ending, 2) && gate.snapshot().recoveryOnly);
    assert(gate.finish(ending, 2, false) && gate.snapshot().recoveryOnly);
    assert(!gate.begin(2));
    auto retry = gate.begin(2, true);
    assert(retry && gate.snapshot().recoveryOnly && gate.finish(retry, 2, false));
    retry = gate.begin(2, true);
    assert(retry && gate.finish(retry, 2, true) && !gate.snapshot().recoveryOnly);

    std::mutex stateLock, waitLock;
    std::condition_variable wait;
    bool entered = false, release = false;
    std::promise<void> closed;
    auto closedFuture = closed.get_future();
    unsigned writes = 0, cleanups = 0;
    std::thread worker([&] {
        uint64_t token;
        { std::lock_guard<std::mutex> lock(stateLock); token = gate.begin(3); }
        assert(token);
        // A fake unbounded kernel wait is deliberately outside the state lock.
        { std::unique_lock<std::mutex> lock(waitLock);
          entered = true; wait.notify_all(); wait.wait(lock, [&] { return release; }); }
        { std::lock_guard<std::mutex> lock(stateLock);
          if (gate.mayProceed(token, 3)) ++writes; }
        ++cleanups;
        { std::lock_guard<std::mutex> lock(stateLock); assert(gate.finish(token, 3, true)); }
    });
    { std::unique_lock<std::mutex> lock(waitLock); wait.wait(lock, [&] { return entered; }); }
    std::thread closer([&] {
        std::lock_guard<std::mutex> lock(stateLock);
        gate.ownerClosed(3);
        auto state = gate.snapshot();
        assert(state.active && state.cancelled);
        assert(!gate.begin(4, true));
        closed.set_value();
    });
    bool remainedReachable = closedFuture.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    // The test releases its fake wait; this is not cancellation of task_hold_and_wait.
    { std::lock_guard<std::mutex> lock(waitLock); release = true; wait.notify_all(); }
    worker.join(); closer.join();
    assert(remainedReachable && writes == 0 && cleanups == 1);
    puts("operation gate: stale tokens, pending, owner death and reachable state during blocked work passed");
}
