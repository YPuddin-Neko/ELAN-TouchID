#pragma once
#include <stdint.h>

// Call every method while holding the same state mutex. Blocking task operations
// run outside that mutex, using the returned token until finish().
class NativeOperationGate {
    uint64_t generation = 0;
    uint64_t owner = 0;
    bool active = false;
    bool cancelled = false;
    bool pending = false;
    bool recoveryOnly = false;
public:
    struct Snapshot { bool active; bool cancelled; bool pending; bool recoveryOnly; };
    uint64_t begin(uint64_t identity, bool recovery = false) {
        if (!identity || active || (pending && !recovery) || generation == UINT64_MAX) return 0;
        ++generation; owner = identity; active = true; cancelled = false;
        return generation;
    }
    bool mayProceed(uint64_t token, uint64_t identity) const {
        return active && token == generation && identity == owner && !cancelled;
    }
    void ownerClosed(uint64_t identity) {
        if (active && owner == identity) { cancelled = true; recoveryOnly = true; }
    }
    // A failed teardown stays recovery-only even if the session is still active.
    bool requireRecovery(uint64_t token, uint64_t identity) {
        if (!active || token != generation || identity != owner) return false;
        recoveryOnly = true;
        return true;
    }
    bool finish(uint64_t token, uint64_t identity, bool allStateClean) {
        if (!active || token != generation || identity != owner) return false;
        pending = !allStateClean; active = false; owner = 0; cancelled = false;
        if (allStateClean) recoveryOnly = false;
        return true;
    }
    Snapshot snapshot() const { return {active, cancelled, pending, recoveryOnly}; }
};
