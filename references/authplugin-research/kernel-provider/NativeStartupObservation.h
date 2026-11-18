#pragma once
#include <stdint.h>
#include <string.h>

// Pure filter: caller supplies trusted lifecycle events, never PID-derived guesses.
// execGeneration is an observer-assigned increasing sequence within one boot.
namespace NativeStartupObservation {
static constexpr const char *TargetPath = "/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password";
enum class Observation : uint32_t { Unknown, Cold, CompletedEmpty, Live, Initializing };
struct Identity {
    uint64_t bootNonce, execGeneration, procUniqueID, task, map;
};
struct Target {
    Identity identity;
    uint32_t uid;
    const char *path;
    uint8_t executableUUID[16];
    bool trustedSignature;
};
struct Policy { uint64_t bootNonce; uint8_t executableUUID[16]; };
struct Check {
    int status;
    bool outputArgumentNonNull;
    bool specialArgument;
    bool outputReadSucceeded;
    bool cacheAddressNonZero;
    Observation observation;
};
struct State {
    uint64_t lastExecGeneration = 0;
    Identity binding {};
    bool armed = false;
    bool recorded = false;
    Observation observation = Observation::Unknown;
};
inline bool same(const Identity &a, const Identity &b) {
    return a.bootNonce == b.bootNonce && a.execGeneration == b.execGeneration &&
        a.procUniqueID == b.procUniqueID && a.task == b.task && a.map == b.map;
}
inline bool exact(const Policy &p, const Target &t) {
    const auto &i = t.identity;
    return p.bootNonce && i.bootNonce == p.bootNonce && i.execGeneration && i.procUniqueID && i.task && i.map &&
        t.uid == 501 && t.path && !strcmp(t.path, TargetPath) && t.trustedSignature &&
        !memcmp(t.executableUUID, p.executableUUID, 16);
}
inline void clear(State &s) {
    s.binding = {}; s.armed = false; s.recorded = false; s.observation = Observation::Unknown;
}
// Only an authenticated new-exec event may arm. Discovery of an existing task may not.
inline bool onExec(State &s, const Policy &p, const Target &t, bool newExecEvent) {
    bool fresh = newExecEvent && t.identity.execGeneration > s.lastExecGeneration;
    if (newExecEvent && t.identity.bootNonce == p.bootNonce && t.identity.execGeneration > s.lastExecGeneration)
        s.lastExecGeneration = t.identity.execGeneration;
    if (s.armed && t.identity.procUniqueID != s.binding.procUniqueID) {
        // Preserve the incumbent. A second target is rejected, never substituted.
        return false;
    }
    clear(s);
    if (!fresh || !exact(p, t)) return false;
    s.binding = t.identity; s.armed = true; return true;
}
inline void onExit(State &s, const Identity &i) {
    if (same(s.binding, i)) clear(s);
}
// Call when the bound target changes identity/credentials/image, including exec.
inline void targetChanged(State &s) { clear(s); }
inline bool observe(State &s, const Policy &p, const Target &t, const Check &c) {
    if (!s.armed) return false;
    if (t.identity.procUniqueID != s.binding.procUniqueID) return false;
    if (!same(s.binding, t.identity) || !exact(p, t)) { clear(s); return false; }
    if (s.recorded || c.status || !c.outputArgumentNonNull || c.specialArgument ||
        !c.outputReadSucceeded || !c.cacheAddressNonZero) return false;
    switch (c.observation) {
        case Observation::Cold: case Observation::CompletedEmpty:
        case Observation::Live: case Observation::Initializing: break;
        default: return false;
    }
    s.recorded = true; s.observation = c.observation;
    return true;
}
} // namespace NativeStartupObservation
