#pragma once
#include <stdint.h>

// Protected by the provider state mutex. Tokens come from NativeOperationGate;
// this state alone never grants an operation or permission to write.
class NativeStartupTrialState {
    uint64_t owner_ = 0, nonce_ = 0, token_ = 0;
    bool armed_ = false, cancelled_ = false;
public:
    bool arm(uint64_t owner, uint64_t nonce) {
        if (!owner || !nonce || token_ || (owner_ == owner && nonce_ == nonce)) return false;
        owner_ = owner; nonce_ = nonce; armed_ = true; cancelled_ = false;
        return true;
    }
    bool reserve(uint64_t owner, uint64_t token) {
        if (!armed_ || cancelled_ || token_ || owner != owner_ || !token) return false;
        token_ = token; return true;
    }
    bool acquired(uint64_t token, uint64_t owner) {
        if (!valid(token, owner) || !armed_) return false;
        armed_ = false; return true;
    }
    bool valid(uint64_t token, uint64_t owner) const {
        return token && token == token_ && owner == owner_ && !cancelled_;
    }
    bool cancel(uint64_t owner, uint64_t nonce) {
        if (!owner || owner != owner_ || nonce != nonce_) return false;
        armed_ = false; cancelled_ = true; return true;
    }
    void invalidate(uint64_t owner) {
        if (owner == owner_) { armed_ = false; cancelled_ = true; }
    }
    bool finish(uint64_t token, uint64_t owner) {
        if (!token || token != token_ || owner != owner_) return false;
        token_ = 0; return true;
    }
    uint64_t owner() const { return owner_; }
    uint64_t nonce() const { return nonce_; }
    uint64_t token() const { return token_; }
    bool armed() const { return armed_; }
    bool cancelled() const { return cancelled_; }
};
