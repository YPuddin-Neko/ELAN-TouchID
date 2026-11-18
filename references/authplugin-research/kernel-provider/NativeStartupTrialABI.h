#pragma once
#include <stdint.h>

static constexpr const char *NativeStartupTrialWriterService = "ELANStartupWriteCandidate";
static constexpr const char *NativeStartupTrialRetireFunction = "ELANStartupTrialRetireCommittedTask";
static constexpr const char *NativeStartupTrialLeaseFunction = "ElanStartupTrialLease";
enum NativeStartupTrialLeaseOperation : uint32_t {
    NativeStartupTrialLeasePeek = 0, NativeStartupTrialLeaseAcquire = 1, NativeStartupTrialLeaseCheck = 2, NativeStartupTrialLeaseFinish = 3
};
enum NativeStartupTrialLeaseOutcome : uint32_t {
    NativeStartupTrialLeaseClean = 0, NativeStartupTrialLeaseCommitted = 1,
    NativeStartupTrialLeaseRetired = 2, NativeStartupTrialLeaseRecoveryRequired = 3
};
// Kernel-only callPlatformFunction parameter1. No task, PID, address or write data
// can be supplied through this interface. Acquire returns its opaque gate token.
struct NativeStartupTrialLeaseRequest {
    uint32_t abi;
    uint32_t operation;
    uint64_t token;
    uint32_t outcome;
    uint32_t reserved;
};
struct NativeStartupTrialRequest { uint32_t abi; uint32_t user; uint64_t nonce; };
struct NativeStartupTrialReport {
    uint32_t abi;
    int32_t status;
    uint32_t armed;
    uint32_t inFlight;
    uint32_t cancelled;
    uint32_t recoveryRequired;
    uint64_t nonce;
};
static_assert(sizeof(NativeStartupTrialLeaseRequest) == 24, "startup lease ABI");
static_assert(sizeof(NativeStartupTrialRequest) == 16, "startup trial request ABI");
static_assert(sizeof(NativeStartupTrialReport) == 32, "startup trial report ABI");
