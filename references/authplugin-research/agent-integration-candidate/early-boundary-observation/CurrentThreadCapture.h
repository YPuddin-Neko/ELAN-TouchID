#pragma once
#include "CallerEvidence.h"
namespace CurrentThreadCapture {
enum class Stage:uint32_t {NoCurrentThread,GetStateFailed,UnexpectedCount,Captured};
struct Result {Stage stage=Stage::NoCurrentThread;int status=0;uint32_t count=0;CallerEvidence::Result caller{};};
// Outer callback must own/revalidate the exact process/task identity. No PID or
// arbitrary thread can be supplied. The copy adapter must read this current task.
bool configurePinned(uintptr_t currentThread,uintptr_t getState);
Result inspectPinned(CallerEvidence::Copy copy,void*context,uint64_t syscallOutputAddress);
Result inspect(CallerEvidence::Copy copy,void*context,uint64_t syscallOutputAddress);
}
