#pragma once
#include <stdint.h>
// Candidate-only policy, not the legacy Apple-binary policy. Exact UUID/path/CDHash
// checks remain mandatory. Constants from MacKernelSDK kern/cs_blobs.h.
inline bool candidateSigningAllowed(uint64_t flags){
 const uint64_t required=0x20010001ULL; // CS_SIGNED | CS_RUNTIME | CS_VALID
 const uint64_t forbidden=0x10000024ULL; // CS_DEBUGGED | CS_INVALID_ALLOWED | CS_GET_TASK_ALLOW
 return (flags&required)==required && !(flags&forbidden);
}
