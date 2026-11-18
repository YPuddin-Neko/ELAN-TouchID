#pragma once
#include "Admission.h"
#include "../../early-shared-region/NativePinnedBinaryIdentity.h"
namespace StartupWriteBinding {
bool configure(NativePinnedBinaryIdentity::Resolve,void*,uint64_t,const uint8_t*);
bool admissionAPI(CallerEvidence::Copy,void*,StartupAdmission::API&);
}
