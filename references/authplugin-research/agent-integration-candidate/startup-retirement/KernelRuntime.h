#pragma once
#include "ExactTaskRetirement.h"
#include "RemoteTaskRetirement.h"
#include "ExactRuntimePins.h"
namespace RetirementRuntime {
bool configure(RetirementPins::Resolve,void*,uint64_t,const uint8_t*);
bool configured();
ExactTaskRetirement::Result admitCurrent(ExactTaskRetirement::Ticket&);
void cancelClean(ExactTaskRetirement::Ticket&);
// The caller MUST exit its proc/vnode/map-owning lexical scopes first. This
// adapter owns no such resources and accepts no caller-provided cleanup promise.
ExactTaskRetirement::Result retireAfterOuterScope(ExactTaskRetirement::Ticket&);
bool retainRemote(void*,ExactTaskRetirement::RemoteTicket&);
bool duplicateCurrent(const ExactTaskRetirement::Ticket&,ExactTaskRetirement::RemoteTicket&);
bool releaseRemoteClean(ExactTaskRetirement::RemoteTicket&);
ExactTaskRetirement::Result retireRemote(ExactTaskRetirement::RemoteTicket&);
}
