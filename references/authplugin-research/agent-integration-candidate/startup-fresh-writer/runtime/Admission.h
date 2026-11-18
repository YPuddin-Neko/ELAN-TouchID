#pragma once
#include "../../exec-generation-observation/ExecGeneration.h"
#include "../../exec-generation-observation/MainImageBase.h"
#include "../../early-boundary-observation/CurrentThreadCapture.h"
#include "../../settings-fresh-observation/SettingsSample.h"
#include "../../early-shared-region/CurrentCopyinSample.h"
#include "../../map-cow-observation/LeafCowSample.h"
#include "../../../kernel-provider/NativeLateCacheBase.h"
namespace StartupAdmission {
struct API {
 ExecGeneration::API generation;
 void*threadContext=nullptr;
 void*(*currentThread)(void*)=nullptr;
 uint16_t(*threadTag)(void*,void*)=nullptr;
 MainImageBase::Layout layout;
 MainImageBase::Read kernelRead=nullptr;void*kernelContext=nullptr;
 CallerEvidence::Copy copy=nullptr;void*copyContext=nullptr;
 CurrentThreadCapture::Result(*caller)(CallerEvidence::Copy,void*,uint64_t)=nullptr;
 SettingsSample::Result(*settings)(SettingsSample::Copy,void*,uint64_t)=SettingsSample::inspect;
 LeafCowSample::Result(*leaf)(void*,uint64_t)=nullptr;
 CurrentCopyinSample::Result(*outer)(CurrentCopyinSample::Reader,uint64_t)=CurrentCopyinSample::inspect;
 CurrentCopyinSample::Result(*outerBase)(CurrentCopyinSample::Reader,uint64_t)=CurrentCopyinSample::inspectKnownBase;
};
enum class Stage:uint32_t {MissingAPI,WrongThread,Generation,MainBase,Caller,Settings,Outer,FinalIdentity,Complete};
struct Result {Stage stage=Stage::MissingAPI;bool jointlyCold=false,mainThread=false,generationBefore=false,mainBaseBefore=false,callerMatched=false,generationAfter=false,mainBaseAfter=false;CallerEvidence::Profile profile=CallerEvidence::Profile::Unknown;CurrentThreadCapture::Result callerResult{};SettingsSample::Result settingsResult{};CurrentCopyinSample::Result outerResult{};LeafCowSample::Result leafResult{};bool leafAttempted=false;uint32_t userCopies=0,userBytes=0;};
struct Receipt {ExecGeneration::Stamp generation{};void* thread=nullptr;uint64_t mainBase=0,cacheBase=0;bool accepted=false;};
struct CopyBudget{CallerEvidence::Copy copy;void*context;Result&result;};
inline int budgetCopy(void*c,uint64_t address,void*out,size_t n){auto&b=*static_cast<CopyBudget*>(c);if(!n||b.result.userCopies>=179||n>6618-b.result.userBytes)return 14;++b.result.userCopies;b.result.userBytes+=uint32_t(n);return b.copy(b.context,address,out,n);}
struct OuterCopyContext{CallerEvidence::Copy copy;void*context;uint64_t output,base=0;bool sawBase=false;};
inline int outerCopy(void*c,uint64_t address,void*out,size_t n){auto&s=*static_cast<OuterCopyContext*>(c);int status=s.copy(s.context,address,out,n);if(!status&&address==s.output&&n==8){memcpy(&s.base,out,8);s.sawBase=true;}return status;}
// Owner must pin all API/layout evidence and run inside the existing exact
// proc/vnode identity capture. Receipt remains private to that callback; its
// proc is borrowed, never usable after identity guards unwind.
inline Result inspect(const API&a,void*referencedProc,void*borrowedCurrentTask,uint64_t syscallOutput,Receipt&receipt){
 receipt={};Result out{};
 if(!a.currentThread||!a.threadTag||!a.kernelRead||!a.copy||!a.caller||!a.settings||!a.outer||!a.leaf||!a.layout.verified)return out;
 out.stage=Stage::WrongThread;void*thread=a.currentThread(a.threadContext);
 if(!thread||!(a.threadTag(a.threadContext,thread)&1))return out;
 out.mainThread=true;out.stage=Stage::Generation;ExecGeneration::Stamp before{};
 if(ExecGeneration::sample(a.generation,referencedProc,borrowedCurrentTask,before)!=ExecGeneration::Outcome::Stable)return out;
 out.generationBefore=true;out.stage=Stage::MainBase;auto main=MainImageBase::inspect(a.layout,a.kernelRead,a.kernelContext,reinterpret_cast<uint64_t>(borrowedCurrentTask));
 if(main.outcome!=MainImageBase::Outcome::Observed)return out;
 CopyBudget budget{a.copy,a.copyContext,out};
 out.mainBaseBefore=true;out.stage=Stage::Caller;auto caller=a.caller(budgetCopy,&budget,syscallOutput);
 out.callerResult=caller;
 if(caller.stage!=CurrentThreadCapture::Stage::Captured||caller.caller.stage!=CallerEvidence::Stage::Matched)return out;
 out.callerMatched=true;out.stage=Stage::Settings;auto settings=a.settings(budgetCopy,&budget,main.base);
 out.settingsResult=settings;
 if(settings.stage!=SettingsSample::Stage::Complete)return out;
 out.stage=Stage::Outer;OuterCopyContext copied{budgetCopy,&budget,syscallOutput};CurrentCopyinSample::Result outer{};
 if(syscallOutput==UINT64_MAX){
  if(!a.outerBase||!NativeLateCacheBase::derive(caller.caller,copied.base))return out;
  outer=a.outerBase({&budget,budgetCopy},copied.base);copied.sawBase=outer.stage==CurrentCopyinSample::Stage::Complete;
 }else{outer=a.outer({&copied,outerCopy},syscallOutput);}
 out.outerResult=outer;
 if(outer.stage!=CurrentCopyinSample::Stage::Complete)return out;
 if(!copied.sawBase||copied.base<0x7ff800000000ULL||copied.base-0x7ff800000000ULL>0x1ae68000ULL)return out;
 // The exact outer parser validated this last output read and its derived image.
 out.leafAttempted=true;out.leafResult=a.leaf(borrowedCurrentTask,copied.base+0x10a5b0000ULL+0x38e1b028ULL);
 out.stage=Stage::FinalIdentity;
 if(a.currentThread(a.threadContext)!=thread||!(a.threadTag(a.threadContext,thread)&1)||ExecGeneration::revalidate(a.generation,before)!=ExecGeneration::Outcome::Stable)return out;
 out.generationAfter=true;auto mainAfter=MainImageBase::inspect(a.layout,a.kernelRead,a.kernelContext,reinterpret_cast<uint64_t>(borrowedCurrentTask));
 if(mainAfter.outcome!=MainImageBase::Outcome::Observed||mainAfter.base!=main.base)return out;
 out.mainBaseAfter=true;out.stage=Stage::Complete;out.profile=caller.caller.profile;
 out.jointlyCold=settings.state==SettingsSample::State::Cold&&outer.state==CurrentCopyinSample::State::NotStarted&&!outer.checked&&!outer.result;
 if(out.jointlyCold&&out.leafResult.cow()){receipt={before,thread,main.base,copied.base,true};}
 return out;
}
}
