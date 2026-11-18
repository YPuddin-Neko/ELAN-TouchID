#include "NativeSettingsStartupDiagnostics.h"
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>
int main(){using namespace NativeSettingsStartupDiagnostics;State s;
 assert(s.snapshot()==(uint64_t{1}<<56)&&!s.count()&&!s.successes());
 s.record(Event::AdmissionRejected,8,5,7,9,255,true,false,true,10);
 auto w=s.snapshot();assert((w&255)==3&&((w>>8)&255)==8&&((w>>16)&255)==5&&((w>>24)&255)==7&&((w>>32)&255)==9);
 assert(((w>>40)&255)==255&&((w>>48)&7)==5&&((w>>51)&31)==10&&(w>>56)==1);
 std::vector<std::thread> jobs;for(unsigned i=0;i<4;++i)jobs.emplace_back([&]{for(unsigned n=0;n<1000;++n)s.record(Event::RouteReturned,0,0,0,0,1);});for(auto&t:jobs)t.join();
 assert(s.count()==4001&&s.successes()==4000);s.attempts=UINT32_MAX;s.routed=UINT32_MAX;s.record(Event::RouteReturned,0,0,0,0,1);assert(s.count()==UINT32_MAX&&s.successes()==UINT32_MAX);
 puts("Startup diagnostics scalar schema, concurrent updates and saturation passed");}
