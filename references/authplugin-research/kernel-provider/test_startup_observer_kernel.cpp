#include "NativeStartupObserverKernel.h"
#include <assert.h>
#include <stdio.h>
static kauth_listener token;
static int starts=0,stops=0;
static bool fail=false;
static kauth_scope_callback_t callback=nullptr;
kauth_listener_t kauth_listen_scope(const char *,kauth_scope_callback_t cb,void *context) {
    assert(!context); ++starts; callback=cb; return fail ? nullptr : &token;
}
void kauth_unlisten_scope(kauth_listener_t value) { assert(value==&token); ++stops; }
int main() {
    using namespace NativeStartupObserverKernel;
    assert(!start() && !snapshot().enabled && starts==0);
    stop(); assert(stops==0);
    fail=true; assert(!start(true) && !snapshot().enabled);
    fail=false; assert(start(true) && start(true) && starts==2);
    assert(callback(nullptr,nullptr,KAUTH_FILEOP_EXEC,0,0,0,0)==KAUTH_RESULT_DEFER);
    assert(callback(nullptr,nullptr,0,0,0,0,0)==KAUTH_RESULT_DEFER);
    auto r=snapshot(); assert(r.execNotifications==1 && r.enabled);
    assert(!r.targetBound && !r.signatureVerified && !r.sharedRegionObserved);
    stop(); stop(); assert(stops==1);
    callback(nullptr,nullptr,KAUTH_FILEOP_EXEC,0,0,0,0);
    assert(snapshot().execNotifications==1 && !snapshot().enabled);
    puts("observer shim: disabled default, registration failure, idempotent lifecycle, DEFER and truthful partial report passed");
}
