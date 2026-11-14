#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>
#include <libproc.h>
#include <dlfcn.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <notify.h>
#include "native-provider-client.h"
#include "native-settings-session.h"
#include "native-user-session-darwin.h"
#include "native-power-observer.h"
#include "native-controller-lease.h"
#include "native-provider-interface.h"
#include "native-catalog-view.h"
#include "native-provider-peer.h"
#import "../../elan-fingerprint-macos/src/ElanFingerprintSession.h"
#import "../../elan-fingerprint-macos/src/ElanFingerprintEnrollment.h"
#include "native-enrollment-progress.h"
#include "native-enrollment-request.h"
#include "native-protected-configuration.h"
#define main elan_diagnostic_main
#include "../../elan-fingerprint-macos/src/elan_match_test.c"
#undef main
#include "../../elan-fingerprint-macos/src/ElanFingerprintStore.inc"
#include "../../elan-fingerprint-macos/src/ElanEnrollmentCapture.inc"
#include "test-enrollment-capture.inc"
static volatile sig_atomic_t providerInterrupted;
static volatile sig_atomic_t providerPowerStopped;
static void providerInterrupt(int signum) { providerInterrupted = 1; interrupt(signum); }
static void providerPowerStop(void) { providerPowerStopped = 1; providerInterrupted = 1; cancelled = 1; }

@interface NSObject (ElanProviderCallbacks)
- (void)matchResult:(id)identity details:(NSDictionary *)details client:(uint64_t)client;
- (void)enrollResult:(id)identity details:(NSDictionary *)details client:(uint64_t)client;
- (void)statusMessage:(unsigned int)status client:(uint64_t)client;
@end

@interface ElanNativeEnrollmentRun : NSObject
@property(nonatomic, copy) NSData *context;
@property(nonatomic) ElanFingerprintEnrollment *draft;
@property(nonatomic) ElanFingerprintSupplement *supplement;
@property(nonatomic) dispatch_semaphore_t continuation;
@property(nonatomic) uint64_t client;
@property(nonatomic) BOOL waiting;
@property(nonatomic) BOOL calibrating;
@property(nonatomic) NSInteger presence;
@end
@implementation ElanNativeEnrollmentRun
@end

@class ElanProviderConnection;
@interface ElanProviderController : NSObject <NSXPCListenerDelegate>
@property(nonatomic) int broker;
@property(nonatomic, strong) ElanFingerprintRepository *repository;
@property(nonatomic, strong) ElanFingerprintSession *session;
@property(nonatomic, readonly) ElanFingerprintMatcher *matcher;
@property(nonatomic, strong) id accessory;
@property(nonatomic, strong) NSMutableArray<NSXPCConnection *> *connections;
@property(nonatomic, strong) dispatch_queue_t captureQueue;
@property(nonatomic, strong) dispatch_group_t captureGroup;
@property(nonatomic, weak) ElanProviderConnection *current;
@property(nonatomic) uint64_t sequence;
@property(nonatomic) uint64_t activeClient;
@property(nonatomic) BOOL busy;
@property(atomic) BOOL stopping;
@property(nonatomic) NativeUserSessionState userSession;
- (BOOL)sessionIsCurrent;
- (BOOL)observeSession:(NativeUserSessionSnapshot)snapshot;
@end

@interface ElanProviderConnection : NSObject
@property(nonatomic, weak) ElanProviderController *controller;
@property(nonatomic, strong) NSXPCConnection *connection;
@property(nonatomic) uint64_t client;
@property(nonatomic) ElanNativeEnrollmentRun *enrollment;
- (void)cancelCurrent;
- (void)cancelClient:(uint64_t)client;
- (void)reportEnrollmentTouch:(BOOL)present;
- (void)reportEnrollmentCaptureEvent:(ElanCaptureEvent)event;
@end

static __weak ElanProviderConnection *enrollmentCaptureOwner;
static void enrollmentCaptureEvent(ElanCaptureEvent event) { [enrollmentCaptureOwner reportEnrollmentCaptureEvent:event]; }
static int enrollmentShouldCancel(void) {
    ElanProviderConnection *owner = enrollmentCaptureOwner;
    return !owner || owner.controller.stopping || cancelled;
}

static NSUUID *managedIdentityUUID(id identity) {
    if (![identity isKindOfClass:NSClassFromString(@"BiometricKitIdentity")] ||
        ![[identity valueForKey:@"userID"] isEqual:@501] || ![[identity valueForKey:@"type"] isEqual:@1]) return nil;
    id uuid = [identity valueForKey:@"uuid"];
    return [uuid isKindOfClass:NSUUID.class] ? uuid : nil;
}

@implementation ElanProviderController
- (ElanFingerprintMatcher *)matcher { return self.session.matcher; }
- (BOOL)sessionIsCurrent {
    @synchronized (self) {
        if (providerInterrupted) {
            self.stopping = YES; cancelled = 1; [self.current cancelCurrent];
            return NO;
        }
        return [self observeSession:nativeReadUserSession(self.userSession.coreauth.pid)];
    }
}
- (BOOL)observeSession:(NativeUserSessionSnapshot)snapshot {
    @synchronized (self) {
        NativeUserSessionState state = self.userSession;
        NativeSessionStatus status = nativeSessionObserve(&state, snapshot);
        self.userSession = state;
        if (status) {
            if (!self.stopping) printf("ELAN_PROVIDER session_stopped=%u\n", status);
            self.stopping = YES; cancelled = 1;
            [self.current cancelCurrent];
        }
        return status == NativeSessionCurrent;
    }
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    unsigned permissions = nativePeerPermissions(connection);
    if (self.stopping || !(permissions & NativePeerRead) || ![self sessionIsCurrent]) return NO;
    ElanProviderConnection *server = [ElanProviderConnection new];
    server.controller = self; server.connection = connection;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitXpcProtocol")];
    connection.exportedObject = server;
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitDelegateXpcProtocol")];
    Class identityClass = NSClassFromString(@"BiometricKitIdentity");
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, identityClass, nil]
                                forSelector:@selector(identities:client:replyBlock:) argumentIndex:0 ofReply:YES];
    [connection.exportedInterface setClasses:[NSSet setWithObject:identityClass]
                                forSelector:NSSelectorFromString(@"getIdentityFromUUID:client:replyBlock:") argumentIndex:0 ofReply:YES];
    for (NSString *name in @[@"updateIdentity:options:async:client:replyBlock:", @"removeIdentity:options:async:client:replyBlock:"])
        [connection.exportedInterface setClasses:[NSSet setWithObject:identityClass]
                                    forSelector:NSSelectorFromString(name) argumentIndex:0 ofReply:NO];
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, NSClassFromString(@"BiometricKitAccessory"), nil]
                                forSelector:@selector(listAccessories:replyBlock:) argumentIndex:1 ofReply:YES];
    configureNativeMatchQuery(connection.exportedInterface);
    [connection.remoteObjectInterface setClasses:[NSSet setWithObject:identityClass]
                                    forSelector:@selector(matchResult:details:client:) argumentIndex:0 ofReply:NO];
    [connection.remoteObjectInterface setClasses:[NSSet setWithObjects:NSDictionary.class, NSNumber.class, NSString.class, nil]
                                    forSelector:@selector(matchResult:details:client:) argumentIndex:1 ofReply:NO];
    [connection.remoteObjectInterface setClasses:[NSSet setWithObject:identityClass]
                                    forSelector:@selector(enrollResult:details:client:) argumentIndex:0 ofReply:NO];
    __weak ElanProviderConnection *weakServer = server;
    __weak ElanProviderController *weakSelf = self;
    __weak NSXPCConnection *weakConnection = connection;
    connection.invalidationHandler = ^{
        [weakServer cancelCurrent];
        ElanProviderController *controller = weakSelf;
        @synchronized (controller) { [controller.connections removeObject:weakConnection]; }
        weakServer.connection = nil;
    };
    @synchronized (self) { [self.connections addObject:connection]; }
    printf("ELAN_PROVIDER accepted_peer=%d permissions=%u\n", connection.processIdentifier, permissions);
    [connection resume];
    return YES;
}
@end

@implementation ElanProviderConnection
- (void)connect:(NSDictionary *)options client:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.client = client;
    reply(self.controller.stopping ? 1 : 0);
}
- (void)disconnect:(uint64_t)client replyBlock:(void (^)(int))reply { [self cancelClient:client]; reply(0); }
- (void)registerDelegate:(BOOL)enabled client:(uint64_t)client replyBlock:(void (^)(int))reply { reply(0); }
- (void)getDeviceHardwareState:(uint64_t)client replyBlock:(void (^)(int, unsigned int))reply { reply(0, 0); }
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply {
    reply(self.controller.stopping ? 1 : 0, self.controller.stopping ? @[] : @[self.controller.accessory]);
}
- (void)getBioLockoutStateForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(int, uint64_t))reply {
    reply(user == 501 && !self.controller.stopping ? 0 : 1, NativeProviderDeviceReady);
}
- (void)getIdentitiesDatabaseHashForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSData *))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) { reply(user == 501 && !controller.stopping ? controller.repository.current.databaseState : nil); }
}
- (void)getBiometryAvailabilityForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(int, NSInteger))reply {
    reply(0, user == 501 && !self.controller.stopping ? 1 : 0);
}
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        NSArray *identities = controller.stopping ? @[] : nativeCatalogIdentities(controller.repository.current, query);
        printf("ELAN_PROVIDER catalog_read peer=%d count=%lu\n", self.connection.processIdentifier, identities.count);
        reply(identities);
    }
}
- (void)getMaxIdentityCount:(int)type client:(uint64_t)client replyBlock:(void (^)(NSInteger))reply {
    reply(type == 0 && !self.controller.stopping ? ElanCatalogMaximumIdentities : 0);
}
- (void)getFreeIdentityCount:(int)type user:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSInteger))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        reply(type == 0 && user == 501 && !controller.stopping ? ElanCatalogMaximumIdentities - controller.repository.current.records.count : 0);
    }
}
- (void)getIdentityFromUUID:(NSUUID *)uuid client:(uint64_t)client replyBlock:(void (^)(id))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanFingerprintRecord *record = [controller.repository.current recordForUUID:uuid];
        reply(controller.stopping ? nil : nativeIdentityForRecord(record, 501));
    }
}
- (void)performCatalogMutation:(ElanFingerprintCatalog *(^)(ElanFingerprintCatalog *, NSError **))mutation
                         action:(NSString *)action uuid:(NSUUID *)uuid client:(uint64_t)client reply:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    if (!(nativePeerPermissions(self.connection) & NativePeerManage)) { reply(1); return; }
    @synchronized (controller) {
        if (controller.stopping || controller.busy || !controller.session || controller.session.invalidated) { reply(1); return; }
        controller.busy = YES; controller.current = self; controller.activeClient = client; cancelled = 0;
    }
    dispatch_group_async(controller.captureGroup, controller.captureQueue, ^{
        @autoreleasepool {
            BOOL allowed;
            @synchronized (controller) { allowed = !cancelled && !controller.stopping && controller.current == self; }
            allowed = allowed && (nativePeerPermissions(self.connection) & NativePeerManage) && [controller sessionIsCurrent];
            NSError *error = nil;
            BOOL saved = NO;
            NSUInteger before = controller.repository.current.records.count;
            if (allowed) {
                ElanFingerprintCatalog *previous = controller.repository.current;
                ElanFingerprintCatalog *candidate = mutation(previous, &error);
                saved = candidate && [controller.session commit:candidate replacing:previous error:&error];
            }
            @synchronized (controller) {
                if (controller.session.invalidated) controller.stopping = YES;
                if (saved) {
                    NSData *background = controller.matcher.background;
                    if (background) memcpy(sensor.bg, background.bytes, background.length);
                    else memset(sensor.bg, 0, (size_t)sensor.w * sensor.hgt * sizeof(*sensor.bg));
                }
                controller.current = nil; controller.activeClient = 0; controller.busy = NO;
            }
            printf("ELAN_PROVIDER catalog_mutation action=%s uuid=%s before=%lu after=%lu saved=%d invalidated=%d error=%s:%ld\n",
                action.UTF8String, uuid ? uuid.UUIDString.UTF8String : "all", before, controller.repository.current.records.count,
                saved, controller.session.invalidated, error ? error.domain.UTF8String : "none", (long)error.code);
            reply(saved ? 0 : 1);
        }
    });
}
- (void)updateIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    NSUUID *uuid = managedIdentityUUID(identity);
    if (!uuid) { reply(1); return; }
    NSString *name = [[identity valueForKey:@"name"] copy];
    [self performCatalogMutation:^ElanFingerprintCatalog *(ElanFingerprintCatalog *catalog, NSError **error) {
        return [catalog renamingUUID:uuid name:name error:error];
    } action:@"rename" uuid:uuid client:client reply:reply];
}
- (void)removeIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    NSUUID *uuid = managedIdentityUUID(identity);
    if (!uuid) { reply(1); return; }
    [self performCatalogMutation:^ElanFingerprintCatalog *(ElanFingerprintCatalog *catalog, NSError **error) {
        return [catalog removingUUID:uuid error:error];
    } action:@"remove" uuid:uuid client:client reply:reply];
}
- (void)removeAllIdentitiesForUser:(unsigned int)user options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (user != 501) { reply(1); return; }
    [self performCatalogMutation:^ElanFingerprintCatalog *(ElanFingerprintCatalog *catalog, NSError **error) {
        return [catalog removingAll:error];
    } action:@"remove-all" uuid:nil client:client reply:reply];
}
#include "native-provider-enrollment.inc"
#include "native-provider-configuration.inc"
- (void)cancelCurrent {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        BOOL applies = controller.current == self;
        printf("ELAN_PROVIDER connection_cancel active_client=%llu applies=%d\n", controller.activeClient, applies);
        if (applies) { cancelled = 1; if (self.enrollment.continuation) dispatch_semaphore_signal(self.enrollment.continuation); }
    }
}
- (void)cancelClient:(uint64_t)client {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        BOOL applies = controller.current == self && controller.activeClient == client;
        printf("ELAN_PROVIDER client_cancel client=%llu active_client=%llu applies=%d\n", client, controller.activeClient, applies);
        if (applies) { cancelled = 1; if (self.enrollment.continuation) dispatch_semaphore_signal(self.enrollment.continuation); }
    }
}
- (void)cancel:(uint64_t)client replyBlock:(void (^)(int))reply { [self cancelClient:client]; reply(0); }
- (void)logEventOrCode:(uint64_t)code { printf("ELAN_PROVIDER event=%llu\n", (unsigned long long)code); }
- (void)doesNotRecognizeSelector:(SEL)selector {
    printf("ELAN_PROVIDER unsupported_selector=%s\n", sel_getName(selector));
    [super doesNotRecognizeSelector:selector];
}
- (void)match:(id)query options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if ([options[@"BKOptionMatchForExtendEnrollment"] boolValue]) {
        [self extendEnrollment:query options:options client:client replyBlock:reply]; return;
    }
    ElanProviderController *controller = self.controller;
    id value = options[@"BKOptionMatchForCredentialSet"];
    BOOL contextValid = [value isKindOfClass:NSData.class] && [value length] == 16;
    BOOL unlock = [options[@"BKOptionMatchForUnlock"] boolValue];
    BOOL peerValid = (nativePeerPermissions(self.connection) & NativePeerMatch) != 0;
    id userFilter = [query isKindOfClass:NSDictionary.class] ? query[@"BKFilterUserID"] : nil;
    BOOL userValid = !userFilter || ([userFilter isKindOfClass:NSNumber.class] && [userFilter isEqual:@501]);
    printf("ELAN_PROVIDER match_request client=%llu query_class=%s context_valid=%d unlock=%d peer_valid=%d\n",
           client, object_getClassName(query), contextValid, unlock, peerValid);
    if (!contextValid || unlock || !peerValid || !userValid) { reply(1); return; }
    NSData *context = [value copy];
    ElanFingerprintMatcher *matcher;
    @synchronized (controller) {
        matcher = controller.matcher;
        if (controller.stopping || controller.busy || !nativeIdentificationEnabled(matcher) || ![controller sessionIsCurrent]) { reply(1); return; }
        controller.busy = YES; controller.current = self; controller.activeClient = client; cancelled = 0;
    }
    reply(0);
    dispatch_group_async(controller.captureGroup, controller.captureQueue, ^{
        @autoreleasepool {
            for (unsigned attempt = 0; attempt < 5 && !cancelled && !controller.stopping; attempt++) {
                double began = capture_milliseconds();
                ElanpressFeatures *features = capture(&sensor);
                printf("ELAN_PROVIDER capture_end client=%llu features=%u cancelled=%d elapsed_ms=%.0f\n",
                       client, features ? features->n : 0, cancelled, capture_milliseconds() - began);
                if (!features) {
                    if (!cancelled) { controller.stopping = YES; [self.connection invalidate]; }
                    break;
                }
                unsigned score = 0;
                ElanFingerprintRecord *record = [matcher bestRecordForFeatures:features score:&score];
                wipe(features->kp, features->n * sizeof(ElanpressKeypoint));
                elanpress_features_free(features);
                BOOL matched = score >= ELANPRESS_MATCH_MIN_PAIRS;
                @synchronized (controller) {
                    if (cancelled || controller.stopping || controller.current != self || ![controller sessionIsCurrent]) break;
                    if (!record || controller.matcher != matcher) { controller.stopping = YES; [self.connection invalidate]; break; }
                    uuid_t identityBytes; [record.uuid getUUIDBytes:identityBytes];
                    uint64_t sequence = ++controller.sequence;
                    int status = elanProviderMatch(controller.broker, sequence, identityBytes,
                                                    context.bytes, matched);
                    printf("ELAN_PROVIDER match_score=%u actual_match=%d kernel_status=%d\n", score, matched, status);
                    if (status) { controller.stopping = YES; [self.connection invalidate]; break; }
                    id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                        printf("ELAN_PROVIDER callback_error=%ld\n", (long)error.code);
                        controller.stopping = YES;
                    }];
                    [remote matchResult:matched ? nativeIdentityForRecord(record, 501) : nil
                                details:nativeProviderMatchDetails(matched) client:client];
                }
                if (matched) break;
                if (attempt == 4) { controller.stopping = YES; [self.connection invalidate]; }
            }
            @synchronized (controller) { controller.current = nil; controller.activeClient = 0; controller.busy = NO; }
        }
    });
}
@end

static int cancellationSelfTest(void) {
    ElanProviderController *controller = [ElanProviderController new];
    ElanProviderConnection *connection = [ElanProviderConnection new];
    connection.controller = controller;
    controller.current = connection;
    controller.activeClient = 10;
    cancelled = 0;
    [connection cancelClient:9];
    BOOL unrelatedPreserved = !cancelled;
    [connection cancelClient:10];
    BOOL currentCancelled = cancelled != 0;
    controller.activeClient = 11; cancelled = 0;
    [connection disconnect:10 replyBlock:^(int status) {}];
    BOOL nextPreserved = !cancelled;
    [connection cancelCurrent];
    BOOL invalidationCancelled = cancelled != 0;
    cancelled = 0;
    BOOL passed = unrelatedPreserved && currentCancelled && nextPreserved && invalidationCancelled;
    printf("PROVIDER_CANCEL_TEST unrelated_preserved=%d current_cancelled=%d next_preserved=%d invalidation_cancelled=%d passed=%d\n",
           unrelatedPreserved, currentCancelled, nextPreserved, invalidationCancelled, passed);
    return passed ? 0 : 1;
}

@interface ElanEnrollmentCallbackFixture : NSObject
@property(nonatomic, copy) void (^handler)(NSError *);
@end
@implementation ElanEnrollmentCallbackFixture
- (id)remoteObjectProxyWithErrorHandler:(void (^)(NSError *))handler { self.handler = handler; return self; }
@end

static int enrollmentControlSelfTest(void) {
    ElanProviderController *controller = [ElanProviderController new];
    ElanProviderConnection *connection = [ElanProviderConnection new]; connection.controller = controller;
    ElanNativeEnrollmentRun *run = [ElanNativeEnrollmentRun new];
    run.client = 55; run.waiting = YES; run.continuation = dispatch_semaphore_create(0);
    connection.enrollment = run; controller.current = connection; controller.activeClient = 55; controller.busy = YES; cancelled = 0;
    __block int status = -1;
    [connection enrollContinue:54 replyBlock:^(int result) { status = result; }];
    BOOL wrongClient = status && run.waiting && dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW) != 0;
    [connection completeEnrollment:55 replyBlock:^(int result) { status = result; }];
    BOOL incomplete = status && run.waiting;
    [connection enrollContinue:55 replyBlock:^(int result) { status = result; }];
    BOOL continued = !status && !run.waiting && !dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW);
    [connection enrollContinue:55 replyBlock:^(int result) { status = result; }];
    BOOL duplicate = status && dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW) != 0;
    run.waiting = YES;
    [connection cancelClient:54];
    BOOL unrelatedCancel = !cancelled && dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW) != 0;
    [connection cancelClient:55];
    BOOL wokeCancel = cancelled && !dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW);
    [connection enrollContinue:55 replyBlock:^(int result) { status = result; }];
    BOOL cancelledRejected = status != 0;
    cancelled = 0;
    ElanEnrollmentCallbackFixture *callback = [ElanEnrollmentCallbackFixture new];
    connection.connection = (id)callback;
    (void)[connection enrollmentRemote];
    ElanNativeEnrollmentRun *next = [ElanNativeEnrollmentRun new];
    next.client = 55; connection.enrollment = next;
    callback.handler([NSError errorWithDomain:@"fixture" code:1 userInfo:nil]);
    BOOL staleCallback = !cancelled;
    (void)[connection enrollmentRemote];
    callback.handler([NSError errorWithDomain:@"fixture" code:1 userInfo:nil]);
    BOOL currentCallback = cancelled != 0;
    connection.connection = nil;
    connection.enrollment = nil; controller.current = nil; controller.busy = NO; cancelled = 0;
    [connection enroll:1 user:501 options:@{@"BKOptionAuthWithCredentialSet": [NSData dataWithBytes:"fixture-context!" length:16]}
                 async:NO client:55 replyBlock:^(int result) { status = result; }];
    BOOL unsignedPeer = status && !controller.busy && !connection.enrollment;
    BOOL passed = wrongClient && incomplete && continued && duplicate && unrelatedCancel && wokeCancel && cancelledRejected && unsignedPeer && staleCallback && currentCallback;
    printf("ENROLLMENT_CONTROL wrong_client=%d incomplete_rejected=%d continued=%d duplicate_rejected=%d unrelated_cancel=%d cancel_wakes=%d cancelled_rejected=%d missing_peer_rejected=%d stale_callback_ignored=%d current_callback_cancelled=%d passed=%d\n",
        wrongClient, incomplete, continued, duplicate, unrelatedCancel, wokeCancel, cancelledRejected, unsignedPeer, staleCallback, currentCallback, passed);
    return passed ? 0 : 1;
}

static void observeCapture(const ElanpressTouchStats *stats, int touched, int clear) {
    [enrollmentCaptureOwner reportEnrollmentTouch:touched != 0];
    static double previous;
    double now = capture_milliseconds();
    if (now - previous < 1000) return;
    previous = now;
    printf("ELAN_PROVIDER capture_frame touched=%d clear=%d coverage=%.4f mean_delta=%.1f\n",
           touched, clear, stats->coverage, stats->mean_delta);
}

static int userSessionCancellationSelfTest(void) {
    NativeUserSessionSnapshot good = {true, true, true, true, true, true, 501, 501, 100001, {1234, 100, 20}};
    BOOL passed = YES;
    for (unsigned reason = 0; reason < 2; reason++) {
        ElanProviderController *controller = [ElanProviderController new];
        ElanProviderConnection *connection = [ElanProviderConnection new]; connection.controller = controller;
        ElanNativeEnrollmentRun *run = [ElanNativeEnrollmentRun new]; run.client = 55;
        run.continuation = dispatch_semaphore_create(0); run.waiting = YES;
        connection.enrollment = run; controller.current = connection; controller.activeClient = 55; controller.busy = YES;
        NativeUserSessionState state = {}; nativeSessionStart(&state, good); controller.userSession = state; cancelled = 0;
        BOOL active = [controller observeSession:good] && !cancelled && !controller.stopping;
        NativeUserSessionSnapshot changed = good;
        if (!reason) changed.onConsole = false; else changed.coreauth.microseconds++;
        BOOL stopped = ![controller observeSession:changed] && cancelled && controller.stopping;
        BOOL woke = dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW) == 0;
        BOOL staysStopped = ![controller observeSession:good] && controller.userSession.stopped;
        passed = passed && active && stopped && woke && staysStopped;
        connection.enrollment = nil; controller.current = nil; cancelled = 0;
    }
    printf("USER_SESSION_CONTROL inactive_console_and_replaced_process_cancellation passed=%d\n", passed);
    return passed ? 0 : 1;
}

static int powerCancellationSelfTest(void) {
    ElanProviderController *controller = [ElanProviderController new];
    ElanProviderConnection *connection = [ElanProviderConnection new]; connection.controller = controller;
    ElanNativeEnrollmentRun *run = [ElanNativeEnrollmentRun new]; run.client = 55;
    run.continuation = dispatch_semaphore_create(0); run.waiting = YES;
    connection.enrollment = run; controller.current = connection; controller.activeClient = 55; controller.busy = YES;
    providerPowerStop();
    BOOL blocked = ![controller sessionIsCurrent] && controller.stopping && cancelled && providerPowerStopped;
    BOOL woke = dispatch_semaphore_wait(run.continuation, DISPATCH_TIME_NOW) == 0;
    BOOL noSessionRead = !controller.userSession.started && !controller.userSession.stopped;
    connection.enrollment = nil; controller.current = nil;
    providerInterrupted = providerPowerStopped = cancelled = 0;
    BOOL passed = blocked && woke && noSessionRead;
    printf("POWER_CAPTURE_CANCEL pending_enrollment_woken_and_credential_path_stopped passed=%d\n", passed);
    return passed ? 0 : 1;
}

static BOOL currentSettingsProcess(NativeSettingsIdentity *identity) {
    *identity = (NativeSettingsIdentity){0, 0, 0};
    int required = proc_listpids(PROC_UID_ONLY, 501, NULL, 0);
    if (required <= 0 || required > 1024 * 1024 - 128) return NO;
    int size = required + 128;
    pid_t *pids = calloc(1, (size_t)size);
    if (!pids) return NO;
    int count = proc_listpids(PROC_UID_ONLY, 501, pids, size);
    BOOL reliable = count > 0 && count < size;
    for (int i = 0; reliable && i < count / (int)sizeof(pid_t); i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (pids[i] <= 1 || proc_pidpath(pids[i], path, sizeof(path)) <= 0 ||
            strcmp(path, "/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password")) continue;
        struct proc_bsdinfo info = {};
        if (proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) || info.pbi_uid != 501) { reliable = NO; break; }
        if (info.pbi_status == SZOMB) continue;
        if (identity->pid) { reliable = NO; break; }
        *identity = (NativeSettingsIdentity){pids[i], info.pbi_start_tvsec, info.pbi_start_tvusec};
    }
    free(pids); return reliable;
}

typedef struct { int broker; uint64_t function; } NativeSettingsWorkerAPI;
static int enableSettingsProcess(void *raw, int32_t pid) {
    NativeSettingsWorkerAPI *api = raw;
    int status = elanProviderSettings(api->broker, pid, api->function);
    printf("ELAN_PROVIDER settings_attach=%d pid=%d\n", status, pid);
    return status;
}
static int restoreSettingsProcess(void *raw) {
    NativeSettingsWorkerAPI *api = raw;
    int status = elanProviderSettingsRestore(api->broker);
    printf("ELAN_PROVIDER settings_restore=%d\n", status);
    return status;
}
static void settingsProcessChanged(void *unused) {
    (void)unused;
    uint32_t status = notify_post("com.apple.BiometricKit.connectedAccessoriesChanged");
    printf("ELAN_PROVIDER settings_refresh=%u\n", status);
}

static int enrollmentBackgroundCheck(void) {
    Sensor probe = {0};
    setbuf(stdout, NULL); cancelled = 0; capture_timeout_seconds = 12;
    signal(SIGINT, providerInterrupt); signal(SIGTERM, providerInterrupt);
    BOOL prepared = open_sensor(&probe) && probe.pid == 0x0c1a && prepareEnrollmentBackground(&probe, 0);
    unsigned mean = 0;
    if (prepared) {
        uint64_t sum = 0;
        for (int i = 0; i < probe.w * probe.hgt; i++) sum += probe.bg[i];
        mean = (unsigned)(sum / (probe.w * probe.hgt));
    }
    printf("ENROLL_BACKGROUND_CHECK pid=%04x firmware=%04x width=%d height=%d prepared=%d mean=%u\n",
        probe.pid, probe.firmware, probe.w, probe.hgt, prepared, mean);
    close_sensor(&probe);
    printf("ENROLL_BACKGROUND_CHECK_DONE status=%d sensor_closed=1 keychain_read=0 credential_added=0 service_changed=0\n", prepared ? 0 : 1);
    return prepared ? 0 : 1;
}

static int observePower(BOOL checkOnly, BOOL managed) {
    if (managed && (!nativeControllerLeaseValid(STDIN_FILENO) || !nativeControllerLeaseAlive(STDIN_FILENO))) return 2;
    setbuf(stdout, NULL);
    signal(SIGINT, providerInterrupt); signal(SIGTERM, providerInterrupt); signal(SIGPIPE, SIG_IGN);
    ElanPowerObserver *power = [ElanPowerObserver new];
    if (![power openDeferringSleep:NO stop:nil]) return 13;
    int result = 0;
    @try {
        NSDictionary *previous = nil;
        double deadline = nativePowerTime() + (checkOnly ? 1 : 960);
        while (!providerInterrupted && (managed ? nativeControllerLeaseAlive(STDIN_FILENO) : nativePowerTime() < deadline)) {
            NSMutableDictionary *state = [[power snapshot] mutableCopy];
            uint32_t consoleUser = UINT32_MAX;
            BOOL consoleKnown = nativeConsoleUser(&consoleUser);
            state[@"console_known"] = @(consoleKnown); state[@"console_user"] = @(consoleUser);
            if (![state isEqual:previous]) {
                NSData *data = [NSJSONSerialization dataWithJSONObject:state options:NSJSONWritingSortedKeys error:NULL];
                printf("POWER_STATE %s\n", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
                previous = state;
            }
            if (checkOnly) usleep(100000);
            else {
                struct pollfd parent = {STDIN_FILENO, POLLIN, 0};
                int ready = poll(&parent, 1, 100);
                if (ready < 0 && errno != EINTR) { result = 1; break; }
                if (ready > 0) {
                    if (parent.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
                    if (parent.revents & POLLIN) { char byte; if (read(STDIN_FILENO, &byte, 1) <= 0) break; }
                }
            }
        }
    } @finally {
        [power close];
        puts("POWER_OBSERVER_DONE registration_closed=1 sensor_opened=0 keychain_read=0 provider_kernel_opened=0");
    }
    return result;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "--self-test")) return self_test() | template_self_test() | cancellationSelfTest() | enrollmentCaptureSelfTest() | enrollmentControlSelfTest() | userSessionCancellationSelfTest() | powerCancellationSelfTest();
        if (argc == 2 && !strcmp(argv[1], "--check-power")) return observePower(YES, NO);
        if (argc == 2 && !strcmp(argv[1], "--observe-power")) return observePower(NO, NO);
        if (argc == 2 && !strcmp(argv[1], "--observe-power-managed")) return observePower(NO, YES);
        if (argc == 2 && !strcmp(argv[1], "--console-state")) {
            uint32_t user = UINT32_MAX;
            BOOL known = nativeConsoleUser(&user);
            printf("{\"console_known\":%s,\"console_user\":%u}\n", known ? "true" : "false", user);
            return 0;
        }
        if (argc == 2 && !strcmp(argv[1], "--check-user-session")) {
            NativeUserSessionSnapshot value = nativeReadUserSession(0);
            NativeSessionStatus status = nativeSessionAdmission(value, true);
            printf("ELAN_PROVIDER session_check=%u console_user=%u gui_user=%u graphic_access=%d coreauth_pid=%d sensor_opened=0 keychain_read=0 kernel_opened=0\n",
                status, value.consoleUser, value.guiUser, value.graphicAccess, value.coreauth.pid);
            return status ? 12 : 0;
        }
        if (argc == 2 && !strcmp(argv[1], "--check-enrollment-background") && getuid() == 501) return enrollmentBackgroundCheck();
        BOOL managed = argc == 2 && !strcmp(argv[1], "--serve-managed");
        BOOL background = managed || (argc == 2 && !strcmp(argv[1], "--serve-background"));
        if (argc != 2 || (!background && strcmp(argv[1], "--serve")) || getuid() != 501) return 2;
        setbuf(stdout, NULL);
        signal(SIGINT, providerInterrupt); signal(SIGTERM, providerInterrupt); signal(SIGPIPE, SIG_IGN);
        capture_timeout_seconds = 35;
        capture_observer = observeCapture;
        void *framework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_LAZY | RTLD_LOCAL);
        void *platformFunction = framework ? dlsym(framework, "isTouchIDPlatformWithFailure") : NULL;
        if (!platformFunction || !objc_getProtocol("BiometricKitXpcProtocol") ||
            !NSClassFromString(@"BiometricKitIdentity") || !NSClassFromString(@"BiometricKitAccessory")) return 3;
        if (!dlopen("/System/Library/PrivateFrameworks/LocalAuthenticationCore.framework/LocalAuthenticationCore", RTLD_LAZY | RTLD_LOCAL)) return 3;
        Class helperClass = NSClassFromString(@"LACBiometryHelper");
        Method instance = class_getClassMethod(helperClass, sel_registerName("touchIdInstance"));
        Method fault = class_getInstanceMethod(helperClass, sel_registerName("fault"));
        Method permanent = class_getInstanceMethod(helperClass, sel_registerName("permanentError"));
        if (!instance || !fault || !permanent) return 3;
        ElanProviderController *controller = [ElanProviderController new];
        controller.broker = -1;
        controller.connections = [NSMutableArray array];
        controller.captureQueue = dispatch_queue_create("io.github.hackintosh-tools.elan-native-capture", DISPATCH_QUEUE_SERIAL);
        controller.captureGroup = dispatch_group_create();
        NSXPCListener *listener = nil;
        ElanPowerObserver *power = [ElanPowerObserver new];
        int result = 1;
        @try {
            NativeSessionStatus admission = nativeSessionAdmission(nativeReadUserSession(0), false);
            if (admission) { printf("ELAN_PROVIDER session_admission=%u\n", admission); return 12; }
            if (![power openDeferringSleep:YES stop:^{ providerPowerStop(); }] || ![[power snapshot][@"ready"] boolValue]) return 13;
            if (!open_sensor(&sensor) || sensor.pid != 0x0c1a) return 4;
            if (providerInterrupted) return 13;
            @autoreleasepool {
                NSError *storageError = nil;
                controller.repository = [[ElanFingerprintRepository alloc] initWithUserKeychain:501 pid:sensor.pid
                    width:sensor.w height:sensor.hgt interactive:!background];
                if (![controller.repository loadOrMigrateLegacyFromUserKeychain:!background error:&storageError]) {
                    printf("ELAN_PROVIDER catalog_load_error=%s:%ld\n", storageError.domain.UTF8String, (long)storageError.code);
                    return 5;
                }
                __weak ElanProviderController *weakController = controller;
                controller.session = [[ElanFingerprintSession alloc] initWithRepository:controller.repository
                    publisher:^int(ElanFingerprintCatalog *catalog) {
                        ElanProviderController *owner = weakController;
                        @synchronized (owner) {
                            if (!owner || owner.stopping || owner.broker < 0 || ![owner sessionIsCurrent]) return -32003;
                            NSData *bytes = nativeCatalogIdentityBytes(catalog);
                            return elanProviderReplaceCatalog(owner.broker, ++owner.sequence, bytes.bytes, (uint32_t)catalog.records.count);
                        }
                    } error:&storageError];
                if (!controller.session) return 5;
                NSData *background = controller.matcher.background;
                if (background) memcpy(sensor.bg, background.bytes, background.length);
                id accessory = [NSClassFromString(@"BiometricKitAccessory") new];
                [accessory setValue:[[NSUUID alloc] initWithUUIDString:@"0D62A891-28A1-4818-A321-04F3000C1A01"] forKey:@"uuid"];
                [accessory setValue:@1 forKey:@"type"]; [accessory setValue:@0 forKey:@"flags"];
                [accessory setValue:@"ELAN 0c1a" forKey:@"name"];
                controller.accessory = accessory;
            }
            if (providerInterrupted) return 13;
            LAContext *baseline = [LAContext new]; NSError *error = nil;
            BOOL available = [baseline canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
            [baseline invalidate];
            printf("ELAN_PROVIDER baseline_available=%d error=%ld identities=%lu\n", available, (long)error.code, controller.repository.current.records.count);
            if (available) return 6;
            NativeUserSessionSnapshot observedSession = nativeReadUserSession(0);
            NativeUserSessionState userSession = {};
            if (nativeSessionStart(&userSession, observedSession)) return 7;
            controller.userSession = userSession;
            if (![controller sessionIsCurrent]) return 13;
            pid_t coreauth = userSession.coreauth.pid;
            controller.broker = elanProviderConnect();
            if (controller.broker < 0) return 8;
            NSData *identityBytes = nativeCatalogIdentityBytes(controller.repository.current);
            int begin = elanProviderBeginCatalog(controller.broker, identityBytes.bytes, (uint32_t)controller.repository.current.records.count);
            printf("ELAN_PROVIDER begin=%d\n", begin);
            if (begin) return 9;
            if (providerInterrupted) return 13;
            listener = [[NSXPCListener alloc] initWithMachServiceName:@"com.apple.biometrickitd"];
            listener.delegate = controller; [listener resume];
            int platform = elanProviderPlatform(controller.broker, coreauth, (uint64_t)platformFunction,
                (uint64_t)method_getImplementation(instance), (uint64_t)method_getImplementation(fault),
                (uint64_t)method_getImplementation(permanent), (uint64_t)(__bridge void *)helperClass);
            printf("ELAN_PROVIDER platform=%d coreauthd=%d\n", platform, coreauth);
            if (platform) return 10;
            puts("ELAN_PROVIDER ready=1 original_ui_requested=0");
            NativeSettingsSession settingsSession = {};
            NativeSettingsWorkerAPI settingsWorker = {controller.broker, (uint64_t)platformFunction};
            NativeSettingsSessionAPI settingsAPI = {&settingsWorker, enableSettingsProcess, restoreSettingsProcess, settingsProcessChanged};
            NSDate *nextSettingsCheck = [NSDate distantPast];
            NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:900];
            while (!providerInterrupted && !controller.stopping && (managed || deadline.timeIntervalSinceNow > 0)) {
                struct pollfd peer = {controller.broker, POLLIN, 0};
                if (poll(&peer, 1, 0) > 0 && (peer.revents & (POLLHUP | POLLERR | POLLNVAL))) break;
                if (nextSettingsCheck.timeIntervalSinceNow <= 0) {
                    if (![controller sessionIsCurrent]) break;
                    NativeSettingsIdentity observed = {};
                    BOOL reliable = currentSettingsProcess(&observed);
                    @synchronized (controller) {
                        int status = nativeSettingsSessionObserve(&settingsSession, settingsAPI, observed, reliable,
                            controller.busy || controller.stopping);
                        if (status) controller.stopping = YES;
                    }
                    nextSettingsCheck = [NSDate dateWithTimeIntervalSinceNow:1];
                }
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
            }
            result = controller.userSession.stopped ? 12 : settingsSession.failure ? 11 : 0;
        } @catch (NSException *exception) {
            printf("ELAN_PROVIDER exception=%s\n", exception.name.UTF8String);
        } @finally {
            controller.stopping = YES; cancelled = 1;
            NSArray *connections;
            @synchronized (controller) { connections = [controller.connections copy]; }
            for (NSXPCConnection *connection in connections) [connection invalidate];
            [listener invalidate];
            if (dispatch_group_wait(controller.captureGroup, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC))) {
                puts("ELAN_PROVIDER capture_stop_timeout=1"); _Exit(124);
            }
            if (controller.broker >= 0) {
                int restored = elanProviderEnd(controller.broker);
                printf("ELAN_PROVIDER restore=%d\n", restored);
                if (restored) result = 1;
                close(controller.broker);
            }
            clearPrints(); close_sensor(&sensor);
            controller.session = nil; controller.repository = nil; controller.accessory = nil;
            [power close];
            if (providerPowerStopped) puts("ELAN_PROVIDER power_stopped=1 sensor_closed=1");
            printf("ELAN_PROVIDER_DONE status=%d\n", result);
        }
        return result;
    }
}
