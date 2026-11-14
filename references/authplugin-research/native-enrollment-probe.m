#define NATIVE_STACK_NO_MAIN
#include "native-stack-probe.m"
#import "../../elan-fingerprint-macos/src/ElanFingerprintCatalog.h"
#include "fingerprint-catalog-fixtures.h"
#include "native-catalog-view.h"
#import "../../elan-fingerprint-macos/src/ElanFingerprintSession.h"
#import "../../elan-fingerprint-macos/src/ElanFingerprintEnrollment.h"
#include "native-enrollment-progress.h"
#include "native-provider-interface.h"
#include "native-enrollment-request.h"

@interface NSObject (NativeEnrollmentResearch)
- (id)createEnrollOperationWithError:(NSError **)error;
- (id)createExtendEnrollTouchIDOperationWithError:(NSError **)error;
- (void)setIdentity:(id)identity;
- (NSNumber *)maxIdentityCountWithError:(NSError **)error;
- (NSNumber *)freeIdentityCountForUser:(unsigned int)user error:(NSError **)error;
- (NSData *)identitiesDatabaseHashForUser:(unsigned int)user error:(NSError **)error;
- (id)identityForUUID:(NSUUID *)uuid error:(NSError **)error;
- (BOOL)updateIdentity:(id)identity error:(NSError **)error;
- (BOOL)removeIdentity:(id)identity error:(NSError **)error;
- (BOOL)removeAllIdentitiesForUser:(unsigned int)user error:(NSError **)error;
- (void)enrollResult:(id)identity details:(NSDictionary *)details client:(uint64_t)client;
- (void)statusMessage:(unsigned int)status client:(uint64_t)client;
- (dispatch_queue_t)dispatchQueue;
@end

@interface NativeEnrollmentServer : NativeBiometricTransportServer
@property(nonatomic, strong) ElanFingerprintRepository *repository;
@property(nonatomic, strong) ElanFingerprintSession *session;
@property(nonatomic, readonly) NSArray *records;
@property(nonatomic) uint64_t enrollClient;
@property(nonatomic) unsigned enrollRequests;
@property(nonatomic) BOOL fixtureCredentialReceived;
@property(nonatomic, strong) dispatch_semaphore_t continued;
@property(nonatomic) unsigned continueRequests;
@property(nonatomic, copy) NSDictionary *extendOptions;
@property(nonatomic, copy) id extendQuery;
@end

@implementation NativeEnrollmentServer
- (NSArray *)records {
    return nativeCatalogIdentities(self.repository.current, nil);
}
- (void)configureConnection:(NSXPCConnection *)connection {
    [super configureConnection:connection];
    Class identity = NSClassFromString(@"BiometricKitIdentity");
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, identity, nil]
                                forSelector:@selector(identities:client:replyBlock:) argumentIndex:0 ofReply:YES];
    for (NSString *name in @[@"updateIdentity:options:async:client:replyBlock:", @"removeIdentity:options:async:client:replyBlock:"])
        [connection.exportedInterface setClasses:[NSSet setWithObject:identity]
                                    forSelector:NSSelectorFromString(name) argumentIndex:0 ofReply:NO];
    [connection.exportedInterface setClasses:[NSSet setWithObject:identity]
                                forSelector:NSSelectorFromString(@"getIdentityFromUUID:client:replyBlock:") argumentIndex:0 ofReply:YES];
    [connection.remoteObjectInterface setClasses:[NSSet setWithObject:identity]
                                    forSelector:@selector(enrollResult:details:client:) argumentIndex:0 ofReply:NO];
    configureNativeMatchQuery(connection.exportedInterface);
    [connection.remoteObjectInterface setClasses:[NSSet setWithObject:identity]
                                    forSelector:@selector(matchResult:details:client:) argumentIndex:0 ofReply:NO];
}
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    printf("ENROLL_QUERY %s\n", query.description.UTF8String);
    reply(nativeCatalogIdentities(self.repository.current, query));
}
- (void)getMaxIdentityCount:(int)type client:(uint64_t)client replyBlock:(void (^)(NSInteger))reply {
    printf("ENROLL_MAX type=%d\n", type);
    reply(type == 0 ? 3 : 0);
}
- (void)getFreeIdentityCount:(int)type user:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSInteger))reply {
    printf("ENROLL_FREE type=%d user=%u\n", type, user);
    reply(type == 0 && user == 501 ? 3 - self.records.count : 0);
}
- (void)getIdentityFromUUID:(NSUUID *)uuid client:(uint64_t)client replyBlock:(void (^)(id))reply {
    for (id identity in self.records) if ([[identity valueForKey:@"uuid"] isEqual:uuid]) { reply(identity); return; }
    reply(nil);
}
- (void)getIdentitiesDatabaseHashForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSData *))reply {
    reply(user == self.repository.current.user ? self.repository.current.databaseState : nil);
}
- (void)updateIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanFingerprintCatalog *previous = self.repository.current;
    ElanFingerprintCatalog *renamed = [previous renamingUUID:[identity valueForKey:@"uuid"] name:[identity valueForKey:@"name"] error:NULL];
    reply(renamed && [self.session commit:renamed replacing:previous error:NULL] ? 0 : 1);
}
- (void)removeIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanFingerprintCatalog *previous = self.repository.current;
    ElanFingerprintCatalog *removed = [previous removingUUID:[identity valueForKey:@"uuid"] error:NULL];
    reply(removed && [self.session commit:removed replacing:previous error:NULL] ? 0 : 1);
}
- (void)removeAllIdentitiesForUser:(unsigned int)user options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (user != 501) { reply(1); return; }
    ElanFingerprintCatalog *previous = self.repository.current;
    ElanFingerprintCatalog *empty = [previous removingAll:NULL];
    reply(empty && [self.session commit:empty replacing:previous error:NULL] ? 0 : 1);
}
- (void)enroll:(int)type user:(unsigned int)user options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    printf("ENROLL_REQUEST type=%d user=%u async=%d keys=%s\n", type, user, async,
           [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String);
    self.enrollRequests++;
    self.enrollClient = client;
    self.fixtureCredentialReceived = [options[@"BKOptionAuthWithCredentialSet"]
        isEqual:[NSData dataWithBytes:"fixture-context!" length:16]];
    reply(type == 1 && user == 501 ? 0 : 1);
}
- (void)pullAlignmentData:(uint64_t)client replyBlock:(void (^)(NSData *))reply {
    puts("ENROLL_ALIGNMENT unavailable=1"); reply(nil);
}
- (void)enrollContinue:(uint64_t)client replyBlock:(void (^)(int))reply {
    BOOL same = client == self.enrollClient;
    printf("ENROLL_CONTINUE same_client=%d\n", same); reply(same ? 0 : 1);
    if (same) { self.continueRequests++; dispatch_semaphore_signal(self.continued); }
}
- (void)completeEnrollment:(uint64_t)client replyBlock:(void (^)(int))reply {
    printf("ENROLL_COMPLETE same_client=%d\n", client == self.enrollClient); reply(client == self.enrollClient ? 0 : 1);
}
- (void)match:(id)query options:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.matchRequests++; self.lastMatchClient = client; self.extendQuery = query; self.extendOptions = options;
    printf("EXTEND_REQUEST query=%s async=%d option_keys=%s\n", [query description].UTF8String, async,
        [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String);
    for (NSString *key in options) {
        id value = options[key];
        if ([value isKindOfClass:NSData.class])
            printf("EXTEND_OPTION %s data_length=%lu fixture_context=%d\n", key.UTF8String, [value length],
                [value isEqual:[NSData dataWithBytes:"fixture-context!" length:16]]);
        else printf("EXTEND_OPTION %s value=%s\n", key.UTF8String, [value description].UTF8String);
    }
    reply(0);
}
- (void)cancel:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.cancelRequests++;
    reply(0);
    if (client == self.enrollClient || client == self.lastMatchClient)
        [[self.connection remoteObjectProxy] statusMessage:99 client:client];
}
@end

@interface NativeEnrollmentDelegate : NSObject
@property(nonatomic, strong) dispatch_semaphore_t completed;
@property(nonatomic, strong) dispatch_semaphore_t progressed;
@property(nonatomic) NSInteger percent;
@property(nonatomic) BOOL identityReceived;
@property(nonatomic) BOOL resultReceived;
@property(nonatomic) NSInteger finishedReason;
@property(nonatomic) unsigned identityCallbacks;
@property(nonatomic) unsigned resultCallbacks;
@property(nonatomic) NSInteger captureError;
@property(nonatomic, strong) dispatch_semaphore_t captureErrorReceived;
@property(nonatomic) NSInteger enrollmentFailure;
@property(nonatomic, strong) dispatch_semaphore_t presenceChanged;
@property(nonatomic) BOOL present;
@property(nonatomic, strong) dispatch_semaphore_t extended;
@property(nonatomic) unsigned extendCallbacks;
@property(nonatomic) BOOL updated;
@end
@implementation NativeEnrollmentDelegate
- (BOOL)respondsToSelector:(SEL)selector {
    printf("ENROLL_DELEGATE_QUERY %s\n", sel_getName(selector));
    return [super respondsToSelector:selector];
}
- (void)operation:(id)operation stateChanged:(NSInteger)state { printf("ENROLL_STATE %ld\n", (long)state); }
- (void)operation:(id)operation finishedWithReason:(NSInteger)reason {
    self.finishedReason = reason;
    printf("ENROLL_FINISHED %ld\n", (long)reason);
    dispatch_semaphore_signal(self.completed);
}
- (void)enrollOperation:(id)operation percentCompleted:(NSInteger)percent {
    self.percent = percent; printf("ENROLL_PERCENT %ld\n", (long)percent);
    if (self.progressed) dispatch_semaphore_signal(self.progressed);
}
- (void)enrollOperation:(id)operation progressedWithTouchIDInfo:(id)info {
    printf("ENROLL_PROGRESS_INFO present=%d\n", info != nil);
}
- (void)fingerprintCaptureOperation:(id)operation encounteredCaptureError:(NSInteger)error {
    self.captureError = error; printf("ENROLL_CAPTURE_ERROR %ld\n", (long)error);
    if (self.captureErrorReceived) dispatch_semaphore_signal(self.captureErrorReceived);
}
- (void)enrollOperation:(id)operation failedWithReason:(NSInteger)reason {
    self.enrollmentFailure = reason; printf("ENROLL_FAILED_REASON %ld\n", (long)reason);
}
- (void)operation:(id)operation presenceStateChanged:(BOOL)present {
    self.present = present; printf("ENROLL_PRESENCE %d\n", present);
    if (self.presenceChanged) dispatch_semaphore_signal(self.presenceChanged);
}
- (void)extendEnroll:(id)operation hasUpdated:(BOOL)updated {
    self.updated = updated; self.extendCallbacks++;
    printf("EXTEND_CALLBACK updated=%d\n", updated);
    dispatch_semaphore_signal(self.extended);
}
- (void)enrollOperation:(id)operation finishedWithIdentity:(id)identity {
    self.identityCallbacks++;
    self.identityReceived = [[identity valueForKey:@"uuid"] isEqual:
        [[NSUUID alloc] initWithUUIDString:@"6AF9A0D7-3E65-42E8-8D65-36F4AA1598F7"]];
    printf("ENROLL_IDENTITY_CALLBACK class=%s expected_uuid=%d\n", object_getClassName(identity), self.identityReceived);
}
- (void)enrollOperation:(id)operation finishedWithEnrollResult:(id)result {
    self.resultCallbacks++;
    id identity = [result valueForKey:@"enrolledIdentity"];
    self.resultReceived = [[identity valueForKey:@"uuid"] isEqual:
        [[NSUUID alloc] initWithUUIDString:@"6AF9A0D7-3E65-42E8-8D65-36F4AA1598F7"]];
    printf("ENROLL_RESULT_CALLBACK class=%s expected_uuid=%d\n", object_getClassName(result), self.resultReceived);
}
@end

static int enrollmentTransport(void) {
    char build[64] = {}; size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) || strcmp(build, "24H32")) return 3;
    PlatformCache cache = {};
    if (!overridePlatformCache(&cache)) return 4;
    NativeEnrollmentServer *server = [NativeEnrollmentServer new];
    server.continued = dispatch_semaphore_create(0);
    __block NSData *catalogData = nil;
    __block OSStatus writerStatus = 0;
    server.repository = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64
        reader:^OSStatus(NSData **data) { *data = catalogData; return catalogData ? 0 : errSecItemNotFound; }
        writer:^OSStatus(NSData *data, BOOL create) {
            if (writerStatus) return writerStatus;
            if (create && catalogData) return errSecDuplicateItem;
            if (!create && !catalogData) return errSecItemNotFound;
            catalogData = [data copy]; return 0;
        }];
    NSData *templateData = fixtureTemplate(3, 0x0c1a, 144, 64, 24);
    NSUUID *fixtureUUID = [[NSUUID alloc] initWithUUIDString:@"6AF9A0D7-3E65-42E8-8D65-36F4AA1598F7"];
    if (![server.repository importLegacy:templateData uuid:fixtureUUID name:@"Fixture" databaseState:[@"legacy-biometry-state-32-bytes!!" dataUsingEncoding:NSUTF8StringEncoding] error:NULL]) {
        *cache.result = cache.oldResult; *cache.checked = cache.oldChecked; return 5;
    }
    __block NSData *publishedIdentities = nativeCatalogIdentityBytes(server.repository.current);
    server.session = [[ElanFingerprintSession alloc] initWithRepository:server.repository
        publisher:^int(ElanFingerprintCatalog *catalog) { publishedIdentities = nativeCatalogIdentityBytes(catalog); return 0; } error:NULL];
    if (!server.session) { *cache.result = cache.oldResult; *cache.checked = cache.oldChecked; return 5; }
    NSXPCListener *listener = [NSXPCListener anonymousListener];
    listener.delegate = server; transportProbeEndpoint = listener.endpoint; [listener resume];
    Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
    Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
    method_exchangeImplementations(original, replacement);
    __block BOOL done = NO;
    __block int result = 1;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            id operation = nil;
            ElanpressFeatures *features = NULL;
            @try {
                NSError *error = nil;
                id descriptor = [NSClassFromString(@"BKDeviceDescriptor") deviceDescriptorForType:1];
                id device = [NSClassFromString(@"BKDevice") deviceWithDescriptor:descriptor error:&error];
                if (!device || error) return;
                NSArray *identities = [device identitiesForUser:501 error:&error];
                if (identities.count != 1 || error) return;
                NSArray *other = [device identitiesForUser:502 error:&error];
                if (!other || other.count || error) return;
                NSNumber *maximum = [device maxIdentityCountWithError:&error];
                NSNumber *free = [device freeIdentityCountForUser:501 error:&error];
                printf("ENROLL_COUNTS identities=%lu other=%lu maximum=%ld free=%ld error=%ld\n",
                       identities.count, other.count, maximum.integerValue, free.integerValue, (long)error.code);
                if (maximum.integerValue != 3 || free.integerValue != 2 || error) return;
                NSData *initialState = [device identitiesDatabaseHashForUser:501 error:&error];
                if (initialState.length != 32 || error) return;
                id identity = identities[0];
                NSUUID *uuid = [identity valueForKey:@"uuid"];
                [identity setValue:@"Renamed fixture" forKey:@"name"];
                NSData *beforeFailure = publishedIdentities;
                writerStatus = errSecInteractionNotAllowed;
                NSError *failedWriteError = nil;
                BOOL failedWrite = [device updateIdentity:identity error:&failedWriteError];
                writerStatus = 0;
                id unchanged = [device identityForUUID:uuid error:&error];
                BOOL restored = [[unchanged valueForKey:@"name"] isEqual:@"Fixture"] &&
                    [publishedIdentities isEqual:beforeFailure] && !server.session.invalidated &&
                    server.session.matcher.catalog == server.repository.current;
                printf("ENROLL_MANAGEMENT_FAILURE rejected=%d error_present=%d restored=%d\n", !failedWrite, failedWriteError != nil, restored);
                if (failedWrite || !failedWriteError || !restored || error) return;
                BOOL renamed = [device updateIdentity:identity error:&error];
                id loaded = [device identityForUUID:uuid error:&error];
                BOOL nameRoundTrip = [[loaded valueForKey:@"name"] isEqual:@"Renamed fixture"];
                if (!renamed || !nameRoundTrip || error) return;
                NSData *renamedState = [device identitiesDatabaseHashForUser:501 error:&error];
                if (![renamedState isEqual:initialState] || error) return;
                BOOL removed = [device removeIdentity:identity error:&error];
                NSArray *empty = [device identitiesForUser:501 error:&error];
                printf("ENROLL_MANAGEMENT rename=%d name_roundtrip=%d removed=%d empty=%d error=%ld\n",
                       renamed, nameRoundTrip, removed, empty && !empty.count, (long)error.code);
                if (!removed || !empty || empty.count || error) return;
                NSData *removedState = [device identitiesDatabaseHashForUser:501 error:&error];
                if (removedState.length != 32 || [removedState isEqual:initialState] || error) return;
                puts("ENROLL_DATABASE_STATE bytes=32 rename_preserved=1 deletion_changed=1");
                operation = [device createEnrollOperationWithError:&error];
                if (!operation || error) return;
                NativeEnrollmentDelegate *delegate = [NativeEnrollmentDelegate new];
                delegate.completed = dispatch_semaphore_create(0);
                delegate.progressed = dispatch_semaphore_create(0);
                delegate.presenceChanged = dispatch_semaphore_create(0);
                [operation setValue:@501 forKey:@"userID"];
                [operation setCredentialSet:[NSData dataWithBytes:"fixture-context!" length:16]];
                ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), delegate);
                BOOL started = [operation startWithError:&error];
                printf("ENROLL_START class=%s started=%d requests=%u error=%ld\n", object_getClassName(operation), started,
                       server.enrollRequests, (long)error.code);
                if (!started || error || server.enrollRequests != 1 || !server.fixtureCredentialReceived) return;
                id remote = [server.connection remoteObjectProxy];
                unsigned char generated[144 * 64]; uint32_t seed = 13;
                for (size_t i = 0; i < sizeof(generated); i++) { seed = seed * 1664525u + 1013904223u; generated[i] = seed >> 24; }
                features = elanpress_image_features(generated, 144, 64);
                ElanFingerprintEnrollment *draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:server.session.matcher
                    background:[NSMutableData dataWithLength:144 * 64 * 2] targetCount:8 error:&error];
                if (!features || !draft || error) return;
                for (unsigned raw = 63; raw <= 64; raw++) {
                    [remote statusMessage:raw client:server.enrollClient];
                    BOOL received = !dispatch_semaphore_wait(delegate.presenceChanged, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    printf("ENROLL_PRESENCE_RAW raw=%u received=%d present=%d finished=%ld\n", raw, received, delegate.present, (long)delegate.finishedReason);
                    if (!received || delegate.present != (raw == 63) || delegate.finishedReason) return;
                }
                [remote statusMessage:98 client:server.enrollClient];
                for (unsigned accepted = 0; accepted <= 8; accepted++) {
                    unsigned score = 0;
                    if (accepted && [draft appendFeatures:features score:&score] != ElanEnrollmentSampleAccepted) return;
                    unsigned status = nativeEnrollmentProgress(accepted, 8);
                    [remote statusMessage:status client:server.enrollClient];
                    BOOL progressReceived = !dispatch_semaphore_wait(delegate.progressed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    BOOL continued = !dispatch_semaphore_wait(server.continued, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    NSInteger expected = (status - 100) * 100 / 255;
                    printf("ENROLL_PROGRESS_STEP accepted=%u raw=%u percent=%ld expected=%ld continued=%d records=%lu\n",
                        accepted, status, (long)delegate.percent, (long)expected, continued, server.records.count);
                    if (!progressReceived || !continued || delegate.percent != expected || server.records.count ||
                        delegate.identityCallbacks || delegate.resultCallbacks || delegate.finishedReason) return;
                }
                if (!draft.ready || ![draft commitWithSession:server.session uuid:fixtureUUID name:@"Fixture" error:&error] || error) return;
                [remote enrollResult:server.records[0] details:@{} client:server.enrollClient];
                BOOL finished = !dispatch_semaphore_wait(delegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("ENROLL_CALLBACK observed_finished=%d percent=%ld identity=%d result=%d reason=%ld\n",
                       finished, (long)delegate.percent, delegate.identityReceived, delegate.resultReceived, (long)delegate.finishedReason);
                if (!finished || delegate.percent != 100 || !delegate.identityReceived || !delegate.resultReceived || delegate.finishedReason != 1 || delegate.captureError != 5) return;
                printf("ENROLL_DRAFT production_accumulator=1 samples=8 continue_requests=%u partial_not_saved=1 completed_after_commit=1\n", server.continueRequests);
                [operation setDelegate:nil]; operation = nil;
                operation = [device createExtendEnrollTouchIDOperationWithError:&error];
                NativeEnrollmentDelegate *extendDelegate = [NativeEnrollmentDelegate new];
                extendDelegate.completed = dispatch_semaphore_create(0); extendDelegate.extended = dispatch_semaphore_create(0);
                [operation setIdentity:[device identityForUUID:fixtureUUID error:&error]];
                [operation setCredentialSet:[NSData dataWithBytes:"fixture-context!" length:16]];
                ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), extendDelegate);
                BOOL extendStarted = [operation startWithError:&error];
                printf("EXTEND_START class=%s started=%d requests=%u error=%ld\n", object_getClassName(operation), extendStarted, server.matchRequests, (long)error.code);
                if (!extendStarted || error || server.matchRequests != 1) return;
                if (![nativeExtendedEnrollmentUUID(server.extendQuery, server.extendOptions) isEqual:fixtureUUID]) return;
                for (NSDictionary *replacement in @[@{@"BKOptionAuthWithCredentialSet": NSData.data},
                    @{@"BKOptionMatchForCredentialSet": [NSMutableData dataWithLength:16]}, @{@"BKOptionMatchForUnlock": @YES},
                    @{@"BKOptionMatchForExtendEnrollment": @NO}]) {
                    NSMutableDictionary *invalid = [server.extendOptions mutableCopy]; [invalid addEntriesFromDictionary:replacement];
                    if (nativeExtendedEnrollmentUUID(server.extendQuery, invalid)) return;
                }
                if (nativeExtendedEnrollmentUUID(@{@"BKFilterIdentity": nativeIdentityForRecord(server.repository.current.records[0], 502)}, server.extendOptions) ||
                    nativeExtendedEnrollmentUUID(@{@"BKFilterUserID": @501}, server.extendOptions) ||
                    nativeExtendedEnrollmentUUID(@[], server.extendOptions)) return;
                puts("EXTEND_REQUEST_VALIDATION apple_request=1 bad_context_rejected=1 credential_match_rejected=1 unlock_rejected=1 wrong_user_rejected=1 missing_identity_rejected=1");
                for (unsigned updated = 0; updated <= 1; updated++) {
                    [remote matchResult:updated ? server.records[0] : nil details:@{} client:server.lastMatchClient];
                    BOOL observed = !dispatch_semaphore_wait(extendDelegate.extended, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    if (!observed || extendDelegate.updated != updated || extendDelegate.finishedReason) return;
                }
                [operation cancel];
                BOOL extendCancelled = !dispatch_semaphore_wait(extendDelegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("EXTEND_END callbacks=%u cancelled=%d reason=%ld identity_callbacks=%u\n", extendDelegate.extendCallbacks, extendCancelled,
                    (long)extendDelegate.finishedReason, extendDelegate.identityCallbacks);
                if (!extendCancelled || extendDelegate.finishedReason != 2 || extendDelegate.identityCallbacks) return;
                [operation setDelegate:nil]; operation = nil;
                operation = [device createExtendEnrollTouchIDOperationWithError:&error];
                extendDelegate = [NativeEnrollmentDelegate new];
                extendDelegate.completed = dispatch_semaphore_create(0); extendDelegate.extended = dispatch_semaphore_create(0);
                extendDelegate.captureErrorReceived = dispatch_semaphore_create(0);
                [operation setIdentity:[device identityForUUID:fixtureUUID error:&error]];
                [operation setCredentialSet:[NSData dataWithBytes:"fixture-context!" length:16]]; ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), extendDelegate);
                if (![operation startWithError:&error] || error) return;
                ElanFingerprintSupplement *supplement = [[ElanFingerprintSupplement alloc] initWithMatcher:server.session.matcher uuid:fixtureUUID error:&error];
                ElanFingerprintCatalog *beforeSupplement = server.repository.current;
                if (!supplement || error || supplement.sampleCount != 8) return;
                seed = 999;
                for (size_t i = 0; i < sizeof(generated); i++) { seed = seed * 1664525u + 1013904223u; generated[i] = seed >> 24; }
                ElanpressFeatures *otherFeatures = elanpress_image_features(generated, 144, 64);
                unsigned supplementScore = 0;
                ElanEnrollmentSampleResult mismatch = [supplement appendFeatures:otherFeatures toSession:server.session score:&supplementScore error:&error];
                elanpress_features_free(otherFeatures);
                if (mismatch != ElanEnrollmentSampleMismatch || error || server.repository.current != beforeSupplement) return;
                [remote statusMessage:98 client:server.lastMatchClient];
                BOOL retry = !dispatch_semaphore_wait(extendDelegate.captureErrorReceived, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("EXTEND_MISMATCH retry=%d error=%ld callbacks=%u saved_samples=%lu\n", retry, (long)extendDelegate.captureError,
                    extendDelegate.extendCallbacks, supplement.sampleCount);
                if (!retry || extendDelegate.captureError != 5 || extendDelegate.extendCallbacks || extendDelegate.finishedReason) return;
                for (unsigned added = 1; added <= 6; added++) {
                    if ([supplement appendFeatures:features toSession:server.session score:&supplementScore error:&error] != ElanEnrollmentSampleAccepted || error) return;
                    [remote matchResult:nativeIdentityForRecord(supplement.record, 501) details:@{} client:server.lastMatchClient];
                    BOOL observed = !dispatch_semaphore_wait(extendDelegate.extended, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    printf("EXTEND_SAVED added=%u samples=%lu callback=%d updated=%d state_preserved=%d\n", added, supplement.sampleCount,
                        observed, extendDelegate.updated, [server.repository.current.databaseState isEqual:beforeSupplement.databaseState]);
                    if (!observed || !extendDelegate.updated || extendDelegate.finishedReason || supplement.sampleCount != 8 + added ||
                        ![server.repository.current.databaseState isEqual:beforeSupplement.databaseState]) return;
                }
                [operation cancel];
                if (dispatch_semaphore_wait(extendDelegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) || extendDelegate.finishedReason != 2) return;
                puts("EXTEND_TWO_PHASE production_accumulator=1 initial=8 supplement=6 saved=14 mismatch_not_progressed=1 cancelled=1");
                [operation setDelegate:nil]; operation = nil;
                operation = [device createExtendEnrollTouchIDOperationWithError:&error];
                extendDelegate = [NativeEnrollmentDelegate new]; extendDelegate.completed = dispatch_semaphore_create(0);
                extendDelegate.extended = dispatch_semaphore_create(0);
                [operation setIdentity:[device identityForUUID:fixtureUUID error:&error]];
                [operation setCredentialSet:[NSData dataWithBytes:"fixture-context!" length:16]]; ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), extendDelegate);
                if (![operation startWithError:&error] || error) return;
                writerStatus = errSecInteractionNotAllowed; NSError *supplementError = nil;
                ElanEnrollmentSampleResult failedSample = [supplement appendFeatures:features toSession:server.session score:&supplementScore error:&supplementError];
                writerStatus = 0;
                if (failedSample != ElanEnrollmentSampleInvalid || !supplementError || supplement.sampleCount != 14) return;
                [remote statusMessage:66 client:server.lastMatchClient];
                BOOL extendFailed = !dispatch_semaphore_wait(extendDelegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("EXTEND_FAILURE raw=66 finished=%d reason=%ld updates=%u samples=%lu\n", extendFailed,
                    (long)extendDelegate.finishedReason, extendDelegate.extendCallbacks, supplement.sampleCount);
                if (!extendFailed || extendDelegate.extendCallbacks) return;
                [operation setDelegate:nil]; operation = nil;
                NSError *wrongUserError = nil;
                BOOL wrongUserRemoved = [device removeAllIdentitiesForUser:502 error:&wrongUserError];
                if (wrongUserRemoved || !wrongUserError || server.records.count != 1) return;
                BOOL removedAll = [device removeAllIdentitiesForUser:501 error:&error];
                ElanFingerprintCatalog *withoutFixture = server.repository.current;
                if (!removedAll || error || withoutFixture.records.count || publishedIdentities.length) return;
                NSData *emptyState = withoutFixture.databaseState;
                if (![device removeAllIdentitiesForUser:501 error:&error] || error ||
                    ![server.repository.current.databaseState isEqual:emptyState]) return;
                printf("ENROLL_REMOVE_ALL wrong_user_rejected=1 owner_removed=1 repeated_empty_preserves_state=1\n");
                operation = [device createEnrollOperationWithError:&error];
                NativeEnrollmentDelegate *cancelDelegate = [NativeEnrollmentDelegate new];
                cancelDelegate.completed = dispatch_semaphore_create(0);
                [operation setValue:@501 forKey:@"userID"];
                ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), cancelDelegate);
                unsigned cancelsBefore = server.cancelRequests;
                BOOL secondStarted = [operation startWithError:&error];
                if (!secondStarted || error) return;
                [operation cancel];
                BOOL cancelFinished = !dispatch_semaphore_wait(cancelDelegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("ENROLL_CANCEL finished=%d reason=%ld server_cancel=%d identity_callbacks=%u result_callbacks=%u records=%lu\n",
                       cancelFinished, (long)cancelDelegate.finishedReason, server.cancelRequests > cancelsBefore,
                       cancelDelegate.identityCallbacks, cancelDelegate.resultCallbacks, server.records.count);
                result = cancelFinished && cancelDelegate.finishedReason == 2 && server.cancelRequests > cancelsBefore &&
                         !cancelDelegate.identityCallbacks && !cancelDelegate.resultCallbacks && !server.records.count ? 0 : 1;
                ElanFingerprintCatalog *persisted = [ElanFingerprintCatalog decode:catalogData user:501 pid:0x0c1a width:144 height:64 error:NULL];
                if (!persisted || persisted.records.count || ![persisted.databaseState isEqual:withoutFixture.databaseState]) result = 1;
                if (publishedIdentities.length || server.session.matcher.catalog.records.count || server.session.invalidated) result = 1;
                printf("ENROLL_CATALOG production_model=1 memory_storage=1 empty_persisted=%d\n", persisted && !persisted.records.count);
                printf("ENROLL_SESSION production_commit=1 matcher_empty=%d simulated_kernel_empty=%d\n",
                    !server.session.matcher.catalog.records.count, !publishedIdentities.length);
                [operation setDelegate:nil]; operation = nil;
                operation = [device createEnrollOperationWithError:&error];
                NativeEnrollmentDelegate *failureDelegate = [NativeEnrollmentDelegate new];
                failureDelegate.completed = dispatch_semaphore_create(0);
                [operation setValue:@501 forKey:@"userID"];
                ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), failureDelegate);
                if (![operation startWithError:&error] || error) { result = 1; return; }
                [remote statusMessage:66 client:server.enrollClient];
                BOOL failureFinished = !dispatch_semaphore_wait(failureDelegate.completed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                printf("ENROLL_FAILURE raw=66 finished=%d reason=%ld failure=%ld identity_callbacks=%u result_callbacks=%u\n",
                    failureFinished, (long)failureDelegate.finishedReason, (long)failureDelegate.enrollmentFailure, failureDelegate.identityCallbacks, failureDelegate.resultCallbacks);
                if (!failureFinished || failureDelegate.finishedReason != 2 || failureDelegate.enrollmentFailure != 1 || failureDelegate.identityCallbacks || failureDelegate.resultCallbacks) result = 1;
            } @catch (NSException *exception) {
                printf("ENROLL_EXCEPTION %s %s\n", exception.name.UTF8String, exception.reason.UTF8String);
            } @finally {
                elanpress_features_free(features);
                [operation cancel]; [operation setDelegate:nil];
                [transportProbeClientConnection invalidate]; [server.connection invalidate]; [listener invalidate];
                transportProbeClientConnection = nil; transportProbeEndpoint = nil;
                method_exchangeImplementations(original, replacement);
                *cache.result = cache.oldResult; *cache.checked = cache.oldChecked;
                printf("ENROLL_TRANSPORT_DONE status=%d system_service_changed=0 keychain_read=0 sensor_opened=0\n", result);
                dispatch_async(dispatch_get_main_queue(), ^{ done = YES; });
            }
        }
    });
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:20];
    while (!done && deadline.timeIntervalSinceNow > 0)
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    if (!done) { puts("ENROLL_TIMEOUT own_process_exit=1"); _Exit(124); }
    return result;
}

static void enrollmentMetadata(void) {
    const char *classes[] = {"BKDeviceTouchID", "BKDevice", "BKOperation", "BKEnrollOperation",
        "BKEnrollTouchIDOperation", "BKExtendEnrollTouchIDOperation", "BKIdentity", "BiometricKitIdentity", "BKEnrollResultInfo"};
    for (unsigned i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
        Class cls = objc_getClass(classes[i]);
        printf("ENROLL_CLASS %s present=%d\n", classes[i], cls != Nil);
        if (!cls) continue;
        for (int meta = 0; meta < 2; meta++) {
            unsigned count = 0;
            Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &count);
            for (unsigned j = 0; j < count; j++)
                printf("ENROLL_METHOD %s %c%s %s\n", classes[i], meta ? '+' : '-',
                    sel_getName(method_getName(methods[j])), method_getTypeEncoding(methods[j]));
            free(methods);
        }
    }
    unsigned count = 0;
    Protocol *__unsafe_unretained *protocols = objc_copyProtocolList(&count);
    for (unsigned i = 0; i < count; i++) {
        const char *name = protocol_getName(protocols[i]);
        if (strncmp(name, "BK", 2) || (!strstr(name, "Enroll") && !strstr(name, "Operation"))) continue;
        for (int required = 0; required < 2; required++) {
            unsigned methodCount = 0;
            struct objc_method_description *methods = protocol_copyMethodDescriptionList(protocols[i], required, YES, &methodCount);
            for (unsigned j = 0; j < methodCount; j++)
                printf("ENROLL_PROTOCOL %s %s %s\n", name, sel_getName(methods[j].name), methods[j].types);
            free(methods);
        }
    }
    free(protocols);
}

static int enrollmentUIMetadata(void) {
    if (!dlopen("/System/Library/PrivateFrameworks/BiometricKitUI.framework/BiometricKitUI", RTLD_LAZY | RTLD_LOCAL)) return 2;
    unsigned imageCount = 0;
    const char **images = objc_copyImageNames(&imageCount);
    for (unsigned i = 0; i < imageCount; i++) {
        if (!strstr(images[i], "/BiometricKitUI.framework/")) continue;
        unsigned count = 0;
        const char **names = objc_copyClassNamesForImage(images[i], &count);
        for (unsigned j = 0; j < count; j++) {
            Class cls = objc_getClass(names[j]);
            printf("ENROLL_UI_CLASS %s super=%s\n", names[j], class_getName(class_getSuperclass(cls)));
            for (int meta = 0; meta < 2; meta++) {
                unsigned methods = 0;
                Method *list = class_copyMethodList(meta ? object_getClass(cls) : cls, &methods);
                for (unsigned k = 0; k < methods; k++)
                    printf("ENROLL_UI_METHOD %s %c%s %s\n", names[j], meta ? '+' : '-',
                        sel_getName(method_getName(list[k])), method_getTypeEncoding(list[k]));
                free(list);
            }
        }
        free(names);
    }
    free(images);
    puts("ENROLL_UI_METADATA_DONE controllers_created=0 windows_opened=0 service_replaced=0");
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        biometricFramework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_NOW | RTLD_LOCAL);
        if (!biometricFramework) return 2;
        if (argc == 2 && !strcmp(argv[1], "--metadata")) {
            enrollmentMetadata();
            puts("ENROLL_METADATA_DONE system_service_changed=0 keychain_read=0 sensor_opened=0");
            return 0;
        }
        if (argc == 2 && !strcmp(argv[1], "--transport")) return enrollmentTransport();
        if (argc == 2 && !strcmp(argv[1], "--ui-metadata")) return enrollmentUIMetadata();
        return 2;
    }
}
