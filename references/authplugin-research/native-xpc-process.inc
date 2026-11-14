#include "native-xpc-service-protocol.h"

static int nativeXPCProcessProbe(void) {
    __block BOOL finished = NO;
    __block int result = 1;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            NSXPCConnection *control = [[NSXPCConnection alloc] initWithServiceName:ELAN_TRANSPORT_XPC_SERVICE];
            control.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ElanTransportStudyControl)];
            [control resume];
            __block BOOL remoteError = NO;
            id<ElanTransportStudyControl> remote = [control synchronousRemoteObjectProxyWithErrorHandler:^(NSError *error) {
                remoteError = YES;
                printf("PROCESS_TRANSPORT_ERROR domain=%s code=%ld\n", error.domain.UTF8String, (long)error.code);
            }];
            PlatformCache cache = {0};
            BOOL platformChanged = NO, redirected = NO;
            Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
            Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
            LAContext *context = nil;
            id operation = nil;
            @try {
                __block NSDictionary *peer = nil;
                [remote openEndpointWithReply:^(NSXPCListenerEndpoint *endpoint, NSDictionary *info) {
                    transportProbeEndpoint = endpoint;
                    peer = info;
                }];
                BOOL separate = [peer[@"pid"] intValue] > 0 && [peer[@"pid"] intValue] != getpid() &&
                                [peer[@"uid"] unsignedIntValue] == geteuid() && [peer[@"allowed_pid"] intValue] == getpid();
                printf("PROCESS_TRANSPORT_PEER separate=%d client_pid=%d service_pid=%d\n", separate, getpid(), [peer[@"pid"] intValue]);
                if (remoteError || !separate || !transportProbeEndpoint) return;
                if (!overridePlatformCache(&cache)) return;
                platformChanged = YES;
                method_exchangeImplementations(original, replacement);
                redirected = YES;
                context = [LAContext new];
                NSError *error = nil;
                if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) return;
                SEL exportSelector = sel_registerName("externalizedContext");
                Method exportMethod = class_getInstanceMethod(LAContext.class, exportSelector);
                char *type = exportMethod ? method_copyReturnType(exportMethod) : NULL;
                BOOL exportSupported = exportMethod && method_getNumberOfArguments(exportMethod) == 2 && type && type[0] == '@';
                free(type);
                if (!exportSupported) return;
                NSData *handle = ((id (*)(id, SEL))objc_msgSend)(context, exportSelector);
                if (![handle isKindOfClass:NSData.class] || handle.length != 16) return;
                id descriptor = [objc_getClass("BKDeviceDescriptor") deviceDescriptorForType:1];
                id device = [objc_getClass("BKDevice") deviceWithDescriptor:descriptor error:&error];
                if (!device || error) return;
                NSUInteger hardware = NSUIntegerMax;
                BOOL hardwareOK = [device deviceHardwareState:&hardware error:&error];
                printf("PROCESS_TRANSPORT_DEVICE class=%s hardware_ok=%d hardware=%lu error=%ld\n",
                       object_getClassName(device), hardwareOK, (unsigned long)hardware, (long)error.code);
                if (!hardwareOK || hardware != 0 || error) return;
                for (NSInteger availability = 1; availability <= 3; availability++) {
                    __block BOOL configured = NO;
                    [remote configureContext:handle availability:availability reply:^(BOOL value) { configured = value; }];
                    NSInteger decoded = -1;
                    error = nil;
                    BOOL ok = [device biometryAvailability:&decoded forUser:getuid() error:&error];
                    BOOL passed = configured && !remoteError && ok && !error && decoded == availability;
                    printf("PROCESS_TRANSPORT_AVAILABILITY fixture=%ld decoded=%ld pass=%d\n", (long)availability, (long)decoded, passed);
                    if (!passed) return;
                }
                NSArray *identities = [device identitiesForUser:getuid() error:&error];
                printf("PROCESS_TRANSPORT_IDENTITIES count=%lu error=%ld\n", (unsigned long)identities.count, (long)error.code);
                if (!identities || identities.count || error) return;
                __block NSUUID *fixtureUUID = nil;
                [remote useFixtureIdentityWithReply:^(NSUUID *value) { fixtureUUID = value; }];
                identities = [device identitiesForUser:getuid() error:&error];
                BOOL identityPassed = !remoteError && !error && identities.count == 1 &&
                                      [[identities[0] valueForKey:@"uuid"] isEqual:fixtureUUID];
                printf("PROCESS_TRANSPORT_FIXTURE_IDENTITY count=%lu native_class=%s uuid_preserved=%d\n",
                       (unsigned long)identities.count, identities.count ? object_getClassName(identities[0]) : "none", identityPassed);
                if (!identityPassed) return;
                for (NSInteger purpose = 3; purpose <= 4; purpose++) {
                    operation = [device createMatchOperationWithError:&error];
                    if (!operation || error) return;
                    [operation setPurpose:purpose];
                    [operation setUserID:@(getuid())];
                    [operation setCredentialSet:handle];
                    NativeMatchControlDelegate *delegate = [NativeMatchControlDelegate new];
                    delegate.resultSignal = dispatch_semaphore_create(0);
                    ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), delegate);
                    BOOL started = [operation startWithError:&error];
                    __block BOOL sent = NO;
                    if (started && !error) [remote sendNegativeWithReply:^(BOOL value) { sent = value; }];
                    BOOL callback = sent && !dispatch_semaphore_wait(delegate.resultSignal, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    BOOL negativePassed = callback && delegate.matchEvents == 1 && !delegate.receivedIdentity && !delegate.receivedCredential;
                    __block BOOL fixtureSent = NO;
                    if (negativePassed) [remote sendFixtureMatchWithReply:^(BOOL value) { fixtureSent = value; }];
                    BOOL fixtureCallback = fixtureSent && !dispatch_semaphore_wait(delegate.resultSignal, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                    BOOL fixturePassed = fixtureCallback && delegate.matchEvents == 2 && delegate.receivedIdentity && !delegate.receivedCredential;
                    [operation cancel];
                    [operation setDelegate:nil];
                    [operation setCredentialSet:nil];
                    operation = nil;
                    __block NSDictionary *report = nil;
                    [remote reportWithReply:^(NSDictionary *value) { report = value; }];
                    BOOL passed = !remoteError && started && !error && negativePassed && fixturePassed &&
                                  [report[@"context_received"] boolValue] && [report[@"cancels"] unsignedIntValue] >= purpose - 2;
                    printf("PROCESS_TRANSPORT_MATCH purpose=%ld started=%d own_context_received=%d negative_callback=%d cancels=%u pass=%d\n",
                           (long)purpose, started, [report[@"context_received"] boolValue], callback,
                           [report[@"cancels"] unsignedIntValue], passed);
                    printf("PROCESS_TRANSPORT_FIXTURE_MATCH purpose=%ld fixture_callback=%d credential_added=%d pass=%d\n",
                           (long)purpose, fixtureCallback, delegate.receivedCredential, fixturePassed);
                    if (!passed) return;
                }
                result = 0;
            } @catch (NSException *exception) {
                printf("PROCESS_TRANSPORT_EXCEPTION name=%s\n", exception.name.UTF8String);
                result = 2;
            } @finally {
                if (operation) { [operation cancel]; [operation setDelegate:nil]; [operation setCredentialSet:nil]; }
                [context invalidate];
                __block BOOL closed = NO;
                if (!remoteError) [remote closeWithReply:^(BOOL value) { closed = value; }];
                [transportProbeClientConnection invalidate];
                if (redirected) method_exchangeImplementations(original, replacement);
                transportProbeClientConnection = nil;
                transportProbeEndpoint = nil;
                if (platformChanged) { *cache.result = cache.oldResult; *cache.checked = cache.oldChecked; }
                BOOL (*platform)(char *) = dlsym(biometricFramework, "isTouchIDPlatformWithFailure");
                printf("PROCESS_TRANSPORT_CLEANUP service_closed=%d restored_platform=%d context_invalidated=1\n", closed, platform ? platform(NULL) : -1);
                if (!closed) result = 1;
                [control invalidate];
                printf("PROCESS_TRANSPORT_DONE status=%d credentials_submitted=0 system_service_replaced=0\n", result);
                dispatch_async(dispatch_get_main_queue(), ^{ finished = YES; });
            }
        }
    });
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:20];
    while (!finished && [deadline timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    if (!finished) { puts("PROCESS_TRANSPORT_TIMEOUT"); _Exit(124); }
    return result;
}
