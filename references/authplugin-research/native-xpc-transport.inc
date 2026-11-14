@interface NSObject (NativeBiometricTransportResearch)
- (instancetype)initWithDeviceType:(NSUInteger)deviceType clientType:(NSUInteger)clientType;
- (int)connect;
- (void)disconnect;
- (int)getDeviceHardwareState:(unsigned int *)state;
- (int)getBiometryAvailability:(NSInteger *)availability forUser:(unsigned int)user;
- (NSArray *)identities:(NSDictionary *)query;
- (void)invalidateConnection;
+ (instancetype)deviceDescriptorForType:(NSInteger)type;
+ (instancetype)deviceWithDescriptor:(id)descriptor error:(NSError **)error;
- (BOOL)deviceHardwareState:(NSUInteger *)state error:(NSError **)error;
- (BOOL)biometryAvailability:(NSInteger *)availability forUser:(unsigned int)user error:(NSError **)error;
- (NSArray *)identitiesForUser:(unsigned int)user error:(NSError **)error;
- (id)createMatchOperationWithError:(NSError **)error;
- (void)setPurpose:(NSInteger)purpose;
- (void)setUserID:(id)user;
- (void)setCredentialSet:(NSData *)credentialSet;
- (NSDictionary *)optionsDictionaryWithError:(NSError **)error;
- (void)setDelegate:(id)delegate;
- (BOOL)startWithError:(NSError **)error;
- (void)cancel;
- (instancetype)initWithServerIdentity:(id)identity details:(NSDictionary *)details device:(id)device;
- (void)matchResult:(id)identity details:(NSDictionary *)details client:(uint64_t)client;
- (id)identity;
- (BOOL)credentialAdded;
@end

static NSXPCListenerEndpoint *transportProbeEndpoint;
static NSXPCConnection *transportProbeClientConnection;
static unsigned transportProbeRedirects;

@interface NSXPCConnection (NativeBiometricTransportResearch)
- (instancetype)elanTransport_initWithMachServiceName:(NSString *)name
                                             options:(NSXPCConnectionOptions)options
    __attribute__((objc_method_family(init)));
@end

@implementation NSXPCConnection (NativeBiometricTransportResearch)
- (instancetype)elanTransport_initWithMachServiceName:(NSString *)name
                                             options:(NSXPCConnectionOptions)options {
    if ([name isEqualToString:@"com.apple.biometrickitd"]) {
        if (!transportProbeEndpoint) return nil;
        self = [self initWithListenerEndpoint:transportProbeEndpoint];
        transportProbeClientConnection = self;
        transportProbeRedirects++;
        printf("TRANSPORT_REDIRECT anonymous_endpoint=1 original_options=%lu privileged=%d\n",
               (unsigned long)options, (options & NSXPCConnectionPrivileged) != 0);
        return self;
    }
    return [self elanTransport_initWithMachServiceName:name options:options];
}
@end

#include "native-xpc-server.inc"

@interface NativeMatchControlDelegate : NSObject
@property(nonatomic, strong) dispatch_semaphore_t resultSignal;
@property(nonatomic) unsigned matchEvents;
@property(nonatomic) BOOL receivedIdentity;
@property(nonatomic) BOOL receivedCredential;
@end
@implementation NativeMatchControlDelegate
- (void)operation:(id)operation stateChanged:(NSInteger)state {
    printf("TRANSPORT_OPERATION state=%ld\n", (long)state);
}
- (void)operation:(id)operation finishedWithReason:(NSInteger)reason {
    printf("TRANSPORT_OPERATION finished_reason=%ld\n", (long)reason);
}
- (void)operation:(id)operation presenceStateChanged:(NSInteger)state {
    printf("TRANSPORT_OPERATION presence=%ld\n", (long)state);
}
- (void)matchOperation:(id)operation matchedWithResult:(id)result {
    self.matchEvents++;
    self.receivedIdentity = ((id (*)(id, SEL))objc_msgSend)(result, @selector(identity)) != nil;
    self.receivedCredential = [result credentialAdded];
    printf("TRANSPORT_MATCH_EVENT class=%s identity=%d credential_added=%d\n",
           object_getClassName(result), self.receivedIdentity, self.receivedCredential);
    dispatch_semaphore_signal(self.resultSignal);
}
@end

@interface NativeMatchDetailsKeys : NSDictionary
@end
@implementation NativeMatchDetailsKeys
- (NSUInteger)count { return 0; }
- (NSEnumerator *)keyEnumerator { return [@[] objectEnumerator]; }
- (id)objectForKey:(id)key {
    printf("TRANSPORT_RESULT_KEY %s\n", [key description].UTF8String);
    return nil;
}
@end

static BOOL nativeMatchControlProbe(id device, NativeBiometricTransportServer *server) {
    NSError *error = nil;
    id operation = [device createMatchOperationWithError:&error];
    printf("TRANSPORT_OPERATION class=%s error=%ld\n", operation ? object_getClassName(operation) : "nil", (long)error.code);
    if (!operation) return NO;
    [operation setUserID:@(getuid())];
    NSInteger selectedPurpose = -1;
    for (NSInteger purpose = 0; purpose <= 5; purpose++) {
        [operation setPurpose:purpose];
        error = nil;
        NSDictionary *options = [operation optionsDictionaryWithError:&error];
        printf("TRANSPORT_OPERATION_OPTIONS purpose=%ld valid=%d error=%ld keys=%s\n", (long)purpose,
               options != nil, (long)error.code,
               options ? [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String : "none");
        if (options && !error && selectedPurpose < 0) selectedPurpose = purpose;
    }
    if (selectedPurpose < 0) return NO;
    [operation setPurpose:selectedPurpose];
    NativeMatchControlDelegate *delegate = [NativeMatchControlDelegate new];
    delegate.resultSignal = dispatch_semaphore_create(0);
    ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), delegate);
    error = nil;
    BOOL started = [operation startWithError:&error];
    printf("TRANSPORT_OPERATION_START ok=%d error=%ld\n", started, (long)error.code);
    BOOL callbackReceived = NO;
    if (started) {
        id remote = [server.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            printf("TRANSPORT_MATCH_SEND_ERROR %ld\n", (long)error.code);
        }];
        [remote matchResult:nil details:@{@"BKMatchDetailCredentialAdded": @NO,
                                         @"BKMatchDetailUnlocked": @NO,
                                         @"BKMatchDetailResultIgnored": @NO}
                     client:server.lastMatchClient];
        callbackReceived = dispatch_semaphore_wait(delegate.resultSignal, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0;
        [operation cancel];
    }
    ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), nil);
    id details = [NativeMatchDetailsKeys new];
    id result = [[objc_getClass("BKMatchResultInfo") alloc] initWithServerIdentity:nil details:details device:device];
    printf("TRANSPORT_RESULT_DECODER created=%d empty_identity=1 event_sent=0\n", result != nil);
    printf("TRANSPORT_CONTROL matches=%u cancels=%u negative_event_received=%d\n", server.matchRequests, server.cancelRequests, callbackReceived);
    return started && !error && server.matchRequests == 1 && server.cancelRequests >= 1 &&
           callbackReceived && delegate.matchEvents == 1 && !delegate.receivedIdentity && !delegate.receivedCredential;
}

static BOOL nativeContextOptionsProbe(id device, NativeBiometricTransportServer *server) {
    LAContext *context = [LAContext new];
    NSData *credentialSet = nil;
    id operation = nil;
    BOOL allPassed = YES;
    @try {
        NSError *error = nil;
        BOOL usable = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error];
        SEL exportSelector = sel_registerName("externalizedContext");
        Method exportMethod = class_getInstanceMethod(LAContext.class, exportSelector);
        char *returnType = exportMethod ? method_copyReturnType(exportMethod) : NULL;
        BOOL supported = exportMethod && method_getNumberOfArguments(exportMethod) == 2 && returnType && returnType[0] == '@';
        free(returnType);
        printf("TRANSPORT_OWN_CONTEXT usable=%d export_supported=%d error=%ld\n", usable, supported, (long)error.code);
        if (!usable || !supported) return NO;
        id data = ((id (*)(id, SEL))objc_msgSend)(context, exportSelector);
        if (![data isKindOfClass:NSData.class] || [data length] != 16) return NO;
        credentialSet = data;
        server.expectedCredentialSet = credentialSet;
        for (NSInteger purpose = 3; purpose <= 4; purpose++) {
            error = nil;
            operation = [device createMatchOperationWithError:&error];
            if (!operation || error) return NO;
            [operation setPurpose:purpose];
            [operation setUserID:@(getuid())];
            [operation setCredentialSet:credentialSet];
            NSDictionary *options = [operation optionsDictionaryWithError:&error];
            printf("TRANSPORT_CONTEXT_OPTIONS purpose=%ld valid=%d error=%ld keys=%s\n", (long)purpose,
                   options != nil, (long)error.code,
                   options ? [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String : "none");
            if (!options || error) return NO;
            NativeMatchControlDelegate *delegate = [NativeMatchControlDelegate new];
            delegate.resultSignal = dispatch_semaphore_create(0);
            ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), delegate);
            BOOL started = [operation startWithError:&error];
            BOOL received = NO;
            if (started && !error) {
                id remote = [server.connection remoteObjectProxyWithErrorHandler:^(NSError *sendError) {
                    printf("TRANSPORT_CONTEXT_SEND_ERROR code=%ld\n", (long)sendError.code);
                }];
                [remote matchResult:nil details:@{@"BKMatchDetailCredentialAdded": @NO,
                                                 @"BKMatchDetailUnlocked": @NO,
                                                 @"BKMatchDetailResultIgnored": @NO}
                             client:server.lastMatchClient];
                received = !dispatch_semaphore_wait(delegate.resultSignal, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
            }
            [operation cancel];
            ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), nil);
            [operation setCredentialSet:nil];
            operation = nil;
            BOOL passed = started && !error && received && delegate.matchEvents == 1 &&
                          !delegate.receivedIdentity && !delegate.receivedCredential && server.receivedExpectedCredentialSet;
            printf("TRANSPORT_CONTEXT_RESULT purpose=%ld started=%d own_context_received=%d negative_callback=%d pass=%d\n",
                   (long)purpose, started, server.receivedExpectedCredentialSet, received, passed);
            allPassed &= passed;
            if (!passed) break;
        }
    } @finally {
        if (operation) {
            [operation cancel];
            ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), nil);
            [operation setCredentialSet:nil];
        }
        server.expectedCredentialSet = nil;
        credentialSet = nil;
        [context invalidate];
        puts("TRANSPORT_OWN_CONTEXT invalidated=1 handle_contents_logged=0 credentials_submitted=0");
    }
    return allPassed;
}

static int nativeXPCTransportProbe(unsigned matchControl) {
    Class clientClass = objc_getClass("BiometricKitXPCClient");
    if (!clientClass || !objc_getProtocol("BiometricKitXpcProtocol") ||
        !objc_getProtocol("BiometricKitDelegateXpcProtocol")) return 4;
    const char *selectors[] = {"initWithDeviceType:clientType:", "connect", "getDeviceHardwareState:",
                              "getBiometryAvailability:forUser:", "identities:", "disconnect"};
    for (unsigned i = 0; i < sizeof(selectors) / sizeof(selectors[0]); i++) {
        Method method = class_getInstanceMethod(clientClass, sel_registerName(selectors[i]));
        if (!method) return 4;
        printf("TRANSPORT_CLIENT_METHOD %s %s\n", selectors[i], method_getTypeEncoding(method));
    }
    PlatformCache platformCache = {0};
    if (!overridePlatformCache(&platformCache)) return 3;
    NativeBiometricTransportServer *server = [NativeBiometricTransportServer new];
    NSXPCListener *listener = [NSXPCListener anonymousListener];
    listener.delegate = server;
    transportProbeEndpoint = listener.endpoint;
    [listener resume];
    Method original = class_getInstanceMethod([NSXPCConnection class], @selector(initWithMachServiceName:options:));
    Method replacement = class_getInstanceMethod([NSXPCConnection class], @selector(elanTransport_initWithMachServiceName:options:));
    method_exchangeImplementations(original, replacement);
    __block BOOL finished = NO;
    __block int result = 1;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            @try {
                id client = [[clientClass alloc] initWithDeviceType:1 clientType:1];
                printf("TRANSPORT_CLIENT created=%d\n", client != nil);
                if (client) {
                    int connected = [client connect];
                    unsigned int hardware = UINT32_MAX;
                    NSInteger availability = -1;
                    int hardwareStatus = [client getDeviceHardwareState:&hardware];
                    int availabilityStatus = [client getBiometryAvailability:&availability forUser:getuid()];
                    NSArray *identities = [client identities:@{}];
                    printf("TRANSPORT_RESULT connected=%d hardware_status=%d hardware=%u availability_status=%d availability=%ld identities=%lu\n",
                           connected, hardwareStatus, hardware, availabilityStatus, (long)availability,
                           (unsigned long)identities.count);
                    result = connected == 0 && hardwareStatus == 0 && hardware == 0 &&
                             availabilityStatus == 0 && availability == 0 && identities && identities.count == 0 ? 0 : 1;
                    NSError *error = nil;
                    id descriptor = [objc_getClass("BKDeviceDescriptor") deviceDescriptorForType:1];
                    id device = [objc_getClass("BKDevice") deviceWithDescriptor:descriptor error:&error];
                    printf("TRANSPORT_DEVICE class=%s error=%ld\n", device ? object_getClassName(device) : "nil", (long)error.code);
                    if (device) {
                        NSUInteger deviceHardware = NSUIntegerMax;
                        error = nil;
                        BOOL hardwareOK = [device deviceHardwareState:&deviceHardware error:&error];
                        if (!hardwareOK || error) result = 1;
                        for (NSInteger value = 1; value <= 3; value++) {
                            server.fixtureAvailability = value;
                            NSInteger decoded = -1;
                            error = nil;
                            BOOL availableOK = [device biometryAvailability:&decoded forUser:getuid() error:&error];
                            printf("TRANSPORT_DEVICE_AVAILABILITY fixture=%ld ok=%d decoded=%ld error=%ld\n",
                                   (long)value, availableOK, (long)decoded, (long)error.code);
                            if (!availableOK || decoded != value || error) result = 1;
                        }
                        error = nil;
                        NSArray *deviceIdentities = [device identitiesForUser:getuid() error:&error];
                        printf("TRANSPORT_DEVICE_RESULT hardware_ok=%d hardware=%lu identities=%lu error=%ld\n",
                               hardwareOK, (unsigned long)deviceHardware,
                               (unsigned long)deviceIdentities.count, (long)error.code);
                        if (!deviceIdentities || error) result = 1;
                        if (matchControl == 1 && !nativeMatchControlProbe(device, server)) result = 1;
                        if (matchControl == 2 && !nativeContextOptionsProbe(device, server)) result = 1;
                    } else result = 1;
                    [client disconnect];
                    [client invalidateConnection];
                }
            } @catch (NSException *exception) {
                printf("TRANSPORT_EXCEPTION %s %s\n", exception.name.UTF8String, exception.reason.UTF8String);
                result = 2;
            }
            dispatch_async(dispatch_get_main_queue(), ^{ finished = YES; });
        }
    });
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:15];
    while (!finished && [deadline timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    if (!finished) {
        puts("TRANSPORT_TIMEOUT own_process_exit=1");
        _Exit(124);
    }
    [transportProbeClientConnection invalidate];
    [server.connection invalidate];
    server.connection = nil;
    [listener invalidate];
    method_exchangeImplementations(original, replacement);
    transportProbeClientConnection = nil;
    transportProbeEndpoint = nil;
    *platformCache.result = platformCache.oldResult;
    *platformCache.checked = platformCache.oldChecked;
    BOOL (*platform)(char *) = dlsym(biometricFramework, "isTouchIDPlatformWithFailure");
    printf("TRANSPORT_PLATFORM restored_available=%d\n", platform(NULL));
    printf("TRANSPORT_COUNTS redirects=%u connects=%u hardware=%u availability=%u identities=%u\n",
           transportProbeRedirects, server.connects, server.hardwareReads, server.availabilityReads, server.identityReads);
    if (!transportProbeRedirects || !server.connects || !server.hardwareReads || !server.availabilityReads || !server.identityReads) result = 1;
    printf("TRANSPORT_DONE status=%d system_service_replaced=0 credentials_submitted=0\n", result);
    const char *metadataClasses[] = {"BiometricKitIdentity", "BKIdentity", "BKMatchOperation", "BKMatchResultInfo", "BKOperation"};
    for (unsigned i = 0; i < sizeof(metadataClasses) / sizeof(metadataClasses[0]); i++) {
        Class cls = objc_getClass(metadataClasses[i]);
        unsigned count = 0;
        Method *methods = class_copyMethodList(cls, &count);
        printf("TRANSPORT_METADATA_CLASS %s\n", metadataClasses[i]);
        for (unsigned j = 0; j < count; j++)
            printf("TRANSPORT_METADATA_METHOD %s %s\n", sel_getName(method_getName(methods[j])), method_getTypeEncoding(methods[j]));
        free(methods);
    }
    return result;
}
