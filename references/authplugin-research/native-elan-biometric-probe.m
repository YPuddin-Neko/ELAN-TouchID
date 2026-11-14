#define ELAN_NO_APP_MAIN 1
#include "../../elan-fingerprint-macos/src/ElanUnlock.m"
#define NATIVE_STACK_NO_MAIN 1
#include "native-stack-probe.m"

@interface ElanBiometricTransportServer : NativeBiometricTransportServer
@property(nonatomic, strong) id enrolledIdentity;
@property(nonatomic, strong) dispatch_semaphore_t captureDone;
@property(atomic) BOOL captureActive;
@property(atomic) BOOL liveMatched;
@property(atomic) BOOL captureFailed;
@end

@implementation ElanBiometricTransportServer
- (void)configureConnection:(NSXPCConnection *)connection {
    [super configureConnection:connection];
    Class identityClass = NSClassFromString(@"BiometricKitIdentity");
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, identityClass, nil]
                                forSelector:@selector(identities:client:replyBlock:) argumentIndex:0 ofReply:YES];
    [connection.remoteObjectInterface setClasses:[NSSet setWithObject:identityClass]
                                    forSelector:@selector(matchResult:details:client:) argumentIndex:0 ofReply:NO];
    [connection.remoteObjectInterface setClasses:[NSSet setWithObjects:NSDictionary.class, NSNumber.class, NSString.class, nil]
                                    forSelector:@selector(matchResult:details:client:) argumentIndex:1 ofReply:NO];
}
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    self.identityReads++;
    reply(self.enrolledIdentity ? @[self.enrolledIdentity] : @[]);
}
- (void)match:(NSArray *)identities options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (self.captureActive || !self.enrolledIdentity || cancelled) { reply(1); return; }
    self.captureActive = YES;
    self.liveMatched = NO;
    self.captureFailed = NO;
    self.captureDone = dispatch_semaphore_create(0);
    [super match:identities options:options async:async client:client replyBlock:reply];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            @try {
                ElanpressFeatures *features = capture(&sensor);
                if (!features) {
                    self.captureFailed = YES;
                    puts("ELAN_NATIVE_CAPTURE failed=1");
                    return;
                }
                unsigned score = match(features, prints, printCount);
                studyFreeFeatures(features);
                self.liveMatched = score >= ELANPRESS_MATCH_MIN_PAIRS;
                printf("ELAN_NATIVE_CAPTURE score=%u matched=%d\n", score, self.liveMatched);
                if (cancelled) return;
                id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                    self.captureFailed = YES;
                    printf("ELAN_NATIVE_SEND_ERROR code=%ld\n", (long)error.code);
                }];
                [remote matchResult:self.liveMatched ? self.enrolledIdentity : nil
                            details:@{@"BKMatchDetailCredentialAdded": @NO,
                                      @"BKMatchDetailUnlocked": @NO,
                                      @"BKMatchDetailResultIgnored": @NO}
                             client:client];
            } @finally {
                self.captureActive = NO;
                dispatch_semaphore_signal(self.captureDone);
            }
        }
    });
}
- (void)cancel:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (self.captureActive) cancelled = 1;
    [super cancel:client replyBlock:reply];
}
@end

static id enrollmentIdentity(void) {
    id identity = [NSClassFromString(@"BiometricKitIdentity") new];
    [identity setValue:NSUUID.UUID forKey:@"uuid"];
    [identity setValue:@1 forKey:@"type"];
    [identity setValue:@(getuid()) forKey:@"userID"];
    [identity setValue:@"ELAN enrolled finger" forKey:@"name"];
    [identity setValue:NSDate.date forKey:@"creationTime"];
    return identity;
}

static int identityCodecTest(void) {
    @try {
        id identity = enrollmentIdentity();
        NSError *error = nil;
        NSData *data = [NSKeyedArchiver archivedDataWithRootObject:identity requiringSecureCoding:YES error:&error];
        id restored = data ? [NSKeyedUnarchiver unarchivedObjectOfClass:NSClassFromString(@"BiometricKitIdentity") fromData:data error:&error] : nil;
        BOOL equal = restored && [[identity valueForKey:@"uuid"] isEqual:[restored valueForKey:@"uuid"]];
        printf("ELAN_NATIVE_IDENTITY_CODEC ok=%d uuid_class=%s type=%ld error=%ld\n", equal,
               object_getClassName([restored valueForKey:@"uuid"]), (long)[[restored valueForKey:@"type"] integerValue], (long)error.code);
        return equal && !error ? 0 : 1;
    } @catch (NSException *exception) {
        printf("ELAN_NATIVE_IDENTITY_EXCEPTION %s\n", exception.reason.UTF8String);
        return 1;
    }
}

static int identityTransportTest(void) {
    PlatformCache cache = {0};
    if (!overridePlatformCache(&cache)) return 4;
    ElanBiometricTransportServer *server = [ElanBiometricTransportServer new];
    server.enrolledIdentity = enrollmentIdentity();
    NSXPCListener *listener = [NSXPCListener anonymousListener];
    listener.delegate = server;
    transportProbeEndpoint = listener.endpoint;
    [listener resume];
    Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
    Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
    method_exchangeImplementations(original, replacement);
    int status = 1;
    @try {
        NSError *error = nil;
        id descriptor = [objc_getClass("BKDeviceDescriptor") deviceDescriptorForType:1];
        id device = [objc_getClass("BKDevice") deviceWithDescriptor:descriptor error:&error];
        NSArray *identities = device ? [device identitiesForUser:getuid() error:&error] : nil;
        BOOL same = identities.count == 1 && [[identities[0] valueForKey:@"uuid"] isEqual:[server.enrolledIdentity valueForKey:@"uuid"]];
        printf("ELAN_NATIVE_IDENTITY_XPC count=%lu class=%s uuid_preserved=%d error=%ld\n",
               (unsigned long)identities.count, identities.count ? object_getClassName(identities[0]) : "none", same, (long)error.code);
        status = same && !error ? 0 : 1;
    } @finally {
        [transportProbeClientConnection invalidate]; [server.connection invalidate]; server.connection = nil;
        [listener invalidate]; method_exchangeImplementations(original, replacement);
        transportProbeEndpoint = nil; transportProbeClientConnection = nil;
        *cache.result = cache.oldResult; *cache.checked = cache.oldChecked;
    }
    printf("ELAN_NATIVE_IDENTITY_XPC_DONE status=%d fixture_only=1 match_events=0\n", status);
    return status;
}

static int liveNativeMatchStudy(void) {
    int result = 1;
    PlatformCache cache = {0};
    BOOL platformChanged = NO, redirected = NO;
    NSXPCListener *listener = nil;
    ElanBiometricTransportServer *server = nil;
    Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
    Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
    NSMutableData *stored = nil;
    @try {
        puts("ELAN 原生匹配接口测试：先用未录入手指，再用已录入手指。按 Control+C 可退出。");
        puts("这轮观察苹果匹配对象接收的结果，不会解锁系统。");
        if (!pause_prompt("先移开手指，按回车读取已保存指纹。")) return 1;
        if (!open_sensor(&sensor)) return 2;
        stored = loadSecret(@"fingerprints-v1", YES);
        if (!unpackPrints(stored)) { puts("无法读取已录入指纹。请记录钥匙串提示后结束测试。"); return 3; }
        wipe(stored.mutableBytes, stored.length); stored = nil;
        printf("ELAN_NATIVE templates=%d threshold=%d\n", printCount, ELANPRESS_MATCH_MIN_PAIRS);
        if (!overridePlatformCache(&cache)) return 4;
        platformChanged = YES;
        server = [ElanBiometricTransportServer new];
        server.enrolledIdentity = enrollmentIdentity();
        listener = [NSXPCListener anonymousListener];
        listener.delegate = server;
        transportProbeEndpoint = listener.endpoint;
        [listener resume];
        method_exchangeImplementations(original, replacement); redirected = YES;
        NSError *error = nil;
        id descriptor = [objc_getClass("BKDeviceDescriptor") deviceDescriptorForType:1];
        id device = [objc_getClass("BKDevice") deviceWithDescriptor:descriptor error:&error];
        NSArray *identities = device ? [device identitiesForUser:getuid() error:&error] : nil;
        printf("ELAN_NATIVE_DEVICE class=%s identities=%lu identity_class=%s error=%ld\n",
               device ? object_getClassName(device) : "nil", (unsigned long)identities.count,
               identities.count ? object_getClassName(identities[0]) : "none", (long)error.code);
        if (!device || error || identities.count != 1) return 5;
        for (int step = 0; step < 2 && !cancelled; step++) {
            puts(step == 0 ? "1/2：准备另一根未录入的手指。" : "2/2：准备已录入的手指，保持指腹中心位置。");
            if (!pause_prompt("先松开手指，准备好后按回车，看到采集提示再按。")) break;
            error = nil;
            id operation = [device createMatchOperationWithError:&error];
            if (!operation || error) break;
            [operation setPurpose:1];
            [operation setUserID:@(getuid())];
            NativeMatchControlDelegate *delegate = [NativeMatchControlDelegate new];
            delegate.resultSignal = dispatch_semaphore_create(0);
            server.captureDone = nil;
            ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), delegate);
            BOOL started = [operation startWithError:&error];
            BOOL received = NO;
            if (started) {
                NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:40];
                while (!cancelled && [deadline timeIntervalSinceNow] > 0 && !server.captureFailed) {
                    if (!dispatch_semaphore_wait(delegate.resultSignal, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC))) { received = YES; break; }
                }
            }
            if (!received) [operation cancel];
            if (server.captureDone && dispatch_semaphore_wait(server.captureDone, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC))) {
                puts("ELAN_NATIVE_CAPTURE_STOP_TIMEOUT"); _Exit(124);
            }
            if (received) [operation cancel];
            ((void (*)(id, SEL, id))objc_msgSend)(operation, @selector(setDelegate:), nil);
            BOOL expected = step == 1;
            BOOL valid = started && received && !server.captureFailed && delegate.matchEvents == 1 &&
                         delegate.receivedIdentity == server.liveMatched && !delegate.receivedCredential &&
                         server.liveMatched == expected && !cancelled;
            printf("ELAN_NATIVE_RESULT step=%d started=%d callback=%d live_match=%d native_identity=%d credential_added=%d expected=%d pass=%d\n",
                   step + 1, started, received, server.liveMatched, delegate.receivedIdentity, delegate.receivedCredential, expected, valid);
            if (!valid) break;
            if (step == 1) result = 0;
        }
    } @finally {
        if (server.captureActive) {
            cancelled = 1;
            if (dispatch_semaphore_wait(server.captureDone, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC))) _Exit(124);
        }
        if (stored) wipe(stored.mutableBytes, stored.length);
        [transportProbeClientConnection invalidate];
        [server.connection invalidate]; server.connection = nil;
        [listener invalidate];
        if (redirected) method_exchangeImplementations(original, replacement);
        transportProbeEndpoint = nil; transportProbeClientConnection = nil;
        if (platformChanged) { *cache.result = cache.oldResult; *cache.checked = cache.oldChecked; }
        clearPrints(); close_sensor(&sensor);
        puts("ELAN_NATIVE_CLEANUP templates_cleared=1 sensor_closed=1 system_service_replaced=0");
    }
    printf("ELAN_NATIVE_DONE status=%d\n", result);
    return result;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        biometricFramework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_LAZY | RTLD_LOCAL);
        if (!biometricFramework) return 4;
        if (argc == 2 && !strcmp(argv[1], "--self-test")) return self_test() | template_self_test() | identityCodecTest();
        if (argc == 2 && !strcmp(argv[1], "--transport-test")) return nativeXPCTransportProbe(YES);
        if (argc == 2 && !strcmp(argv[1], "--identity-transport-test")) return identityTransportTest();
        if (argc != 2 || strcmp(argv[1], "--live-study")) return 64;
        struct sigaction action = {0}; action.sa_handler = interrupt; sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL); cancelled = 0;
        __block BOOL finished = NO; __block int result = 1;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                @try { result = liveNativeMatchStudy(); }
                @catch (NSException *exception) { printf("ELAN_NATIVE_EXCEPTION %s\n", exception.reason.UTF8String); result = 6; }
                dispatch_async(dispatch_get_main_queue(), ^{ finished = YES; });
            }
        });
        while (!finished) [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        return result;
    }
}
