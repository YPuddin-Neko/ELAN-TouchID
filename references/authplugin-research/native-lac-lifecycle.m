#define NATIVE_STACK_NO_MAIN
#include "native-stack-probe.m"

@interface NSObject (ElanLACLifecycle)
- (instancetype)initWithBiometryType:(NSInteger)type;
- (BOOL)deviceHasBiometryWithError:(NSError **)error;
- (id)fault;
- (id)permanentError;
+ (BOOL)deviceHasTouchID;
+ (id)touchIdInstance;
- (BOOL)isEnrolled:(id)user error:(NSError **)error;
- (BOOL)isLockedOutForUser:(id)user request:(id)request error:(NSError **)error;
- (NSData *)biometryDatabaseHashForUser:(id)user error:(NSError **)error;
@end
extern int elanRetryOwnHelper(uint64_t, uint64_t, uint64_t, uint64_t);

@interface NativeLACFixtureServer : NativeBiometricTransportServer
@property(nonatomic, strong) id fixture;
@property(nonatomic, strong) id accessory;
@end
@implementation NativeLACFixtureServer
- (void)configureConnection:(NSXPCConnection *)connection {
    [super configureConnection:connection];
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, NSClassFromString(@"BiometricKitIdentity"), nil]
                                forSelector:@selector(identities:client:replyBlock:) argumentIndex:0 ofReply:YES];
    [connection.exportedInterface setClasses:[NSSet setWithObjects:NSArray.class, NSClassFromString(@"BiometricKitAccessory"), nil]
                                forSelector:@selector(listAccessories:replyBlock:) argumentIndex:1 ofReply:YES];
}
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply { reply(0, @[self.accessory]); }
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    printf("LAC_FIXTURE identity_query=%s\n", query.description.UTF8String);
    reply(@[self.fixture]);
}
- (void)getBioLockoutStateForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(int, int64_t))reply {
    printf("LAC_FIXTURE lockout_user=%u\n", user); reply(user == 501 ? 0 : 1, 0);
}
- (void)getIdentitiesDatabaseHashForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSData *))reply {
    printf("LAC_FIXTURE database_hash_user=%u\n", user);
    reply(user == 501 ? [NSMutableData dataWithLength:32] : nil);
}
@end

static BOOL reportHelper(id helper, const char *phase) {
    NSError *error = nil;
    BOOL available = [helper deviceHasBiometryWithError:&error];
    printf("LAC_LIFECYCLE phase=%s available=%d fault=%d permanent=%d error=%ld\n",
           phase, available, [helper fault] != nil, [helper permanentError] != nil, (long)error.code);
    return available;
}

int main(void) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        biometricFramework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_LAZY | RTLD_LOCAL);
        void *lac = dlopen("/System/Library/PrivateFrameworks/LocalAuthenticationCore.framework/LocalAuthenticationCore", RTLD_LAZY | RTLD_LOCAL);
        if (!biometricFramework || !lac || !objc_getClass("LACBiometryHelper")) return 3;
        char build[64] = {}; size_t length = sizeof(build);
        if (sysctlbyname("kern.osversion", build, &length, NULL, 0) || strcmp(build, "24H32")) return 4;
        NativeLACFixtureServer *server = [NativeLACFixtureServer new];
        server.fixture = [NSClassFromString(@"BiometricKitIdentity") new];
        [server.fixture setValue:NSUUID.UUID forKey:@"uuid"];
        [server.fixture setValue:@1 forKey:@"type"]; [server.fixture setValue:@501 forKey:@"userID"];
        [server.fixture setValue:@"Fixture" forKey:@"name"]; [server.fixture setValue:NSDate.date forKey:@"creationTime"];
        server.accessory = [NSClassFromString(@"BiometricKitAccessory") new];
        [server.accessory setValue:NSUUID.UUID forKey:@"uuid"]; [server.accessory setValue:@1 forKey:@"type"];
        [server.accessory setValue:@0 forKey:@"flags"]; [server.accessory setValue:@"ELAN fixture" forKey:@"name"];
        server.fixtureAvailability = 1;
        NSXPCListener *listener = [NSXPCListener anonymousListener];
        listener.delegate = server; transportProbeEndpoint = listener.endpoint; [listener resume];
        Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
        Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
        method_exchangeImplementations(original, replacement);
        __block BOOL finished = NO;
        __block int result = 1;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                PlatformCache cache = {};
                BOOL changed = NO;
                @try {
                    printf("LAC_LIFECYCLE gestalt_touchid=%d\n", [objc_getClass("LACMobileGestalt") deviceHasTouchID]);
                    Class helperClass = objc_getClass("LACBiometryHelper");
                    id helper = [helperClass touchIdInstance];
                    BOOL baseline = reportHelper(helper, "baseline");
                    if (baseline || !overridePlatformCache(&cache)) return;
                    changed = YES;
                    BOOL existing = reportHelper(helper, "existing_after_platform");
                    int transferred = elanRetryOwnHelper(
                        (uint64_t)method_getImplementation(class_getClassMethod(helperClass, @selector(touchIdInstance))),
                        (uint64_t)method_getImplementation(class_getInstanceMethod(helperClass, @selector(fault))),
                        (uint64_t)method_getImplementation(class_getInstanceMethod(helperClass, @selector(permanentError))),
                        (uint64_t)(__bridge void *)helperClass);
                    if (transferred) return;
                    BOOL retry = reportHelper(helper, "existing_after_retry_reset");
                    NSError *queryError = nil;
                    BOOL enrolled = [helper isEnrolled:@501 error:&queryError];
                    printf("LAC_LIFECYCLE enrolled=%d error=%ld\n", enrolled, (long)queryError.code);
                    if (!enrolled || queryError) return;
                    queryError = nil;
                    BOOL wrongUserEnrolled = [helper isEnrolled:@502 error:&queryError];
                    printf("LAC_LIFECYCLE wrong_user_enrolled=%d error=%ld\n", wrongUserEnrolled, (long)queryError.code);
                    if (wrongUserEnrolled || queryError.code != -7) return;
                    queryError = nil;
                    BOOL locked = [helper isLockedOutForUser:@501 request:nil error:&queryError];
                    printf("LAC_LIFECYCLE locked=%d error=%ld\n", locked, (long)queryError.code);
                    if (locked || queryError) return;
                    NSData *hash = [helper biometryDatabaseHashForUser:@501 error:&queryError];
                    printf("LAC_LIFECYCLE hash_bytes=%lu error=%ld\n", (unsigned long)hash.length, (long)queryError.code);
                    if (hash.length != 32 || queryError) return;
                    id fresh = [[objc_getClass("LACBiometryHelper") alloc] initWithBiometryType:1];
                    BOOL rebuilt = reportHelper(fresh, "new_after_platform");
                    printf("LAC_LIFECYCLE existing_recovers=%d new_recovers=%d redirects=%u\n", existing, rebuilt, transportProbeRedirects);
                    printf("LAC_LIFECYCLE retry_reset_recovers=%d fixture_object_only=1\n", retry);
                    result = rebuilt && retry ? 0 : 1;
                    helper = nil; fresh = nil;
                } @catch (NSException *exception) {
                    printf("LAC_LIFECYCLE exception=%s\n", exception.name.UTF8String);
                } @finally {
                    [transportProbeClientConnection invalidate]; [server.connection invalidate];
                    server.connection = nil; [listener invalidate];
                    method_exchangeImplementations(original, replacement);
                    transportProbeClientConnection = nil; transportProbeEndpoint = nil;
                    if (changed) { *cache.result = cache.oldResult; *cache.checked = cache.oldChecked; }
                    BOOL (*platform)(char *) = dlsym(biometricFramework, "isTouchIDPlatformWithFailure");
                    printf("LAC_LIFECYCLE_DONE status=%d platform=%d system_services_changed=0 credentials_submitted=0\n", result, platform(NULL));
                    dispatch_async(dispatch_get_main_queue(), ^{ finished = YES; });
                }
            }
        });
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:20];
        while (!finished && deadline.timeIntervalSinceNow > 0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        if (!finished) { puts("LAC_LIFECYCLE_TIMEOUT own_process_exit=1"); _Exit(124); }
        return result;
    }
}
