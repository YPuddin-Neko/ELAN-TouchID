#define NATIVE_STACK_NO_MAIN
#include "native-stack-probe.m"
#define NATIVE_CONFIGURATION_NO_MAIN
#include "test-native-configuration.m"

@interface NSObject (ConfigurationResearch)
- (instancetype)initWithDictionary:(NSDictionary *)dictionary effective:(BOOL)effective;
- (instancetype)initWithDictionary:(NSDictionary *)dictionary;
- (NSDictionary *)dictionary;
- (id)protectedConfigurationForUser:(unsigned int)user error:(NSError **)error;
- (id)effectiveProtectedConfigurationForUser:(unsigned int)user error:(NSError **)error;
- (id)systemProtectedConfigurationWithError:(NSError **)error;
- (BOOL)setProtectedConfiguration:(id)configuration forUser:(unsigned int)user credentialSet:(NSData *)context error:(NSError **)error;
- (BOOL)setSystemProtectedConfiguration:(id)configuration credentialSet:(NSData *)context error:(NSError **)error;
@end

@interface ConfigurationKeyProbe : NSDictionary
@end
@implementation ConfigurationKeyProbe
- (NSUInteger)count { return 0; }
- (NSEnumerator *)keyEnumerator { return [@[] objectEnumerator]; }
- (id)objectForKey:(id)key { printf("CONFIG_READ_KEY %s\n", [key description].UTF8String); return @NO; }
@end

static int configurationObjects(void) {
    id user = [[NSClassFromString(@"BKUserProtectedConfiguration") alloc] initWithDictionary:@{} effective:NO];
    id system = [[NSClassFromString(@"BKSystemProtectedConfiguration") alloc] initWithDictionary:@{}];
    if (!user || !system) return 1;
    for (NSString *key in @[@"unlockEnabled", @"identificationEnabled", @"loginEnabled", @"applePayEnabled", @"attentionDetectionEnabled", @"periocularFaceIDMatchEnabled"])
        [user setValue:@YES forKey:key];
    for (NSString *key in @[@"biometryEnabled", @"unlockEnabled", @"identificationEnabled", @"loginEnabled", @"periocularFaceIDMatchEnabled"])
        [system setValue:@YES forKey:key];
    for (NSString *key in @[@"unlockTokenMaxLifetime", @"bioMatchLifespan", @"passcodeInputLifespan"])
        [system setValue:@123 forKey:key];
    printf("CONFIG_USER_DICTIONARY %s\n", [[user dictionary] description].UTF8String);
    printf("CONFIG_SYSTEM_DICTIONARY %s\n", [[system dictionary] description].UTF8String);
    puts("CONFIG_READ_REQUESTED");
    (void)[[NSClassFromString(@"BKUserProtectedConfiguration") alloc] initWithDictionary:[ConfigurationKeyProbe new] effective:NO];
    puts("CONFIG_READ_EFFECTIVE");
    (void)[[NSClassFromString(@"BKUserProtectedConfiguration") alloc] initWithDictionary:[ConfigurationKeyProbe new] effective:YES];
    puts("CONFIG_READ_SYSTEM");
    (void)[[NSClassFromString(@"BKSystemProtectedConfiguration") alloc] initWithDictionary:[ConfigurationKeyProbe new]];
    return 0;
}

@interface NativeConfigurationServer : NativeBiometricTransportServer
@property(nonatomic) ElanFingerprintRepository *repository;
@property(nonatomic) ElanFingerprintSession *session;
@property(nonatomic) unsigned authorizations;
@end
@implementation NativeConfigurationServer
- (void)getProtectedConfigurationForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    reply(user == 501 ? nativeUserProtectedConfiguration(self.repository.current) : nil);
}
- (void)getSystemProtectedConfiguration:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    reply(nativeSystemProtectedConfiguration());
}
- (void)setProtectedConfiguration:(NSDictionary *)configuration user:(unsigned int)user options:(NSDictionary *)options
                           async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    printf("CONFIG_TRANSPORT_SET user=%u async=%d keys=%s options=%s\n", user, async,
        [[configuration.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String,
        [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String);
    if (user != 501) { reply(EACCES); return; }
    reply(nativeCommitUserConfiguration(self.session, configuration, options[@"BKOptionAuthWithCredentialSet"], ^int(NSData *context) {
        self.authorizations++;
        return [context isEqual:[NSData dataWithBytes:"fixture-context!" length:16]] ? 0 : EACCES;
    }));
}
- (void)setSystemProtectedConfiguration:(NSDictionary *)configuration options:(NSDictionary *)options
                                 async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    reply(ENOTSUP);
}
@end

static int configurationTransport(void) {
    char build[64] = {}; size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) || strcmp(build, "24H32")) return 3;
    PlatformCache cache = {};
    if (!overridePlatformCache(&cache)) return 4;
    NativeConfigurationServer *server = [NativeConfigurationServer new];
    __block NSData *saved = nil;
    __block OSStatus writeStatus = 0;
    server.repository = [[ElanFingerprintRepository alloc] initWithUser:501 pid:0x0c1a width:144 height:64
        reader:^OSStatus(NSData **data) { *data = saved; return saved ? 0 : errSecItemNotFound; }
        writer:^OSStatus(NSData *data, BOOL create) { if (writeStatus) return writeStatus; saved = data; return 0; }];
    if (![server.repository importLegacy:fixtureTemplate(3, 0x0c1a, 144, 64, 24) uuid:NSUUID.UUID name:@"Fixture"
                              databaseState:[NSMutableData dataWithLength:32] error:NULL]) return 5;
    server.session = [[ElanFingerprintSession alloc] initWithRepository:server.repository publisher:^int(ElanFingerprintCatalog *catalog) { return 0; } error:NULL];
    NSXPCListener *listener = [NSXPCListener anonymousListener];
    listener.delegate = server; transportProbeEndpoint = listener.endpoint; [listener resume];
    Method original = class_getInstanceMethod(NSXPCConnection.class, @selector(initWithMachServiceName:options:));
    Method replacement = class_getInstanceMethod(NSXPCConnection.class, @selector(elanTransport_initWithMachServiceName:options:));
    method_exchangeImplementations(original, replacement);
    __block BOOL done = NO;
    __block int result = 1;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            @try {
                NSError *error = nil;
                id descriptor = [NSClassFromString(@"BKDeviceDescriptor") deviceDescriptorForType:1];
                id device = [NSClassFromString(@"BKDevice") deviceWithDescriptor:descriptor error:&error];
                if (!device || error) return;
                id config = [device protectedConfigurationForUser:501 error:&error];
                id effective = [device effectiveProtectedConfigurationForUser:501 error:&error];
                id system = [device systemProtectedConfigurationWithError:&error];
                if (!config || !effective || !system || error) return;
                BOOL initial = [[config valueForKey:@"identificationEnabled"] boolValue] &&
                    [[effective valueForKey:@"identificationEnabled"] boolValue] && [[system valueForKey:@"biometryEnabled"] boolValue] &&
                    ![[config valueForKey:@"unlockEnabled"] boolValue] && ![[config valueForKey:@"applePayEnabled"] boolValue];
                printf("CONFIG_TRANSPORT_READ original_objects=%d initial_values=%d\n", [config isKindOfClass:NSClassFromString(@"BKUserProtectedConfiguration")], initial);
                if (!initial) return;
                NSData *state = server.repository.current.databaseState;
                NSData *context = [NSData dataWithBytes:"fixture-context!" length:16];
                [config setValue:@NO forKey:@"identificationEnabled"];
                if (![device setProtectedConfiguration:config forUser:501 credentialSet:context error:&error] || error) return;
                effective = [device effectiveProtectedConfigurationForUser:501 error:&error];
                ElanFingerprintCatalog *loaded = [ElanFingerprintCatalog decode:saved user:501 pid:0x0c1a width:144 height:64 error:NULL];
                BOOL disabled = effective && !error && ![[effective valueForKey:@"identificationEnabled"] boolValue] &&
                    !nativeIdentificationEnabled(server.session.matcher) && loaded && !loaded.identificationEnabled;
                printf("CONFIG_TRANSPORT_DISABLE readback=%d persistent_model=%d\n", disabled, loaded && !loaded.identificationEnabled);
                if (!disabled) return;
                [config setValue:@YES forKey:@"identificationEnabled"];
                writeStatus = errSecInteractionNotAllowed; error = nil;
                BOOL failedSave = ![device setProtectedConfiguration:config forUser:501 credentialSet:context error:&error] && error &&
                    !server.session.invalidated && !server.repository.current.identificationEnabled;
                printf("CONFIG_TRANSPORT_WRITE_FAILURE rejected_and_restored=%d\n", failedSave);
                if (!failedSave) return;
                writeStatus = 0; error = nil;
                BOOL denied = ![device setProtectedConfiguration:config forUser:501 credentialSet:[NSMutableData dataWithLength:16] error:&error] && error;
                if (!denied || server.repository.current.identificationEnabled) return;
                error = nil;
                if (![device setProtectedConfiguration:config forUser:501 credentialSet:context error:&error] || error) return;
                if (!nativeIdentificationEnabled(server.session.matcher) || ![server.repository.current.databaseState isEqual:state]) return;
                [config setValue:@YES forKey:@"unlockEnabled"]; error = nil;
                BOOL unlockRejected = ![device setProtectedConfiguration:config forUser:501 credentialSet:context error:&error] && error;
                [config setValue:@NO forKey:@"unlockEnabled"]; error = nil;
                BOOL otherRejected = ![device setProtectedConfiguration:config forUser:502 credentialSet:context error:&error] && error;
                error = nil;
                BOOL systemRejected = ![device setSystemProtectedConfiguration:system credentialSet:context error:&error] && error;
                error = nil;
                id other = [device protectedConfigurationForUser:502 error:&error];
                printf("CONFIG_TRANSPORT_BOUNDARIES wrong_context=%d unlock=%d other_user=%d system_write=%d other_read=%d\n",
                    denied, unlockRejected, otherRejected, systemRejected, other == nil);
                result = unlockRejected && otherRejected && systemRejected && other == nil ? 0 : 1;
            } @catch (NSException *exception) {
                printf("CONFIG_EXCEPTION %s %s\n", exception.name.UTF8String, exception.reason.UTF8String);
            } @finally {
                [transportProbeClientConnection invalidate]; [server.connection invalidate]; [listener invalidate];
                transportProbeClientConnection = nil; transportProbeEndpoint = nil;
                method_exchangeImplementations(original, replacement);
                *cache.result = cache.oldResult; *cache.checked = cache.oldChecked;
                printf("CONFIG_TRANSPORT_DONE status=%d anonymous_own_process=1 system_service_changed=0 keychain_read=0 sensor_opened=0\n", result);
                dispatch_async(dispatch_get_main_queue(), ^{ done = YES; });
            }
        }
    });
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:20];
    while (!done && deadline.timeIntervalSinceNow > 0)
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    if (!done) { puts("CONFIG_TRANSPORT_TIMEOUT own_process_exit=1"); _Exit(124); }
    return result;
}

static int configurationMetadata(void) {
    for (NSString *name in @[@"BKUserProtectedConfiguration", @"BKSystemProtectedConfiguration", @"BKDevice", @"BiometricKitXPCClient"]) {
        Class cls = NSClassFromString(name);
        printf("CONFIG_CLASS %s present=%d\n", name.UTF8String, cls != Nil);
        for (int meta = 0; cls && meta < 2; meta++) {
            unsigned count = 0;
            Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &count);
            for (unsigned i = 0; i < count; i++) {
                const char *selector = sel_getName(method_getName(methods[i]));
                if ([name containsString:@"Configuration"] || strstr(selector, "Configuration"))
                    printf("CONFIG_METHOD %s %c%s %s\n", name.UTF8String, meta ? '+' : '-', selector, method_getTypeEncoding(methods[i]));
            }
            free(methods);
        }
    }
    Protocol *protocol = objc_getProtocol("BiometricKitXpcProtocol");
    for (int required = 0; protocol && required < 2; required++) {
        unsigned count = 0;
        struct objc_method_description *methods = protocol_copyMethodDescriptionList(protocol, required, YES, &count);
        for (unsigned i = 0; i < count; i++) {
            const char *selector = sel_getName(methods[i].name);
            if (strstr(selector, "Configuration")) printf("CONFIG_PROTOCOL %s %s\n", selector, methods[i].types);
        }
        free(methods);
    }
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        biometricFramework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_NOW | RTLD_LOCAL);
        if (!biometricFramework) return 2;
        if (argc == 2 && !strcmp(argv[1], "--metadata")) return configurationMetadata();
        if (argc == 2 && !strcmp(argv[1], "--objects")) return configurationObjects();
        if (argc == 2 && !strcmp(argv[1], "--self-test")) return configurationModelTests();
        if (argc == 2 && !strcmp(argv[1], "--transport")) return configurationTransport();
        return 2;
    }
}
