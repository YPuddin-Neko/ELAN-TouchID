#import "AccessoryDiscovery.h"
#import "../native-enrollment-request.h"
#import "../native-provider-peer.h"
#import <IOKit/IOReturn.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <unistd.h>

NSString *const ELANSensorServiceName = @"io.hackmac.elan.touchid";
static NSString *const accessoryID = @"0D62A891-28A1-4818-A321-04F3000C1A01";

BOOL ELANDiscoveryNameAllowed(NSString *name) {
    if ([name isEqual:ELANSensorServiceName]) return YES;
    NSString *prefix = @"io.github.hackintosh-tools.elan-usb.check-";
    NSUInteger suffixLength = 32;
    if ([name hasPrefix:@"io.hackmac."]) {
        prefix = @"io.hackmac.";
        suffixLength = 12;
    }
    if (![name hasPrefix:prefix]) return NO;
    NSString *suffix = [name substringFromIndex:prefix.length];
    NSCharacterSet *other = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    return suffix.length == suffixLength && [suffix rangeOfCharacterFromSet:other].location == NSNotFound;
}

@protocol ELANListAccessories
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply;
@end

@interface NSObject (ELANDeviceManager)
+ (NSArray *)availableDevices;
@end

static void *loadBiometricKit(void) {
    static void *framework;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        framework = dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit",
                           RTLD_LAZY | RTLD_LOCAL);
    });
    return framework;
}

NSNumber *ELANSystemTouchIDPlatform(void) {
    char build[32] = {};
    size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, nullptr, 0) || strcmp(build, "24H32")) return nil;
    void *framework = loadBiometricKit();
    if (!framework) return nil;
    auto platform = reinterpret_cast<BOOL (*)(char *)>(dlsym(framework, "isTouchIDPlatformWithFailure"));
    char failure = 0;
    return platform ? @(!!platform(&failure)) : nil;
}

NSNumber *ELANSystemDeviceCount(void) {
    if (!loadBiometricKit()) return nil;
    Class manager = NSClassFromString(@"BKDeviceManager");
    if (![manager respondsToSelector:@selector(availableDevices)]) return nil;
    NSArray *devices = [manager availableDevices];
    return [devices isKindOfClass:NSArray.class] ? @(devices.count) : nil;
}

static NSXPCInterface *wireInterface(void) {
    if (!loadBiometricKit()) return nil;
    Protocol *wire = objc_getProtocol("BiometricKitXpcProtocol");
    Class accessory = NSClassFromString(@"BiometricKitAccessory");
    if (!wire || !accessory || !protocol_getMethodDescription(wire, @selector(listAccessories:replyBlock:), YES, YES).types)
        return nil;
    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:wire];
    [interface setClasses:[NSSet setWithObjects:NSArray.class, accessory, nil]
              forSelector:@selector(listAccessories:replyBlock:) argumentIndex:1 ofReply:YES];
    return interface;
}

static id sensorAccessory(void) {
    id item = [NSClassFromString(@"BiometricKitAccessory") new];
    if (!item) return nil;
    [item setValue:[[NSUUID alloc] initWithUUIDString:accessoryID] forKey:@"uuid"];
    [item setValue:@1 forKey:@"type"];
    [item setValue:@2 forKey:@"flags"];
    [item setValue:@"ELAN 0c1a" forKey:@"name"];
    return item;
}

@interface ELANDiscovery : NSObject <NSXPCListenerDelegate, ELANListAccessories>
@property(copy) BOOL (^sensorPresent)(void);
@property(copy) ELANSettingsHandler handleSettings;
@property(strong) NSXPCInterface *wire;
@property(strong) NSXPCListener *listener;
@end
@implementation ELANDiscovery
- (void)connect:(NSDictionary *)options client:(uint64_t)client replyBlock:(void (^)(int))reply {
    reply(self.sensorPresent() ? 0 : 1);
}
- (void)disconnect:(uint64_t)client replyBlock:(void (^)(int))reply { reply(0); }
- (void)registerDelegate:(BOOL)enabled client:(uint64_t)client replyBlock:(void (^)(int))reply { reply(0); }
- (void)isAriadneSignpostsEnabled:(uint64_t)client replyBlock:(void (^)(BOOL))reply { (void)client; reply(NO); }
- (void)logEventOrCode:(uint64_t)code {}
- (void)enroll:(int)type user:(unsigned)user options:(NSDictionary *)options async:(BOOL)async
         client:(uint64_t)client replyBlock:(void (^)(int))reply {
    NSData *context = nativeInitialEnrollmentContext(type, user, getuid(), options);
    if (!context || !(nativePeerPermissions(NSXPCConnection.currentConnection) & NativePeerEnroll)) {
        puts(context ? "ELAN enrollment rejected: peer" : "ELAN enrollment rejected: request");
        fflush(stdout);
        reply(kIOReturnNotPrivileged);
        return;
    }
    // A native Settings peer still needs a verified password context and an active capture backend.
    reply(kIOReturnNotReady);
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)peer {
    if (peer.effectiveUserIdentifier != getuid()) return NO;
    if (self.handleSettings && (nativePeerPermissions(peer) & (NativePeerEnroll | NativePeerMatch)))
        return self.handleSettings(peer, sensorAccessory(), self.sensorPresent);
    peer.exportedInterface = self.wire;
    peer.exportedObject = self;
    Protocol *callback = objc_getProtocol("BiometricKitDelegateXpcProtocol");
    if (callback) peer.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:callback];
    [peer resume];
    return YES;
}
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply {
    if (!self.sensorPresent()) { reply(0, @[]); return; }
    id item = sensorAccessory();
    reply(item ? 0 : 1, item ? @[item] : @[]);
}
- (void)getBiometryAvailabilityForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(int, NSInteger))reply {
    reply(0, user == getuid() && self.sensorPresent() ? 1 : 0);
}
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    reply(@[]);
}
@end

void ELANServeDiscovery(NSString *service, BOOL (^sensorPresent)(void), ELANSettingsHandler handleSettings) {
    if (!ELANDiscoveryNameAllowed(service)) exit(2);
    static ELANDiscovery *server;
    if (server) exit(2);
    server = [ELANDiscovery new];
    server.sensorPresent = sensorPresent;
    server.handleSettings = handleSettings;
    server.wire = wireInterface();
    if (!server.wire) exit(2);
    server.listener = [[NSXPCListener alloc] initWithMachServiceName:service];
    server.listener.delegate = server;
    [server.listener resume];
    if ([service isEqual:ELANSensorServiceName]) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [server.listener invalidate];
        exit(0);
    });
}

int ELANReadDiscovery(NSString *service) {
    if (!ELANDiscoveryNameAllowed(service)) return 2;
    NSXPCInterface *wire = wireInterface();
    if (!wire) return 2;
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:service options:0];
    connection.remoteObjectInterface = wire;
    [connection resume];
    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block BOOL decoded = NO;
    id<ELANListAccessories> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        fprintf(stderr, "Discovery XPC: %s %ld\n", error.domain.UTF8String, (long)error.code);
        dispatch_semaphore_signal(completed);
    }];
    [proxy listAccessories:1 replyBlock:^(int status, NSArray *items) {
        id item = items.firstObject;
        decoded = status == 0 && items.count == 1 &&
            [item isKindOfClass:NSClassFromString(@"BiometricKitAccessory")] &&
            [[item valueForKey:@"uuid"] isEqual:[[NSUUID alloc] initWithUUIDString:accessoryID]] &&
            [[item valueForKey:@"type"] isEqual:@1] && [[item valueForKey:@"flags"] isEqual:@2] &&
            [[item valueForKey:@"name"] isEqual:@"ELAN 0c1a"];
        dispatch_semaphore_signal(completed);
    }];
    bool timedOut = dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));
    [connection invalidate];
    bool ok = !timedOut && decoded;
    NSNumber *systemCount = ELANSystemDeviceCount();
    printf("{\"native_accessory_decoded\":%s,\"uid\":%u,\"system_device_count\":%s}\n",
           ok ? "true" : "false", getuid(), systemCount ? systemCount.stringValue.UTF8String : "null");
    return ok ? 0 : 1;
}
