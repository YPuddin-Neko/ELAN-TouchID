#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <unistd.h>
#include "native-provider-interface.h"

@interface NSObject (TransportTestCall)
- (instancetype)initWithServerIdentity:(id)identity details:(NSDictionary *)details device:(id)device;
- (void)match:(id)query options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply;
@end

@interface MatchTransportTest : NSObject <NSXPCListenerDelegate>
@property(nonatomic, strong) NSXPCConnection *accepted;
@property(atomic) BOOL dictionaryReceived;
@end

@implementation MatchTransportTest
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (connection.processIdentifier != getpid() || connection.effectiveUserIdentifier != geteuid()) return NO;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitXpcProtocol")];
    configureNativeMatchQuery(connection.exportedInterface);
    connection.exportedObject = self;
    self.accepted = connection;
    [connection resume];
    return YES;
}
- (void)match:(id)query options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.dictionaryReceived = [query isEqual:@{@"userID": @501}] &&
        [options[@"BKOptionMatchForCredentialSet"] isEqual:[NSMutableData dataWithLength:16]];
    reply(self.dictionaryReceived ? 0 : 1);
}
@end

int main(void) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        if (!dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_NOW)) return 2;
        void *lac = dlopen("/System/Library/PrivateFrameworks/LocalAuthenticationCore.framework/LocalAuthenticationCore", RTLD_NOW);
        NSString *(*stateName)(NSInteger) = lac ? dlsym(lac, "NSStringFromBKLockoutState") : NULL;
        for (NSInteger raw = -1; raw <= 8; raw += raw < 0 ? 1 : 8) {
            NSDictionary *details = raw < 0 ? @{} : @{@"BKMatchDetailLockoutState": @(raw)};
            id result = [[NSClassFromString(@"BKMatchResultInfo") alloc] initWithServerIdentity:nil details:details device:nil];
            NSInteger decoded = [[result valueForKey:@"lockoutState"] integerValue];
            printf("NATIVE_MATCH_LOCKOUT raw=%ld decoded=%ld name=%s\n", (long)raw, (long)decoded,
                   stateName ? stateName(decoded).UTF8String : "unavailable");
        }
        id negative = [[NSClassFromString(@"BKMatchResultInfo") alloc] initWithServerIdentity:nil
                         details:nativeProviderMatchDetails(NO) device:nil];
        NSInteger lockout = [[negative valueForKey:@"lockoutState"] integerValue];
        BOOL negativeValid = stateName && [stateName(lockout) isEqualToString:@"BKLockoutStateNone"] &&
                             ![nativeProviderMatchDetails(NO)[@"BKMatchDetailCredentialAdded"] boolValue];
        printf("NATIVE_MATCH_NEGATIVE no_lockout=%d credential_added=0\n", negativeValid);
        MatchTransportTest *server = [MatchTransportTest new];
        NSXPCListener *listener = [NSXPCListener anonymousListener];
        listener.delegate = server;
        [listener resume];
        NSXPCConnection *client = [[NSXPCConnection alloc] initWithListenerEndpoint:listener.endpoint];
        client.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitXpcProtocol")];
        [client resume];
        __block BOOL done = NO;
        __block int result = 3;
        id remote = [client remoteObjectProxyWithErrorHandler:^(NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{ result = 4; done = YES; });
        }];
        [remote match:@{@"userID": @501} options:@{@"BKOptionMatchForCredentialSet": [NSMutableData dataWithLength:16]}
                 async:NO client:1 replyBlock:^(int status) {
            dispatch_async(dispatch_get_main_queue(), ^{ result = status; done = YES; });
        }];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:10];
        while (!done && deadline.timeIntervalSinceNow > 0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        [client invalidate];
        [server.accepted invalidate];
        [listener invalidate];
        BOOL passed = done && result == 0 && server.dictionaryReceived && negativeValid;
        printf("NATIVE_MATCH_TRANSPORT dictionary_query=%d status=%d passed=%d system_service_changed=0 kernel_opened=0\n",
               server.dictionaryReceived, result, passed);
        return passed ? 0 : 1;
    }
}
