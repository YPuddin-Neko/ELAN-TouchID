#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <unistd.h>
#include "native-xpc-service-protocol.h"

@interface NSObject (ElanServiceNegativeCallback)
- (void)matchResult:(id)identity details:(NSDictionary *)details client:(uint64_t)client;
@end

#include "native-xpc-server.inc"

@interface ElanRemoteTransportServer : NativeBiometricTransportServer
@property(nonatomic) pid_t allowedPID;
@property(nonatomic, strong) id fixtureIdentity;
@end
@implementation ElanRemoteTransportServer
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
    reply(self.fixtureIdentity ? @[self.fixtureIdentity] : @[]);
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (connection.processIdentifier != self.allowedPID || connection.effectiveUserIdentifier != geteuid()) return NO;
    [self configureConnection:connection];
    self.connection = connection;
    [connection resume];
    return YES;
}
@end

@interface ElanTransportService : NSObject <NSXPCListenerDelegate, ElanTransportStudyControl>
@property(nonatomic, strong) NSXPCConnection *control;
@property(nonatomic, strong) NSXPCListener *listener;
@property(nonatomic, strong) ElanRemoteTransportServer *server;
@end

@implementation ElanTransportService
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (self.control || connection.processIdentifier == getpid() || connection.effectiveUserIdentifier != geteuid()) return NO;
    self.control = connection;
    self.server = [ElanRemoteTransportServer new];
    self.server.allowedPID = connection.processIdentifier;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ElanTransportStudyControl)];
    connection.exportedObject = self;
    __weak ElanTransportService *weakSelf = self;
    connection.invalidationHandler = ^{
        ElanTransportService *service = weakSelf;
        [service.server.connection invalidate];
        [service.listener invalidate];
        service.server.expectedCredentialSet = nil;
        service.control = nil;
        dispatch_async(dispatch_get_main_queue(), ^{ exit(0); });
    };
    [connection resume];
    return YES;
}
- (void)openEndpointWithReply:(void (^)(NSXPCListenerEndpoint *, NSDictionary *))reply {
    if (!self.listener) {
        self.listener = [NSXPCListener anonymousListener];
        self.listener.delegate = self.server;
        [self.listener resume];
    }
    reply(self.listener.endpoint, @{@"pid": @(getpid()), @"uid": @(geteuid()), @"allowed_pid": @(self.server.allowedPID)});
}
- (void)configureContext:(NSData *)context availability:(NSInteger)availability reply:(void (^)(BOOL))reply {
    if (context.length != 16 || availability < 0 || availability > 3) { reply(NO); return; }
    self.server.expectedCredentialSet = context;
    self.server.fixtureAvailability = availability;
    reply(YES);
}
- (void)sendNegativeWithReply:(void (^)(BOOL))reply {
    if (!self.server.connection || !self.server.matchRequests) { reply(NO); return; }
    id remote = [self.server.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {}];
    [remote matchResult:nil details:@{@"BKMatchDetailCredentialAdded": @NO,
                                     @"BKMatchDetailUnlocked": @NO,
                                     @"BKMatchDetailResultIgnored": @NO} client:self.server.lastMatchClient];
    reply(YES);
}
- (void)useFixtureIdentityWithReply:(void (^)(NSUUID *))reply {
    id identity = [NSClassFromString(@"BiometricKitIdentity") new];
    NSUUID *uuid = NSUUID.UUID;
    [identity setValue:uuid forKey:@"uuid"];
    [identity setValue:@1 forKey:@"type"];
    [identity setValue:@(getuid()) forKey:@"userID"];
    [identity setValue:@"Transport fixture" forKey:@"name"];
    [identity setValue:NSDate.date forKey:@"creationTime"];
    self.server.fixtureIdentity = identity;
    reply(uuid);
}
- (void)sendFixtureMatchWithReply:(void (^)(BOOL))reply {
    if (!self.server.connection || !self.server.matchRequests || !self.server.fixtureIdentity) { reply(NO); return; }
    id remote = [self.server.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {}];
    [remote matchResult:self.server.fixtureIdentity details:@{@"BKMatchDetailCredentialAdded": @NO,
                                                             @"BKMatchDetailUnlocked": @NO,
                                                             @"BKMatchDetailResultIgnored": @NO} client:self.server.lastMatchClient];
    reply(YES);
}
- (void)reportWithReply:(void (^)(NSDictionary *))reply {
    reply(@{@"pid": @(getpid()), @"connects": @(self.server.connects),
            @"hardware": @(self.server.hardwareReads), @"availability": @(self.server.availabilityReads),
            @"identities": @(self.server.identityReads), @"matches": @(self.server.matchRequests),
            @"cancels": @(self.server.cancelRequests), @"context_received": @(self.server.receivedExpectedCredentialSet)});
}
- (void)closeWithReply:(void (^)(BOOL))reply {
    [self.server.connection invalidate];
    self.server.connection = nil;
    self.server.expectedCredentialSet = nil;
    self.server.fixtureIdentity = nil;
    [self.listener invalidate];
    self.listener = nil;
    reply(YES);
}
@end

int main(void) {
    @autoreleasepool {
        if (!dlopen("/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit", RTLD_LAZY | RTLD_LOCAL) ||
            !objc_getProtocol("BiometricKitXpcProtocol") || !objc_getProtocol("BiometricKitDelegateXpcProtocol")) return 4;
        NSXPCListener *listener = [NSXPCListener serviceListener];
        ElanTransportService *service = [ElanTransportService new];
        listener.delegate = service;
        [listener resume];
    }
    return 0;
}
