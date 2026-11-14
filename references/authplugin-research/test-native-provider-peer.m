#include "native-provider-peer.h"
#include <unistd.h>

@protocol NativePeerTestProtocol
- (void)permissions:(void (^)(unsigned))reply;
@end
@interface NativePeerTestServer : NSObject <NSXPCListenerDelegate, NativePeerTestProtocol>
@property(nonatomic, weak) NSXPCConnection *connection;
@end
@implementation NativePeerTestServer
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (connection.processIdentifier != getpid()) return NO;
    self.connection = connection;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NativePeerTestProtocol)];
    connection.exportedObject = self;
    [connection resume]; return YES;
}
- (void)permissions:(void (^)(unsigned))reply {
    NSXPCConnection *connection = self.connection;
    if (!connection || ![connection respondsToSelector:@selector(auditToken)]) { reply(UINT32_MAX); return; }
    audit_token_t token = connection.auditToken;
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:sizeof(token)]};
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    if (!status) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    if (code) CFRelease(code);
    printf("PEER_AUDIT own_guest_lookup_and_signature_status=%d\n", status);
    reply(status ? UINT32_MAX : nativePeerPermissions(connection));
}
@end

int main(void) {
    @autoreleasepool {
        NSDictionary *settings = @{@"com.apple.private.biometrickit.allow-connect": @YES,
            @"com.apple.private.biometrickit.allow-match": @YES, @"com.apple.private.biometrickit.allow-enroll": @YES,
            @"com.apple.private.biometrickit.allow-id-mgmt": @YES, @"com.apple.private.biometrickit.allow-config": @YES};
        NSDictionary *match = @{@"com.apple.private.biometrickit.allow-match": @YES};
        NSString *settingsID = @"com.apple.Touch-ID-Settings.extension", *coreauthID = @"com.apple.coreauthd";
        BOOL policy = nativePermissionsForPeer(501, YES, settingsID, settings) == 31 &&
            nativePermissionsForPeer(501, YES, coreauthID, match) == (NativePeerRead | NativePeerMatch) &&
            !nativePermissionsForPeer(502, YES, settingsID, settings) &&
            !nativePermissionsForPeer(0, YES, settingsID, settings) &&
            !nativePermissionsForPeer(501, NO, settingsID, settings) &&
            !nativePermissionsForPeer(501, YES, @"com.apple.other", settings) &&
            !nativePermissionsForPeer(501, YES, coreauthID, @{}) &&
            !nativePermissionsForPeer(501, YES, settingsID, match) &&
            !(nativePermissionsForPeer(501, YES, coreauthID, settings) & NativePeerManage);
        NSMutableDictionary *restricted = [settings mutableCopy];
        [restricted removeObjectForKey:@"com.apple.private.biometrickit.allow-id-mgmt"];
        policy &= !(nativePermissionsForPeer(501, YES, settingsID, restricted) & NativePeerManage);
        [restricted removeObjectForKey:@"com.apple.private.biometrickit.allow-config"];
        policy &= !(nativePermissionsForPeer(501, YES, settingsID, restricted) & NativePeerConfigure);
        policy &= !(nativePermissionsForPeer(501, YES, coreauthID, settings) & NativePeerConfigure);
        printf("PEER_POLICY fixture_roles_permissions_and_user_checks=%d\n", policy);
        if (!policy) return 1;
        NativePeerTestServer *server = [NativePeerTestServer new];
        NSXPCListener *listener = [NSXPCListener anonymousListener]; listener.delegate = server; [listener resume];
        NSXPCConnection *connection = [[NSXPCConnection alloc] initWithListenerEndpoint:listener.endpoint];
        connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NativePeerTestProtocol)];
        [connection resume];
        dispatch_semaphore_t complete = dispatch_semaphore_create(0);
        __block unsigned received = UINT32_MAX;
        [[connection remoteObjectProxyWithErrorHandler:^(NSError *error) { dispatch_semaphore_signal(complete); }]
            permissions:^(unsigned permissions) { received = permissions; dispatch_semaphore_signal(complete); }];
        long timeout = dispatch_semaphore_wait(complete, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        [connection invalidate]; [listener invalidate];
        printf("PEER_ACTUAL own_adhoc_process_rejected=%d user=%u timeout=%ld\n", !received, getuid(), timeout);
        return timeout || received ? 2 : 0;
    }
}
