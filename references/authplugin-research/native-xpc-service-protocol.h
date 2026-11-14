#import <Foundation/Foundation.h>

#define ELAN_TRANSPORT_XPC_SERVICE @"io.github.hackintosh-tools.native-bio-transport"

@protocol ElanTransportStudyControl
- (void)openEndpointWithReply:(void (^)(NSXPCListenerEndpoint *, NSDictionary *))reply;
- (void)configureContext:(NSData *)context availability:(NSInteger)availability reply:(void (^)(BOOL))reply;
- (void)sendNegativeWithReply:(void (^)(BOOL))reply;
- (void)useFixtureIdentityWithReply:(void (^)(NSUUID *))reply;
- (void)sendFixtureMatchWithReply:(void (^)(BOOL))reply;
- (void)reportWithReply:(void (^)(NSDictionary *))reply;
- (void)closeWithReply:(void (^)(BOOL))reply;
@end
