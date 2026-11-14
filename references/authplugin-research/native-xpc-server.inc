@interface NativeBiometricTransportServer : NSObject <NSXPCListenerDelegate>
@property(nonatomic, strong) NSXPCConnection *connection;
@property(nonatomic) unsigned connects;
@property(nonatomic) unsigned hardwareReads;
@property(nonatomic) unsigned availabilityReads;
@property(nonatomic) unsigned identityReads;
@property(atomic) NSInteger fixtureAvailability;
@property(nonatomic) unsigned matchRequests;
@property(nonatomic) unsigned cancelRequests;
@property(nonatomic) uint64_t lastMatchClient;
@property(nonatomic, copy) NSData *expectedCredentialSet;
@property(nonatomic) BOOL receivedExpectedCredentialSet;
- (void)configureConnection:(NSXPCConnection *)connection;
@end

@implementation NativeBiometricTransportServer
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (connection.processIdentifier != getpid() || connection.effectiveUserIdentifier != geteuid()) return NO;
    [self configureConnection:connection];
    self.connection = connection;
    [connection resume];
    puts("TRANSPORT_SERVER accepted_own_process=1");
    return YES;
}
- (void)configureConnection:(NSXPCConnection *)connection {
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitXpcProtocol")];
    connection.exportedObject = self;
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitDelegateXpcProtocol")];
}
- (void)connect:(NSDictionary *)options client:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.connects++;
    printf("TRANSPORT_SERVER connect options_class=%s\n", object_getClassName(options));
    reply(0);
}
- (void)disconnect:(uint64_t)client replyBlock:(void (^)(int))reply {
    puts("TRANSPORT_SERVER disconnect");
    reply(0);
}
- (void)registerDelegate:(BOOL)enabled client:(uint64_t)client replyBlock:(void (^)(int))reply {
    printf("TRANSPORT_SERVER delegate=%d\n", enabled);
    reply(0);
}
- (void)getDeviceHardwareState:(uint64_t)client replyBlock:(void (^)(int, unsigned int))reply {
    self.hardwareReads++;
    reply(0, 0);
}
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply {
    reply(0, @[]);
}
- (void)getBiometryAvailabilityForUser:(unsigned int)user client:(uint64_t)client
                          replyBlock:(void (^)(int, NSInteger))reply {
    self.availabilityReads++;
    reply(0, self.fixtureAvailability);
}
- (void)identities:(NSDictionary *)query client:(uint64_t)client replyBlock:(void (^)(NSArray *))reply {
    self.identityReads++;
    reply(@[]);
}
- (void)match:(NSArray *)identities options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.receivedExpectedCredentialSet = NO;
    if (self.expectedCredentialSet) {
        for (NSString *key in options) {
            id value = options[key];
            if ([value isKindOfClass:NSData.class]) {
                BOOL same = [value isEqualToData:self.expectedCredentialSet];
                printf("TRANSPORT_CONTEXT_FIELD key=%s length=%lu same_own_context=%d\n",
                       key.UTF8String, (unsigned long)[value length], same);
                self.receivedExpectedCredentialSet |= same;
            }
        }
    }
    self.matchRequests++;
    self.lastMatchClient = client;
    printf("TRANSPORT_SERVER match async=%d option_keys=%s\n", async,
           [[options.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","].UTF8String);
    reply(0);
}
- (void)cancel:(uint64_t)client replyBlock:(void (^)(int))reply {
    self.cancelRequests++;
    puts("TRANSPORT_SERVER cancel");
    reply(0);
}
- (void)logEventOrCode:(uint64_t)code {
    printf("TRANSPORT_SERVER diagnostic_event=%llu\n", (unsigned long long)code);
}
@end

