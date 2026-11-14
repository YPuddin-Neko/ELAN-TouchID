- (void)getProtectedConfigurationForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        NSDictionary *configuration = user == 501 && !controller.stopping && (nativePeerPermissions(self.connection) & NativePeerRead)
            ? nativeUserProtectedConfiguration(controller.repository.current) : nil;
        printf("ELAN_PROVIDER configuration_read peer=%d user=%u available=%d identification_enabled=%d\n",
            self.connection.processIdentifier, user, configuration != nil, configuration && controller.repository.current.identificationEnabled);
        reply(configuration);
    }
}
- (void)getSystemProtectedConfiguration:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    reply(!self.controller.stopping && (nativePeerPermissions(self.connection) & NativePeerRead)
        ? nativeSystemProtectedConfiguration() : nil);
}
- (void)setProtectedConfiguration:(NSDictionary *)configuration user:(unsigned int)user options:(NSDictionary *)options
                           async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    NSData *context = [options isKindOfClass:NSDictionary.class] ? options[@"BKOptionAuthWithCredentialSet"] : nil;
    if (user != 501 || !(nativePeerPermissions(self.connection) & NativePeerConfigure) ||
        ![context isKindOfClass:NSData.class] || context.length != 16) { reply(EACCES); return; }
    @synchronized (controller) {
        if (controller.stopping || controller.busy || !controller.session || controller.session.invalidated) { reply(EBUSY); return; }
        controller.busy = YES; controller.current = self; controller.activeClient = client; cancelled = 0;
    }
    dispatch_group_async(controller.captureGroup, controller.captureQueue, ^{
        @autoreleasepool {
            int status = EACCES;
            @synchronized (controller) {
                if (!cancelled && !controller.stopping && controller.current == self &&
                    (nativePeerPermissions(self.connection) & NativePeerConfigure) && [controller sessionIsCurrent]) {
                    status = nativeCommitUserConfiguration(controller.session, configuration, context, ^int(NSData *credential) {
                        // Configuration changes require the same private password context as enrollment.
                        return elanProviderAuthorizeEnrollment(controller.broker, ++controller.sequence, credential.bytes);
                    });
                }
                if (controller.session.invalidated) controller.stopping = YES;
                controller.current = nil; controller.activeClient = 0; controller.busy = NO;
            }
            printf("ELAN_PROVIDER configuration_status=%d identification_enabled=%d invalidated=%d\n",
                status, controller.repository.current.identificationEnabled, controller.session.invalidated);
            reply(status);
        }
    });
}
- (void)setSystemProtectedConfiguration:(NSDictionary *)configuration options:(NSDictionary *)options
                                 async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    reply(ENOTSUP);
}
