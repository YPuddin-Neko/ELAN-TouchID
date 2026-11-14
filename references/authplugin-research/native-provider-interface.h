static inline void configureNativeMatchQuery(NSXPCInterface *interface) {
    [interface setClasses:[NSSet setWithObjects:NSArray.class, NSDictionary.class, NSString.class,
                           NSNumber.class, NSClassFromString(@"BiometricKitIdentity"), NSUUID.class, nil]
               forSelector:@selector(match:options:async:client:replyBlock:) argumentIndex:0 ofReply:NO];
}

static const uint64_t NativeProviderDeviceReady = 8;

static inline NSDictionary *nativeProviderMatchDetails(BOOL matched) {
    return @{@"BKMatchDetailLockoutState": @(NativeProviderDeviceReady),
             @"BKMatchDetailCredentialAdded": @(matched), @"BKMatchDetailUnlocked": @NO,
             @"BKMatchDetailResultIgnored": @NO};
}
