#pragma once
#import <Foundation/Foundation.h>

static inline NSData *nativeInitialEnrollmentContext(int type, unsigned user, unsigned expectedUser,
                                                     NSDictionary *options) {
    if (type != 1 || user != expectedUser || ![options isKindOfClass:NSDictionary.class]) return nil;
    id value = options[@"BKOptionAuthWithCredentialSet"];
    return [value isKindOfClass:NSData.class] && [value length] == 16 ? value : nil;
}

static inline NSUUID *nativeExtendedEnrollmentUUID(id query, NSDictionary *options) {
    if (![query isKindOfClass:NSDictionary.class] || [query count] != 1 ||
        ![options[@"BKOptionMatchForExtendEnrollment"] isEqual:@YES]) return nil;
    id context = options[@"BKOptionAuthWithCredentialSet"];
    if (![context isKindOfClass:NSData.class] || [context length] != 16 ||
        options[@"BKOptionMatchForCredentialSet"] || [options[@"BKOptionMatchForUnlock"] boolValue]) return nil;
    id identity = query[@"BKFilterIdentity"];
    if (![identity isKindOfClass:NSClassFromString(@"BiometricKitIdentity")] ||
        ![[identity valueForKey:@"userID"] isEqual:@501] || ![[identity valueForKey:@"type"] isEqual:@1]) return nil;
    id uuid = [identity valueForKey:@"uuid"];
    return [uuid isKindOfClass:NSUUID.class] ? uuid : nil;
}
