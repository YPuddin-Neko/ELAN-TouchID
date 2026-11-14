#pragma once
#import "../../elan-fingerprint-macos/src/ElanFingerprintSession.h"
#include <errno.h>

static inline NSDictionary *nativeUserProtectedConfiguration(ElanFingerprintCatalog *catalog) {
    if (!catalog) return nil;
    return @{@"BKUserCfgTouchIDUnlockEnabled": @NO, @"BKUserCfgEffectiveTouchIDUnlockEnabled": @NO,
        @"BKUserCfgTouchIDIdentificationEnabled": @(catalog.identificationEnabled),
        @"BKUserCfgEffectiveTouchIDIdentificationEnabled": @(catalog.identificationEnabled && catalog.records.count != 0),
        @"BKUserCfgTouchIDLoginEnabled": @NO, @"BKUserCfgEffectiveTouchIDLoginEnabled": @NO,
        @"BKUserCfgTouchIDApplePayEnabled": @NO, @"BKUserCfgEffectiveTouchIDApplePayEnabled": @NO,
        @"BKUserCfgAttentionDetectionEnabled": @NO, @"BKUserCfgEffectiveAttentionDetectionEnabled": @NO,
        @"BKUserCfgPeriocularMatchEnabled": @NO, @"BKUserCfgEffectivePeriocularMatchEnabled": @NO};
}

static inline NSDictionary *nativeSystemProtectedConfiguration(void) {
    return @{@"BKSysCfgTouchIDEnabled": @YES, @"BKSysCfgTouchIDIdentificationEnabled": @YES,
        @"BKSysCfgTouchIDUnlockEnabled": @NO, @"BKSysCfgTouchIDLoginEnabled": @NO,
        @"BKSysCfgPeriocularMatchEnabled": @NO};
}

static inline int nativeRequestedIdentification(id configuration, BOOL current, BOOL *enabled) {
    if (![configuration isKindOfClass:NSDictionary.class]) return EINVAL;
    *enabled = current;
    for (id key in configuration) {
        id value = configuration[key];
        if (![key isKindOfClass:NSString.class] || ![value isKindOfClass:NSNumber.class] ||
            (![value isEqual:@NO] && ![value isEqual:@YES])) return EINVAL;
        if ([key isEqual:@"BKUserCfgTouchIDIdentificationEnabled"]) *enabled = [value boolValue];
        else if (![@[@"BKUserCfgTouchIDUnlockEnabled", @"BKUserCfgTouchIDLoginEnabled", @"BKUserCfgTouchIDApplePayEnabled",
                     @"BKUserCfgAttentionDetectionEnabled", @"BKUserCfgPeriocularMatchEnabled"] containsObject:key] ||
                 [value boolValue]) return ENOTSUP;
    }
    return 0;
}

static inline int nativeCommitUserConfiguration(ElanFingerprintSession *session, NSDictionary *configuration,
                                                NSData *context, int (^authorize)(NSData *)) {
    if (!session || session.invalidated) return EBUSY;
    if (![context isKindOfClass:NSData.class] || context.length != 16 || !authorize) return EACCES;
    ElanFingerprintCatalog *previous = session.matcher.catalog;
    BOOL enabled = previous.identificationEnabled;
    int status = nativeRequestedIdentification(configuration, enabled, &enabled);
    if (status) return status;
    if (authorize(context)) return EACCES;
    if (enabled == previous.identificationEnabled) return 0;
    ElanFingerprintCatalog *candidate = [previous withIdentificationEnabled:enabled];
    return [session commit:candidate replacing:previous error:NULL] ? 0 : EIO;
}

static inline BOOL nativeIdentificationEnabled(ElanFingerprintMatcher *matcher) {
    return matcher.catalog.identificationEnabled && matcher.catalog.records.count != 0;
}
