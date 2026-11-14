#pragma once
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <mach/message.h>

enum { NativePeerRead = 1, NativePeerMatch = 2, NativePeerManage = 4, NativePeerEnroll = 8, NativePeerConfigure = 16 };

@interface NSXPCConnection (NativeProviderAuditToken)
- (audit_token_t)auditToken;
@end

static unsigned nativePermissionsForPeer(uid_t user, BOOL appleSignature, NSString *identifier, NSDictionary *entitlements) {
    if (user != 501 || !appleSignature || ![entitlements isKindOfClass:NSDictionary.class]) return 0;
    BOOL match = [entitlements[@"com.apple.private.biometrickit.allow-match"] isEqual:@YES];
    if ([identifier isEqual:@"com.apple.coreauthd"]) return match ? NativePeerRead | NativePeerMatch : 0;
    if (![identifier isEqual:@"com.apple.Touch-ID-Settings.extension"] ||
        ![entitlements[@"com.apple.private.biometrickit.allow-connect"] isEqual:@YES]) return 0;
    unsigned permissions = NativePeerRead;
    if (match) permissions |= NativePeerMatch;
    if ([entitlements[@"com.apple.private.biometrickit.allow-id-mgmt"] isEqual:@YES]) permissions |= NativePeerManage;
    if ([entitlements[@"com.apple.private.biometrickit.allow-enroll"] isEqual:@YES]) permissions |= NativePeerEnroll;
    if ([entitlements[@"com.apple.private.biometrickit.allow-config"] isEqual:@YES]) permissions |= NativePeerConfigure;
    return permissions;
}

static unsigned nativePeerPermissions(NSXPCConnection *connection) {
    if (!connection || connection.effectiveUserIdentifier != 501 || ![connection respondsToSelector:@selector(auditToken)]) return 0;
    audit_token_t token = [connection auditToken];
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:sizeof(token)]};
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef information = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
    if (!status) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
    NSDictionary *info = CFBridgingRelease(information);
    unsigned permissions = nativePermissionsForPeer(connection.effectiveUserIdentifier, status == errSecSuccess,
        info[(__bridge id)kSecCodeInfoIdentifier], info[(__bridge id)kSecCodeInfoEntitlementsDict]);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    return permissions;
}
