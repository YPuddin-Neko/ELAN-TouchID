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

static BOOL nativeCoreAuthSignedInfo(NSDictionary *info) {
    static const uint8_t pin[20] = {
        0x69, 0x82, 0x84, 0x36, 0xa4, 0x85, 0x0c, 0x9b, 0x85, 0x6c,
        0x51, 0xc6, 0xf9, 0xb0, 0x67, 0x2c, 0x2a, 0x50, 0x39, 0x74
    };
    if (![info isKindOfClass:NSDictionary.class]) return NO;
    NSURL *path = info[(__bridge id)kSecCodeInfoMainExecutable];
    NSData *hash = info[(__bridge id)kSecCodeInfoUnique];
    NSString *identifier = info[(__bridge id)kSecCodeInfoIdentifier];
    return [identifier isEqual:@"com.apple.coreauthd"] &&
        [path isKindOfClass:NSURL.class] && path.isFileURL &&
        [path.path isEqual:@"/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd"] &&
        [hash isKindOfClass:NSData.class] && hash.length == sizeof(pin) &&
        !memcmp(hash.bytes, pin, sizeof(pin));
}

static unsigned nativePeerPermissions(NSXPCConnection *connection) {
    if (!connection || connection.effectiveUserIdentifier != 501 || ![connection respondsToSelector:@selector(auditToken)]) return 0;
    audit_token_t token = [connection auditToken];
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:sizeof(token)]};
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef information = NULL;
    OSStatus guestStatus = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    OSStatus validStatus = guestStatus;
    if (!validStatus) validStatus = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
    if (!validStatus) validStatus = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    OSStatus infoStatus = code ? SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) : errSecInvalidPointer;
    NSDictionary *info = CFBridgingRelease(information);
    unsigned permissions = 0;
    if (!validStatus && !infoStatus) {
        permissions = nativePermissionsForPeer(connection.effectiveUserIdentifier, YES,
            info[(__bridge id)kSecCodeInfoIdentifier], info[(__bridge id)kSecCodeInfoEntitlementsDict]);
    }
    if (!permissions && !guestStatus && !infoStatus && nativeCoreAuthSignedInfo(info)) {
        permissions = NativePeerRead | NativePeerMatch;
    }
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    return permissions;
}
