#pragma once
#import "../native-provider-peer.h"
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <string.h>

static BOOL ELANSettingsPeerEvidence(audit_token_t token, NSData *expectedToken, uint32_t serviceASID,
                                    uid_t connectionUID, BOOL valid, NSDictionary *info) {
    static const uint8_t pin[20] = {0xe3,0xfe,0xc5,0x23,0xfc,0x8a,0xfc,0x4e,0x82,0xb0,0xe7,0x4d,0xf6,0x26,0x67,0xb0,0x56,0xa0,0xbf,0x27};
    NSData *actual = [NSData dataWithBytes:&token length:sizeof(token)];
    if (!valid || connectionUID != 501 || audit_token_to_euid(token) != connectionUID ||
        audit_token_to_pid(token) <= 1 || !serviceASID || (uint32_t)audit_token_to_asid(token) != serviceASID ||
        expectedToken.length != sizeof(token) || ![expectedToken isEqual:actual] ||
        ![info isKindOfClass:NSDictionary.class]) return NO;
    NSURL *path = info[(__bridge id)kSecCodeInfoMainExecutable];
    NSData *hash = info[(__bridge id)kSecCodeInfoUnique];
    NSString *identifier = info[(__bridge id)kSecCodeInfoIdentifier];
    NSDictionary *entitlements = info[(__bridge id)kSecCodeInfoEntitlementsDict];
    return [identifier isEqual:@"com.apple.Touch-ID-Settings.extension"] &&
        (nativePermissionsForPeer(connectionUID, valid, identifier, entitlements) & NativePeerEnroll) &&
        [path isKindOfClass:NSURL.class] && path.isFileURL &&
        [path.path isEqual:@"/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password"] &&
        [hash isKindOfClass:NSData.class] && hash.length == sizeof(pin) &&
        !memcmp(hash.bytes, pin, sizeof(pin));
}

static BOOL ELANSettingsPeerCurrent(NSXPCConnection *peer, NSData *expectedToken) {
    if (!peer || ![peer respondsToSelector:@selector(auditToken)]) return NO;
    audit_token_t token = peer.auditToken, selfToken = {};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&selfToken, &count) ||
        count != TASK_AUDIT_TOKEN_COUNT) return NO;
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributeAudit:
        [NSData dataWithBytes:&token length:sizeof(token)]};
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef information = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code);
    if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
    if (!status) status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
    NSDictionary *info = CFBridgingRelease(information);
    BOOL accepted = ELANSettingsPeerEvidence(token, expectedToken, audit_token_to_asid(selfToken),
        peer.effectiveUserIdentifier, status == errSecSuccess, info);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    return accepted;
}
