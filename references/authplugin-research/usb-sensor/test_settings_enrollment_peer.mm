#import "SettingsEnrollmentPeer.h"
#include <cassert>
#include <cstdio>
int main() { @autoreleasepool {
    (void)&ELANSettingsPeerCurrent; (void)&nativePeerPermissions;
    audit_token_t token = {{501,501,20,501,20,1234,100002,77}};
    NSData *expected = [NSData dataWithBytes:&token length:sizeof(token)];
    const uint8_t hash[20]={0xe3,0xfe,0xc5,0x23,0xfc,0x8a,0xfc,0x4e,0x82,0xb0,0xe7,0x4d,0xf6,0x26,0x67,0xb0,0x56,0xa0,0xbf,0x27};
    NSString *path=@"/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password";
    NSDictionary *entitlements=@{@"com.apple.private.biometrickit.allow-connect":@YES,
        @"com.apple.private.biometrickit.allow-enroll":@YES};
    NSDictionary *info=@{(__bridge id)kSecCodeInfoMainExecutable:[NSURL fileURLWithPath:path],
        (__bridge id)kSecCodeInfoIdentifier:@"com.apple.Touch-ID-Settings.extension",
        (__bridge id)kSecCodeInfoUnique:[NSData dataWithBytes:hash length:20],
        (__bridge id)kSecCodeInfoEntitlementsDict:entitlements};
    assert(ELANSettingsPeerEvidence(token,expected,100002,501,YES,info));
    assert(!ELANSettingsPeerEvidence(token,expected,100002,501,NO,info));
    assert(!ELANSettingsPeerEvidence(token,expected,100002,502,YES,info));
    assert(!ELANSettingsPeerEvidence(token,expected,0,501,YES,info));
    assert(!ELANSettingsPeerEvidence(token,expected,100003,501,YES,info));
    assert(!ELANSettingsPeerEvidence(token,nil,100002,501,YES,info));
    assert(!ELANSettingsPeerEvidence(token,[NSData data],100002,501,YES,info));
    assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,nil));
    for (unsigned i=0;i<8;++i) {
        audit_token_t changed=token; ++changed.val[i];
        assert(!ELANSettingsPeerEvidence(changed,expected,100002,501,YES,info));
    }
    for (NSUInteger n=0;n<20;++n) {
        NSMutableData *badHash=[info[(__bridge id)kSecCodeInfoUnique] mutableCopy];
        ((uint8_t *)badHash.mutableBytes)[n]^=1;
        NSMutableDictionary *bad=[info mutableCopy]; bad[(__bridge id)kSecCodeInfoUnique]=badHash;
        assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,bad));
    }
    NSArray *keys=@[(__bridge id)kSecCodeInfoMainExecutable,(__bridge id)kSecCodeInfoIdentifier,
        (__bridge id)kSecCodeInfoUnique,(__bridge id)kSecCodeInfoEntitlementsDict];
    for (id key in keys) {
        NSMutableDictionary *bad=[info mutableCopy]; [bad removeObjectForKey:key];
        assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,bad));
    }
    for (id badPath in @[[NSURL fileURLWithPath:@"/tmp/Touch ID & Password"],[NSURL URLWithString:@"https://example.invalid/"],path]) {
        NSMutableDictionary *bad=[info mutableCopy];bad[(__bridge id)kSecCodeInfoMainExecutable]=badPath;
        assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,bad));
    }
    for (id badEntitlements in @[@{},@{@"com.apple.private.biometrickit.allow-connect":@YES},
        @{@"com.apple.private.biometrickit.allow-enroll":@YES}]) {
        NSMutableDictionary *bad=[info mutableCopy];bad[(__bridge id)kSecCodeInfoEntitlementsDict]=badEntitlements;
        assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,bad));
    }
    NSMutableDictionary *other=[info mutableCopy];other[(__bridge id)kSecCodeInfoIdentifier]=@"com.apple.coreauthd";
    assert(!ELANSettingsPeerEvidence(token,expected,100002,501,YES,other));
    puts("Settings peer evidence passed: synthetic signatures and audit tokens only; no Security guest lookup or authentication invoked");
} }
