#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <sys/sysctl.h>

int main(void) {
    @autoreleasepool {
        setbuf(stdout, NULL);
        char build[64] = {}; size_t length = sizeof(build);
        if (sysctlbyname("kern.osversion", build, &length, NULL, 0) || strcmp(build, "24H32")) return 2;
        void *framework = dlopen("/System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricSupport", RTLD_NOW | RTLD_LOCAL);
        Class exported = objc_getClass("BiometricKitXPCExportedObject");
        SEL selector = sel_registerName("entitlementsNeededForPermissionGroup:");
        Method mapping = class_getInstanceMethod(exported, selector);
        if (!framework || !mapping || method_getNumberOfArguments(mapping) != 3) return 3;
        char *result = method_copyReturnType(mapping), *argument = method_copyArgumentType(mapping, 2);
        BOOL valid = !strcmp(result, "@") && !strcmp(argument, "i");
        printf("SETTINGS_PERMISSION_METHOD encoding=%s supported=%d\n", method_getTypeEncoding(mapping), valid);
        free(result); free(argument);
        if (!valid) return 4;
        // On 24H32 this method returns a constant table entry and does not read its receiver.
        id (*lookup)(id, SEL, int) = (void *)method_getImplementation(mapping);
        for (unsigned group = 0; group <= 7; group++) {
            id entitlement = lookup(nil, selector, group);
            if (![entitlement isKindOfClass:NSString.class]) return 5;
            printf("SETTINGS_PERMISSION group=%u entitlement=%s\n", group, [entitlement UTF8String]);
        }
        Method audit = class_getInstanceMethod(NSXPCConnection.class, sel_registerName("auditToken"));
        printf("SETTINGS_XPC_AUDIT encoding=%s\n", audit ? method_getTypeEncoding(audit) : "missing");
        NSURL *settings = [NSURL fileURLWithPath:@"/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex"];
        SecStaticCodeRef code = NULL;
        SecRequirementRef requirement = NULL;
        CFDictionaryRef information = NULL;
        OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)settings, kSecCSDefaultFlags, &code);
        if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
        if (!status) status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
        if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
        NSDictionary *info = CFBridgingRelease(information);
        NSDictionary *entitlements = info[(__bridge id)kSecCodeInfoEntitlementsDict];
        NSMutableDictionary *selected = [NSMutableDictionary dictionary];
        for (NSString *key in entitlements)
            if ([key hasPrefix:@"com.apple.private.biometrickit."]) selected[key] = entitlements[key];
        NSData *json = [NSJSONSerialization dataWithJSONObject:selected options:NSJSONWritingSortedKeys error:NULL];
        printf("SETTINGS_SIGNATURE status=%d identifier=%s\n", status, [info[(__bridge id)kSecCodeInfoIdentifier] UTF8String]);
        printf("SETTINGS_ENTITLEMENTS %s\n", [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
        if (requirement) CFRelease(requirement);
        if (code) CFRelease(code);
        printf("SETTINGS_ACCESS_DONE status=%d processes_started=0 service_connections=0\n", status);
        return status ? 6 : 0;
    }
}
