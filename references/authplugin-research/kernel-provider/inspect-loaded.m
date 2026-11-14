#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/IOKitServer.h>
#import <IOKit/IOCFUnserialize.h>
#import <IOKit/kext/KextManager.h>
#import <mach/mach.h>

int main(void) {
    @autoreleasepool {
        NSArray *identifiers = @[@"io.github.hackintosh-tools.elan-native-probe",
                                 @"as.vit9696.Lilu", @"com.apple.driver.AppleCredentialManager"];
        NSArray *keys = @[@"CFBundleIdentifier", @"CFBundleVersion", @"OSBundleStarted",
                         @"OSBundlePrelinked", @"OSBundleLoadTag", @"OSBundleRetainCount", @"OSBundleClasses"];
        NSDictionary *loaded = CFBridgingRelease(KextManagerCopyLoadedKextInfo(
            (__bridge CFArrayRef)identifiers, (__bridge CFArrayRef)keys));
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        result[@"loaded"] = loaded ?: @{};
        io_service_t acm = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleCredentialManager"));
        result[@"acm_service_present"] = @(acm != IO_OBJECT_NULL);
        if (acm) {
            NSDictionary *matching = @{@"IOProviderClass": @"AppleCredentialManager"};
            boolean_t matches = false;
            kern_return_t matchStatus = IOServiceMatchPropertyTable(acm, (__bridge CFDictionaryRef)matching, &matches);
            result[@"acm_provider_match"] = @{@"status": @(matchStatus), @"matches": @(matches)};
            IOObjectRelease(acm);
        }
        char *buffer = NULL;
        uint32_t size = 0;
        kern_return_t status = IOCatalogueGetData(kIOMainPortDefault, kIOCatalogGetContents, &buffer, &size);
        result[@"catalogue_status"] = @(status);
        result[@"catalogue_error_text"] = [NSString stringWithUTF8String:mach_error_string(status)];
        if (!status && buffer) {
            CFStringRef error = NULL;
            id catalogue = CFBridgingRelease(IOCFUnserializeWithSize(buffer, size, NULL, 0, &error));
            vm_deallocate(mach_task_self(), (vm_address_t)buffer, size);
            if (error) { result[@"catalogue_parse_error"] = CFBridgingRelease(error); }
            NSMutableArray *selected = [NSMutableArray array];
            if ([catalogue isKindOfClass:[NSArray class]]) {
                for (id entry in catalogue) {
                    if ([entry isKindOfClass:[NSDictionary class]] &&
                        [identifiers containsObject:entry[@"CFBundleIdentifier"]]) [selected addObject:entry];
                }
            } else result[@"catalogue_root_type"] = catalogue ? NSStringFromClass([catalogue class]) : @"nil";
            result[@"personalities"] = selected;
        }
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
        if (!json) { fprintf(stderr, "%s\n", error.description.UTF8String); return 1; }
        fwrite(json.bytes, 1, json.length, stdout);
        putchar('\n');
        return 0;
    }
}
