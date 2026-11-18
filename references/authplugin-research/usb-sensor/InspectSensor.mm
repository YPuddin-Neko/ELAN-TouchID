#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <IOKit/IOKitLib.h>
#import "SensorRegistry.h"
#include <xpc/xpc.h>
#include <unistd.h>
#import "AccessoryDiscovery.h"

static NSNumber *sensorInterfaceForEvent(bool fromDriver, uint64_t serviceID) {
    if (!serviceID) return nil;
    if (!fromDriver) return @(serviceID);
    io_service_t driver = IOServiceGetMatchingService(kIOMainPortDefault, IORegistryEntryIDMatching(serviceID));
    if (!driver) return nil;
    io_registry_entry_t parent = IO_OBJECT_NULL;
    uint64_t ident = 0;
    if (IOObjectConformsTo(driver, "ELANFingerprintUSB") &&
        IORegistryEntryGetParentEntry(driver, kIOServicePlane, &parent) == KERN_SUCCESS) {
        if (IOObjectConformsTo(parent, "IOUSBHostInterface")) IORegistryEntryGetRegistryEntryID(parent, &ident);
        IOObjectRelease(parent);
    }
    IOObjectRelease(driver);
    return ident ? @(ident) : nil;
}

static int inspect(NSNumber *eventID, bool summary) {
    NSArray *interfaces = ELANSensorInterfaces();
    NSArray *drivers = ELANMatchingIDs(@{@"IOProviderClass": @"ELANFingerprintUSB"});
    if (!interfaces || !drivers) return 2;
    bool verified = false, attached = false;
    IOReturn status = kIOReturnNotFound;
    if (interfaces.count == 1 && (!eventID || [interfaces containsObject:eventID])) {
        io_service_t interface = IOServiceGetMatchingService(kIOMainPortDefault,
            IORegistryEntryIDMatching([interfaces.firstObject unsignedLongLongValue]));
        verified = ELANVerifyInterface(interfaces.firstObject, &status);
        if (interface && drivers.count == 1) {
            io_service_t driver = IOServiceGetMatchingService(kIOMainPortDefault,
                IORegistryEntryIDMatching([drivers.firstObject unsignedLongLongValue]));
            io_registry_entry_t parent = IO_OBJECT_NULL;
            if (driver && IORegistryEntryGetParentEntry(driver, kIOServicePlane, &parent) == KERN_SUCCESS) {
                attached = IOObjectIsEqualTo(interface, parent);
                IOObjectRelease(parent);
            }
            if (driver) IOObjectRelease(driver);
        }
        if (interface) IOObjectRelease(interface);
    }
    LAContext *context = [LAContext new];
    NSError *error = nil;
    BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    NSNumber *systemCount = ELANSystemDeviceCount();
    NSNumber *platform = ELANSystemTouchIDPlatform();
    NSDictionary *result = @{@"uid": @(getuid()), @"interface_count": @(interfaces.count),
        @"system_device_count": systemCount ?: NSNull.null,
        @"system_touchid_platform": platform ?: NSNull.null,
        @"usb_profile_verified": @(verified), @"usb_query_status": @(status),
        @"usb_event_verified": @(eventID && verified), @"usb_driver_attached": @(attached),
        @"biometry_type": @(context.biometryType), @"la_policy_available": @(available),
        @"la_error_domain": error.domain ?: @"", @"la_error": @(error.code)};
    [context invalidate];
    if (summary) {
        if (verified) puts("已识别 ELAN 04f3:0c1a 和指纹采集端点。");
        else printf("匹配到 %lu 个 ELAN 接口，无法确认传感器端点。\n", (unsigned long)interfaces.count);
        puts(attached ? "ELAN USB 指纹驱动已连接。" : "ELAN USB 指纹驱动尚未连接。");
        if (systemCount) printf("苹果生物识别框架列出 %lu 个设备。\n", systemCount.unsignedLongValue);
        if (available) puts("系统生物识别认证可用。");
        else printf("系统生物识别认证当前不可用（%s %ld）。\n", error.domain.UTF8String ?: "", (long)error.code);
        return verified ? 0 : 1;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:nil];
    if (!data) return 2;
    fwrite(data.bytes, 1, data.length, stdout);
    putchar('\n');
    fflush(stdout);
    return verified ? 0 : 1;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (!getuid() || geteuid() != getuid()) return 2;
        if (argc == 1) return inspect(nil, false);
        if (argc == 2 && !strcmp(argv[1], "--summary")) return inspect(nil, true);
        if (argc != 3) return 2;
        NSString *service = [NSString stringWithUTF8String:argv[2]];
        if (!ELANDiscoveryNameAllowed(service)) return 2;
        if (!strcmp(argv[1], "--read-discovery")) return ELANReadDiscovery(service);
        if (strcmp(argv[1], "--on-attach")) return 2;
        __block bool serving = false;
        xpc_set_event_stream_handler("com.apple.iokit.matching", dispatch_get_main_queue(), ^(xpc_object_t event) {
            const char *name = xpc_dictionary_get_string(event, XPC_EVENT_KEY_NAME);
            uint64_t serviceID = xpc_dictionary_get_uint64(event, "IOMatchLaunchServiceID");
            if (!name) return;
            bool fromDriver = !strcmp(name, "ELANFingerprintUSB");
            if (!fromDriver && strcmp(name, "ELANUsbInterface")) return;
            NSNumber *entry = sensorInterfaceForEvent(fromDriver, serviceID);
            if (serving || !entry) return;
            int status = inspect(entry, false);
            if (status) exit(status);
            serving = true;
            ELANServeDiscovery(service, ^BOOL{
                NSNumber *current = sensorInterfaceForEvent(fromDriver, serviceID);
                return [entry isEqual:current] && [ELANSensorInterfaces() isEqualToArray:@[entry]];
            }, nil);
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ exit(3); });
        dispatch_main();
    }
}
