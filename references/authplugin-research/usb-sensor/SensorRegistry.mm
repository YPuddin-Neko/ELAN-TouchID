#import "SensorRegistry.h"
#import <IOKit/IOCFPlugIn.h>
#import <IOKit/usb/IOUSBLib.h>
#include "SensorProfile.h"

NSDictionary *ELANSensorMatch() {
    return @{@"IOProviderClass": @"IOUSBHostInterface", @"idVendor": @(elan::vendor),
             @"idProduct": @(elan::product), @"bConfigurationValue": @1, @"bInterfaceNumber": @0};
}

NSArray<NSNumber *> *ELANMatchingIDs(NSDictionary *table) {
    io_iterator_t iter = IO_OBJECT_NULL;
    kern_return_t result = IOServiceGetMatchingServices(kIOMainPortDefault, (__bridge_retained CFDictionaryRef)table, &iter);
    if (result != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceGetMatchingServices(%s): 0x%x\n", [table[@"IOProviderClass"] UTF8String], result);
        return nil;
    }
    if (iter == IO_OBJECT_NULL) return @[];
    NSMutableArray *ids = [NSMutableArray array];
    while (io_service_t entry = IOIteratorNext(iter)) {
        uint64_t ident = 0;
        kern_return_t err = IORegistryEntryGetRegistryEntryID(entry, &ident);
        IOObjectRelease(entry);
        if (err) { IOObjectRelease(iter); return nil; }
        [ids addObject:@(ident)];
    }
    bool complete = IOIteratorIsValid(iter);
    IOObjectRelease(iter);
    if (!complete) fprintf(stderr, "IOKit iterator changed for %s\n", [table[@"IOProviderClass"] UTF8String]);
    return complete ? ids : nil;
}

static bool sensorDescriptors(io_service_t device, IOReturn *status) {
    IOCFPlugInInterface **plugin = nullptr;
    SInt32 score = 0;
    *status = IOCreatePlugInInterfaceForService(device, kIOUSBDeviceUserClientTypeID,
                                                 kIOCFPlugInInterfaceID, &plugin, &score);
    if (*status || !plugin) return false;
    IOUSBDeviceInterface **usb = nullptr;
    HRESULT queried = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID),
                                                reinterpret_cast<void **>(&usb));
    (*plugin)->Release(plugin);
    if (queried != S_OK || !usb) { *status = kIOReturnUnsupported; return false; }
    IOUSBConfigurationDescriptorPtr config = nullptr;
    *status = (*usb)->GetConfigurationDescriptorPtr(usb, 0, &config);
    bool valid = !*status && config && elan::hasSensorInterface(
        reinterpret_cast<const uint8_t *>(config), USBToHostWord(config->wTotalLength));
    (*usb)->Release(usb);
    return valid;
}

NSArray<NSNumber *> *ELANSensorInterfaces(void) {
    return ELANMatchingIDs(ELANSensorMatch());
}

BOOL ELANVerifyInterface(NSNumber *entryID, IOReturn *status) {
    *status = kIOReturnNotFound;
    io_service_t interface = IOServiceGetMatchingService(kIOMainPortDefault,
        IORegistryEntryIDMatching(entryID.unsignedLongLongValue));
    if (!interface) return NO;
    BOOL verified = NO;
    io_registry_entry_t device = IO_OBJECT_NULL;
    if (IOObjectConformsTo(interface, "IOUSBHostInterface") &&
        IORegistryEntryGetParentEntry(interface, kIOServicePlane, &device) == KERN_SUCCESS) {
        if (IOObjectConformsTo(device, "IOUSBHostDevice")) verified = sensorDescriptors(device, status);
        IOObjectRelease(device);
    }
    IOObjectRelease(interface);
    return verified;
}
