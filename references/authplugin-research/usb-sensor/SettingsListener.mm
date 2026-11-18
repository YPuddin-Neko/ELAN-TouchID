#import "SensorRegistry.h"
#import "SettingsEnrollment.h"
#include "DirectEnrollmentPolicy.h"
#include <CoreFoundation/CoreFoundation.h>
#include <notify.h>

namespace {
void syncSystemSettingsTouchIDState(bool available) {
    CFStringRef domain = CFSTR("com.apple.systemsettings.extensions");
    CFStringRef stateKey = CFSTR("current_state");
    CFStringRef hosts[2] = {kCFPreferencesCurrentHost, kCFPreferencesAnyHost};
    CFBooleanRef desired = available ? kCFBooleanTrue : kCFBooleanFalse;
    bool changed = false;
    for (CFStringRef host : hosts) {
        CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, host);
        id raw = CFBridgingRelease(CFPreferencesCopyValue(stateKey, domain, kCFPreferencesCurrentUser, host));
        if (![raw isKindOfClass:NSDictionary.class]) continue;
        NSDictionary *state = static_cast<NSDictionary *>(raw);
        id existing = state[@"device.touchID"];
        if (existing && CFGetTypeID((__bridge CFTypeRef)existing) == CFBooleanGetTypeID() &&
            [existing boolValue] == available) {
            continue;
        }
        NSMutableDictionary *updated = [state mutableCopy];
        updated[@"device.touchID"] = (__bridge id)desired;
        CFPreferencesSetValue(stateKey, (__bridge CFDictionaryRef)updated, domain, kCFPreferencesCurrentUser, host);
        if (CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, host)) changed = true;
    }
    if (changed) notify_post("com.apple.systemsettings.extensions.didchange");
}

// IOKit delivers all notifications on the main queue. Holding the user-client port
// ties the published listener to this login and to the lifetime of this process.
struct Listener {
    IONotificationPortRef port = nullptr;
    io_iterator_t iterators[4] = {};
    io_connect_t channel = IO_OBJECT_NULL;
    uint64_t sensorID = 0, driverID = 0;
    unsigned retrySeconds = 1;
    dispatch_source_t retry;

    void scheduleSidebarReconcile() {
        const int64_t delays[2] = {3, 10};
        for (int64_t delaySeconds : delays) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delaySeconds * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                @autoreleasepool {
                    if (this->channel != IO_OBJECT_NULL) syncSystemSettingsTouchIDState(true);
                }
            });
        }
    }

    void refresh() {
        dispatch_source_set_timer(retry,DISPATCH_TIME_FOREVER,DISPATCH_TIME_FOREVER,0);
        NSArray<NSNumber *> *devices = ELANSensorInterfaces();
        NSArray<NSNumber *> *drivers = ELANMatchingIDs(@{@"IOProviderClass":@"ELANNativeProbe"});
        uint64_t sensor = devices.count==1 ? devices.firstObject.unsignedLongLongValue : 0;
        uint64_t driver = drivers.count==1 ? drivers.firstObject.unsignedLongLongValue : 0;
        if (channel && sensor==sensorID && driver==driverID) return;
        bool wasPublished = channel != IO_OBJECT_NULL;
        if (channel) { IOServiceClose(channel); channel=IO_OBJECT_NULL; }
        sensorID=sensor; driverID=driver;
        if (!sensor || !driver) {
            retrySeconds=1;
            if (wasPublished) {
                notify_post("com.apple.BiometricKit.connectedAccessoriesChanged");
                syncSystemSettingsTouchIDState(false);
            }
            return;
        }
        IOReturn status=kIOReturnNotReady;
        if (ELANVerifyInterface(devices.firstObject,&status)) {
            status=elanOpenDirectEnrollment(&channel);
            if (!status) status=IOConnectCallScalarMethod(channel,ElanPublishSettingsListener,nullptr,0,nullptr,nullptr);
            if (!status) {
                retrySeconds=1;
                ELANSyncPublishedCatalog();
                notify_post("com.apple.BiometricKit.connectedAccessoriesChanged");
                notify_post("com.apple.BiometricKit.enrollmentChanged");
                syncSystemSettingsTouchIDState(true);
                scheduleSidebarReconcile();
                return;
            }
            if (channel) { IOServiceClose(channel); channel=IO_OBJECT_NULL; }
            if (status==kIOReturnBadArgument || status==kIOReturnUnsupported || status==kIOReturnNotPrivileged) return;
        }
        dispatch_source_set_timer(retry,dispatch_time(DISPATCH_TIME_NOW,retrySeconds*NSEC_PER_SEC),
                                  DISPATCH_TIME_FOREVER,NSEC_PER_SEC/4);
        if (retrySeconds<30) retrySeconds=MIN(30U,2*retrySeconds);
    }
    static void changed(void *context,io_iterator_t iterator) {
        while (io_object_t entry=IOIteratorNext(iterator)) IOObjectRelease(entry);
        @autoreleasepool { static_cast<Listener *>(context)->refresh(); }
    }
    bool start() {
        port=IONotificationPortCreate(kIOMainPortDefault);
        if (!port) return false;
        retry=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
        if (!retry) { IONotificationPortDestroy(port); return false; }
        dispatch_source_set_event_handler(retry,^{ @autoreleasepool { this->refresh(); } });
        dispatch_source_set_timer(retry,DISPATCH_TIME_FOREVER,DISPATCH_TIME_FOREVER,0);
        dispatch_resume(retry);
        IONotificationPortSetDispatchQueue(port,dispatch_get_main_queue());
        for (unsigned index=0;index<4;index++) {
            NSDictionary *match=index<2 ? ELANSensorMatch() : @{@"IOProviderClass":@"ELANNativeProbe"};
            if (IOServiceAddMatchingNotification(port,index%2 ? kIOTerminatedNotification : kIOFirstMatchNotification,
                    (__bridge_retained CFDictionaryRef)match,changed,this,&iterators[index])) {
                for (auto item:iterators) if (item) IOObjectRelease(item);
                IONotificationPortDestroy(port);
                dispatch_source_cancel(retry);
                return false;
            }
            while (io_object_t entry=IOIteratorNext(iterators[index])) IOObjectRelease(entry);
        }
        refresh();
        return true;
    }
};
}
void ELANObserveSettingsDriver() {
    static Listener listener{};
    if (!listener.start()) fputs("ELAN driver notifications unavailable\n",stderr);
}
