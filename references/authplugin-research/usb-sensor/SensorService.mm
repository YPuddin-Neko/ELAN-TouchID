#import "AccessoryDiscovery.h"
#import "SensorRegistry.h"
#import "SettingsEnrollment.h"
#include <xpc/xpc.h>
#include <unistd.h>
void ELANObserveSettingsDriver();

int main(void) {
    @autoreleasepool {
        if (!getuid() || geteuid() != getuid()) return 2;
        // launchd retains IOKit events until consumed. XPC reads check the current device independently.
        xpc_set_event_stream_handler("com.apple.iokit.matching", dispatch_get_main_queue(), ^(xpc_object_t event) {
            const char *name = xpc_dictionary_get_string(event, XPC_EVENT_KEY_NAME);
            if (name && !strcmp(name, "ELANUsbInterface")) {
                puts("ELAN USB interface attached");
                fflush(stdout);
            }
        });
        ELANObserveSettingsDriver();
        ELANServeDiscovery(ELANSensorServiceName, ^BOOL{
            NSArray<NSNumber *> *interfaces = ELANSensorInterfaces();
            IOReturn status;
            return interfaces.count == 1 && ELANVerifyInterface(interfaces.firstObject, &status);
        }, ^BOOL(NSXPCConnection *peer, id accessory, BOOL (^present)(void)) {
            return ELANAcceptSettingsEnrollment(peer, accessory, present);
        });
        dispatch_main();
    }
}
