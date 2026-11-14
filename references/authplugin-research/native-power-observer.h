#import <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <time.h>
#include "native-power-state.h"

static double nativePowerTime(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}

@interface ElanPowerObserver : NSObject {
    io_connect_t _root;
    io_object_t _notifier;
    IONotificationPortRef _port;
    dispatch_queue_t _queue;
    dispatch_source_t _timer;
    NativePowerState _state;
    BOOL _deferSleep;
    void (^_stopHandler)(void);
}
- (BOOL)openDeferringSleep:(BOOL)defer stop:(void (^)(void))handler;
- (NSDictionary *)snapshot;
- (void)close;
- (void)message:(natural_t)message token:(intptr_t)token;
@end

static void nativePowerCallback(void *context, io_service_t service, natural_t message, void *argument) {
    (void)service;
    [(__bridge ElanPowerObserver *)context message:message token:(intptr_t)argument];
}

@implementation ElanPowerObserver
- (void)acknowledge:(NativePowerAcknowledgement)ack {
    for (unsigned i = 0; i < ack.count; ++i) {
        IOReturn status = IOAllowPowerChange(_root, ack.tokens[i]);
        if (status) fprintf(stderr, "ELAN_POWER acknowledgement=0x%x\n", status);
    }
    if (ack.expired) fprintf(stderr, "ELAN_POWER cleanup_deadline=1\n");
}
- (BOOL)openDeferringSleep:(BOOL)defer stop:(void (^)(void))handler {
    if (_queue) return NO;
    _queue = dispatch_queue_create("io.github.hackintosh-tools.elan-power", DISPATCH_QUEUE_SERIAL);
    _deferSleep = defer; _stopHandler = [handler copy]; _state.awake = true;
    _root = IORegisterForSystemPower((__bridge void *)self, &_port, nativePowerCallback, &_notifier);
    if (!_root || !_port || !_notifier) { [self close]; return NO; }
    IONotificationPortSetDispatchQueue(_port, _queue);
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    __weak ElanPowerObserver *weakSelf = self;
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC, 100 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(_timer, ^{
        ElanPowerObserver *owner = weakSelf;
        if (owner && owner->_root) [owner acknowledge:nativePowerDeadline(&owner->_state, nativePowerTime())];
    });
    dispatch_resume(_timer);
    return YES;
}
- (void)message:(natural_t)message token:(intptr_t)token {
    if (!_root) return;
    NativePowerEvent event;
    switch (message) {
        case kIOMessageCanSystemSleep: event = NativePowerIdle; break;
        case kIOMessageSystemWillSleep: event = NativePowerSleep; break;
        case kIOMessageSystemWillPowerOn: event = NativePowerWakeStarting; break;
        case kIOMessageSystemHasPoweredOn: event = NativePowerWakeComplete; break;
        case kIOMessageSystemWillNotSleep: event = NativePowerSleepCancelled; break;
        default: return;
    }
    BOOL wasStopped = _state.stop;
    NativePowerAcknowledgement ack = nativePowerEvent(&_state, event, token, nativePowerTime(), _deferSleep);
    if (_state.stop && !wasStopped && _stopHandler) _stopHandler();
    [self acknowledge:ack];
}
- (NSDictionary *)snapshot {
    __block NSDictionary *result;
    dispatch_sync(_queue, ^{
        uint64_t capabilities = 0; BOOL known = NO;
        io_service_t domain = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"));
        if (domain) {
            CFTypeRef value = IORegistryEntryCreateCFProperty(domain, CFSTR("System Capabilities"), kCFAllocatorDefault, 0);
            if (value) {
                known = CFGetTypeID(value) == CFNumberGetTypeID() && CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &capabilities);
                CFRelease(value);
            }
            IOObjectRelease(domain);
        }
        result = @{ @"ready": @((BOOL)(self->_root && nativePowerReady(self->_state, known, capabilities))),
            @"capabilities_known": @(known), @"capabilities": @(capabilities),
            @"awake": @(self->_state.awake), @"epoch": @(self->_state.epoch), @"stopped": @(self->_state.stop) };
    });
    return result;
}
- (void)close {
    if (!_queue) return;
    dispatch_sync(_queue, ^{
        if (self->_timer) { dispatch_source_cancel(self->_timer); self->_timer = nil; }
        if (self->_root) [self acknowledge:nativePowerDrain(&self->_state)];
        if (self->_notifier) IODeregisterForSystemPower(&self->_notifier);
        self->_notifier = IO_OBJECT_NULL;
        if (self->_port) { IONotificationPortDestroy(self->_port); self->_port = NULL; }
        if (self->_root) { IOServiceClose(self->_root); self->_root = IO_OBJECT_NULL; }
        self->_stopHandler = nil;
    });
    // Drain already queued callbacks while their refcon remains alive.
    dispatch_sync(_queue, ^{});
}
@end
