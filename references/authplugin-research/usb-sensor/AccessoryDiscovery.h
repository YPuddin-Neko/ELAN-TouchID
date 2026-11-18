#pragma once
#import <Foundation/Foundation.h>

extern NSString *const ELANSensorServiceName;
BOOL ELANDiscoveryNameAllowed(NSString *name);
NSNumber *ELANSystemDeviceCount(void);
NSNumber *ELANSystemTouchIDPlatform(void);
typedef BOOL (^ELANSettingsHandler)(NSXPCConnection *, id, BOOL (^)(void));
void ELANServeDiscovery(NSString *service, BOOL (^sensorPresent)(void), ELANSettingsHandler handleSettings);
int ELANReadDiscovery(NSString *service);
