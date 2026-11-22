#pragma once
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif
BOOL ELANAcceptSettingsEnrollment(NSXPCConnection *peer, id accessory, BOOL (^sensorPresent)(void));
void ELANSyncPublishedCatalog(void);
void ELANHardenServiceInstallation(void);
#ifdef __cplusplus
}
#endif
