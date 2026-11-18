#pragma once
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

NSArray<NSNumber *> *ELANSensorInterfaces(void);
NSDictionary *ELANSensorMatch(void);
NSArray<NSNumber *> *ELANMatchingIDs(NSDictionary *table);
BOOL ELANVerifyInterface(NSNumber *entryID, IOReturn *status);
