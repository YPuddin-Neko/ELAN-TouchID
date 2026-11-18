#pragma once
#import <Foundation/Foundation.h>
// Call only after authenticating this NSXPC peer and deciding its trial role.
// NO permits read/lifecycle only; YES additionally permits initial enrollment.
// Neither mode permits match, supplement, identity deletion/rename or configuration.
BOOL ElanEnrollmentFacadeABICompatible(void);
id ElanCreateEnrollmentProtocolFacade(id target, NSXPCConnection *peer, BOOL allowEnrollment);
// Gate is evaluated for each enrollment call; it must derive from trusted runtime state.
id ElanCreateEnrollmentProtocolFacadeWithGate(id target, NSXPCConnection *peer, BOOL (^gate)(void));
NSXPCInterface *ElanEnrollmentExportedInterface(void);
NSXPCInterface *ElanEnrollmentCallbackInterface(void);

// Observer reports successful synchronous read dispatch, never client delivery.
id ElanCreateEnrollmentProtocolFacadeWithGateAndObserver(id target, NSXPCConnection *peer, BOOL (^gate)(void), void (^observer)(NSString *selector));
