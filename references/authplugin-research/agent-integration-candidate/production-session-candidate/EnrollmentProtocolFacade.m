#import "EnrollmentProtocolFacade.h"
#import <objc/runtime.h>
#include <dlfcn.h>
#include <string.h>
static NSArray<NSString*> *readSelectors(void){return @[@"connect:client:replyBlock:",@"disconnect:replyBlock:",@"registerDelegate:client:replyBlock:",@"getDeviceHardwareState:replyBlock:",@"listAccessories:replyBlock:",@"getBiometryAvailabilityForUser:client:replyBlock:",@"getMaxIdentityCount:client:replyBlock:",@"getFreeIdentityCount:user:client:replyBlock:",@"identities:client:replyBlock:",@"getIdentitiesDatabaseHashForUser:client:replyBlock:",@"getBioLockoutStateForUser:client:replyBlock:",@"getIdentityFromUUID:client:replyBlock:",@"cancel:replyBlock:",@"logEventOrCode:",@"getProtectedConfigurationForUser:client:replyBlock:",@"getSystemProtectedConfiguration:replyBlock:",@"isAriadneSignpostsEnabled:replyBlock:"];}
static NSArray<NSString*> *enrollSelectors(void){return @[@"enroll:user:options:async:client:replyBlock:",@"enrollContinue:replyBlock:",@"completeEnrollment:replyBlock:",@"pullAlignmentData:replyBlock:",@"updateIdentity:options:async:client:replyBlock:",@"removeIdentity:options:async:client:replyBlock:",@"removeAllIdentitiesForUser:options:async:client:replyBlock:",@"match:options:async:client:replyBlock:"];}
BOOL ElanEnrollmentFacadeABICompatible(void){
 const char*(*encoding)(Protocol*,SEL,BOOL,BOOL)=dlsym(RTLD_DEFAULT,"_protocol_getMethodTypeEncoding");
 Protocol*p=objc_getProtocol("BiometricKitXpcProtocol");
 if(!p||!encoding||!objc_getProtocol("BiometricKitDelegateXpcProtocol"))return NO;
 {const char*t=encoding(p,sel_registerName("connect:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v40@0:8@\"NSDictionary\"16Q24@?<v@?i>32"))return NO;}
 {const char*t=encoding(p,sel_registerName("disconnect:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?i>24"))return NO;}
 {const char*t=encoding(p,sel_registerName("registerDelegate:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8c16Q20@?<v@?i>28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getDeviceHardwareState:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?iI>24"))return NO;}
 {const char*t=encoding(p,sel_registerName("listAccessories:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?i@\"NSArray\">24"))return NO;}
 {const char*t=encoding(p,sel_registerName("getBiometryAvailabilityForUser:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8I16Q20@?<v@?iq>28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getMaxIdentityCount:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8i16Q20@?<v@?q>28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getFreeIdentityCount:user:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v40@0:8i16I20Q24@?<v@?q>32"))return NO;}
 {const char*t=encoding(p,sel_registerName("identities:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v40@0:8@\"NSDictionary\"16Q24@?<v@?@\"NSArray\">32"))return NO;}
 {const char*t=encoding(p,sel_registerName("getIdentitiesDatabaseHashForUser:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8I16Q20@?<v@?@\"NSData\">28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getBioLockoutStateForUser:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8I16Q20@?<v@?iq>28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getIdentityFromUUID:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v40@0:8@\"NSUUID\"16Q24@?<v@?@\"BiometricKitIdentity\">32"))return NO;}
 {const char*t=encoding(p,sel_registerName("cancel:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?i>24"))return NO;}
 {const char*t=encoding(p,sel_registerName("logEventOrCode:"),YES,YES);if(!t||strcmp(t,"v24@0:8Q16"))return NO;}
 {const char*t=encoding(p,sel_registerName("enroll:user:options:async:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v52@0:8i16I20@\"NSDictionary\"24c32Q36@?<v@?i>44"))return NO;}
 {const char*t=encoding(p,sel_registerName("enrollContinue:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?i>24"))return NO;}
 {const char*t=encoding(p,sel_registerName("completeEnrollment:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?i>24"))return NO;}
 {const char*t=encoding(p,sel_registerName("pullAlignmentData:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?@\"NSData\">24"))return NO;}
 {const char*t=encoding(p,sel_registerName("updateIdentity:options:async:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v52@0:8@\"BiometricKitIdentity\"16@\"NSDictionary\"24c32Q36@?<v@?i>44"))return NO;}
 {const char*t=encoding(p,sel_registerName("removeIdentity:options:async:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v52@0:8@\"BiometricKitIdentity\"16@\"NSDictionary\"24c32Q36@?<v@?i>44"))return NO;}
 {const char*t=encoding(p,sel_registerName("removeAllIdentitiesForUser:options:async:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v48@0:8I16@\"NSDictionary\"20c28Q32@?<v@?i>40"))return NO;}
 {const char*t=encoding(p,sel_registerName("match:options:async:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v52@0:8@\"NSDictionary\"16@\"NSDictionary\"24c32Q36@?<v@?i>44"))return NO;}
 {const char*t=encoding(p,sel_registerName("getProtectedConfigurationForUser:client:replyBlock:"),YES,YES);if(!t||strcmp(t,"v36@0:8I16Q20@?<v@?@\"NSDictionary\">28"))return NO;}
 {const char*t=encoding(p,sel_registerName("getSystemProtectedConfiguration:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?@\"NSDictionary\">24"))return NO;}
 {const char*t=encoding(p,sel_registerName("isAriadneSignpostsEnabled:replyBlock:"),YES,YES);if(!t||strcmp(t,"v32@0:8Q16@?<v@?c>24"))return NO;}
 Protocol*delegate=objc_getProtocol("BiometricKitDelegateXpcProtocol");
 {const char*t=encoding(delegate,sel_registerName("statusMessage:client:"),YES,YES);if(!t||strcmp(t,"v28@0:8I16Q20"))return NO;}
 {const char*t=encoding(delegate,sel_registerName("enrollResult:details:client:"),YES,YES);if(!t||strcmp(t,"v40@0:8@\"BiometricKitIdentity\"16@\"NSDictionary\"24Q32"))return NO;}
 {const char*t=encoding(delegate,sel_registerName("matchResult:details:client:"),YES,YES);if(!t||strcmp(t,"v40@0:8@\"BiometricKitIdentity\"16@\"NSDictionary\"24Q32"))return NO;}
 return YES;
}
@interface ElanEnrollmentProtocolFacade : NSObject
@property(nonatomic,strong) id target;
@property(nonatomic,weak) NSXPCConnection*peer;
@property(nonatomic,copy) BOOL(^enrollmentGate)(void);
@property(nonatomic,copy) void(^readObserver)(NSString*);
@end
@implementation ElanEnrollmentProtocolFacade
// This provider does not emit Ariadne kdebug signposts. This diagnostic flag
// describes this service, not Apple's daemon or enrollment authorization.
- (void)isAriadneSignpostsEnabled:(uint64_t)client replyBlock:(void(^)(BOOL))reply {
 (void)client;reply(NO);
 if(self.readObserver)self.readObserver(@"isAriadneSignpostsEnabled:replyBlock:");
}

- (BOOL)allows:(SEL)selector {
 NSString*name=NSStringFromSelector(selector);
 BOOL allowed=[readSelectors() containsObject:name];
 if(!allowed&&[enrollSelectors() containsObject:name]){
  @try{allowed=self.enrollmentGate&&self.enrollmentGate();}
  @catch(NSException*exception){(void)exception;allowed=NO;}
 }
 return allowed&&[self.target respondsToSelector:selector];
}
- (NSMethodSignature*)protocolSignature:(SEL)selector {
 Protocol*p=objc_getProtocol("BiometricKitXpcProtocol");
 struct objc_method_description d=protocol_getMethodDescription(p,selector,YES,YES);
 if(!d.types)d=protocol_getMethodDescription(p,selector,NO,YES);
 return d.types?[NSMethodSignature signatureWithObjCTypes:d.types]:nil;
}
- (BOOL)respondsToSelector:(SEL)selector {
 return [self protocolSignature:selector]!=nil||[super respondsToSelector:selector];
}
- (NSMethodSignature*)methodSignatureForSelector:(SEL)selector {
 return [self protocolSignature:selector]?:[super methodSignatureForSelector:selector];
}
- (void)reject:(SEL)selector {
 fprintf(stderr,"ENROLLMENT_FACADE rejected_selector=%s\n",sel_getName(selector));
 // Only the offending peer closes. Do not invent a reply block ABI or throw.
 [self.peer invalidate];
}
- (void)forwardInvocation:(NSInvocation*)invocation {
 if(![self allows:invocation.selector]){[self reject:invocation.selector];return;}
 if(invocation.selector==sel_registerName("match:options:async:client:replyBlock:")){
  __unsafe_unretained id options=nil;[invocation getArgument:&options atIndex:3];
  if(![options isKindOfClass:NSDictionary.class]||![options[@"BKOptionMatchForExtendEnrollment"] isEqual:@YES]||
     options[@"BKOptionMatchForCredentialSet"]||[options[@"BKOptionMatchForUnlock"] boolValue]){
   [self reject:invocation.selector];return;
  }
 }
 @try{[invocation invokeWithTarget:self.target];
  if(self.readObserver&&[readSelectors() containsObject:NSStringFromSelector(invocation.selector)])self.readObserver(NSStringFromSelector(invocation.selector));
 }
 @catch(NSException*exception){
  fprintf(stderr,"ENROLLMENT_FACADE target_exception=%s selector=%s\n",exception.name.UTF8String,sel_getName(invocation.selector));
  [self reject:invocation.selector];
 }
}
- (void)doesNotRecognizeSelector:(SEL)selector {[self reject:selector];}
@end
id ElanCreateEnrollmentProtocolFacadeWithGateAndObserver(id target,NSXPCConnection*peer,BOOL(^gate)(void),void(^observer)(NSString*)){
 if(!target||!peer||!gate||!ElanEnrollmentFacadeABICompatible())return nil;
 ElanEnrollmentProtocolFacade*facade=[ElanEnrollmentProtocolFacade new];
 facade.target=target;facade.peer=peer;facade.enrollmentGate=gate;facade.readObserver=observer;return facade;
}
id ElanCreateEnrollmentProtocolFacadeWithGate(id target,NSXPCConnection*peer,BOOL(^gate)(void)){return ElanCreateEnrollmentProtocolFacadeWithGateAndObserver(target,peer,gate,nil);}
id ElanCreateEnrollmentProtocolFacade(id target,NSXPCConnection*peer,BOOL allowEnrollment){
 return ElanCreateEnrollmentProtocolFacadeWithGate(target,peer,^{return allowEnrollment;});
}
NSXPCInterface*ElanEnrollmentExportedInterface(void){
 if(!ElanEnrollmentFacadeABICompatible())return nil;
 Class identity=NSClassFromString(@"BiometricKitIdentity"),accessory=NSClassFromString(@"BiometricKitAccessory");
 if(!identity||!accessory)return nil;
 NSXPCInterface*i=[NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitXpcProtocol")];
 [i setClasses:[NSSet setWithObjects:NSArray.class,identity,nil] forSelector:sel_registerName("identities:client:replyBlock:") argumentIndex:0 ofReply:YES];
 [i setClasses:[NSSet setWithObject:identity] forSelector:sel_registerName("getIdentityFromUUID:client:replyBlock:") argumentIndex:0 ofReply:YES];
 for(NSString*name in @[@"updateIdentity:options:async:client:replyBlock:",@"removeIdentity:options:async:client:replyBlock:"])
  [i setClasses:[NSSet setWithObject:identity] forSelector:NSSelectorFromString(name) argumentIndex:0 ofReply:NO];
 [i setClasses:[NSSet setWithObjects:NSArray.class,NSDictionary.class,NSString.class,NSNumber.class,identity,NSUUID.class,nil] forSelector:sel_registerName("match:options:async:client:replyBlock:") argumentIndex:0 ofReply:NO];
 [i setClasses:[NSSet setWithObjects:NSArray.class,accessory,nil] forSelector:sel_registerName("listAccessories:replyBlock:") argumentIndex:1 ofReply:YES];
 for(NSString*name in @[@"getProtectedConfigurationForUser:client:replyBlock:",@"getSystemProtectedConfiguration:replyBlock:"])
  [i setClasses:[NSSet setWithObjects:NSDictionary.class,NSString.class,NSNumber.class,nil] forSelector:NSSelectorFromString(name) argumentIndex:0 ofReply:YES];
 return i;
}
NSXPCInterface*ElanEnrollmentCallbackInterface(void){
 if(!ElanEnrollmentFacadeABICompatible())return nil;
 Class identity=NSClassFromString(@"BiometricKitIdentity");if(!identity)return nil;
 NSXPCInterface*i=[NSXPCInterface interfaceWithProtocol:objc_getProtocol("BiometricKitDelegateXpcProtocol")];
 for(NSString*name in @[@"enrollResult:details:client:",@"matchResult:details:client:"]){
  [i setClasses:[NSSet setWithObject:identity] forSelector:NSSelectorFromString(name) argumentIndex:0 ofReply:NO];
  [i setClasses:[NSSet setWithObjects:NSDictionary.class,NSString.class,NSNumber.class,nil] forSelector:NSSelectorFromString(name) argumentIndex:1 ofReply:NO];
 }
 return i;
}
