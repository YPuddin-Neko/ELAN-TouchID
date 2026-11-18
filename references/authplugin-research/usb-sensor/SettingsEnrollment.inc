#import "SettingsEnrollment.h"
#import "SettingsEnrollmentPeer.h"
#import "../agent-integration-candidate/production-session-candidate/EnrollmentProtocolFacade.h"
#import <ApplicationServices/ApplicationServices.h>
#import <AppKit/AppKit.h>
#import <OpenDirectory/OpenDirectory.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <pwd.h>
#include <sys/stat.h>

#ifndef ELAN_VERIFY_MIN_PAIRS
#define ELAN_VERIFY_MIN_PAIRS 8
#endif

@interface ELANServiceController : ElanProviderController
@property(nonatomic) SecuritySessionId boundSecuritySession;
@end

@implementation ELANServiceController
- (BOOL)sessionIsCurrent {
    @synchronized (self) {
        if (providerInterrupted) {
            cancelled = 1;
            [self.current cancelCurrent];
            return NO;
        }
        if (getuid() != 501 || geteuid() != 501) return NO;
        SecuritySessionId sid = noSecuritySession;
        SessionAttributeBits attrs = 0;
        if (SessionGetInfo(callerSecuritySession, &sid, &attrs) != errSecSuccess ||
            !(attrs & sessionHasGraphicAccess) || !sid || sid == UINT32_MAX) return NO;
        if (self.boundSecuritySession && sid != self.boundSecuritySession) return NO;
        uint32_t consoleUser = UINT32_MAX;
        return nativeConsoleUser(&consoleUser) && consoleUser == 501;
    }
}
@end

@interface ELANSettingsEnrollmentConnection : ElanProviderConnection
@property(copy) BOOL (^sensorPresent)(void);
@property(copy) NSData *settingsPeerToken;
@property(nonatomic) BOOL isSettingsPeer;
@property(nonatomic) BOOL isCoreAuthPeer;
@property(nonatomic) NSInteger matchPresence;
- (void)reportMatchCaptureEvent:(ElanCaptureEvent)event;
@end

// All native Settings and CoreAuth connections share the same physical capture queue.
static ElanProviderController *settingsOwner;
static BOOL sensorClaimedForEnrollment;
static NSObject *settingsLock(void) {
    static NSObject *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; });
    return lock;
}

static void matchCaptureEvent(ElanCaptureEvent event) {
    ElanProviderConnection *owner = enrollmentCaptureOwner;
    if ([owner isKindOfClass:ELANSettingsEnrollmentConnection.class])
        [(ELANSettingsEnrollmentConnection *)owner reportMatchCaptureEvent:event];
}

static id defaultSensorAccessory(void) {
    id item = [NSClassFromString(@"BiometricKitAccessory") new];
    if (!item) return nil;
    [item setValue:[[NSUUID alloc] initWithUUIDString:@"0D62A891-28A1-4818-A321-04F3000C1A01"] forKey:@"uuid"];
    [item setValue:@1 forKey:@"type"];
    [item setValue:@2 forKey:@"flags"];
    [item setValue:@"ELAN 0c1a" forKey:@"name"];
    return item;
}

static NSURL *elanCatalogFileURL(void) {
    struct passwd *pw = getpwuid(getuid());
    NSString *home = (pw && pw->pw_dir && pw->pw_dir[0]) ?
        [NSString stringWithUTF8String:pw->pw_dir] : NSHomeDirectory();
    NSString *path = [home stringByAppendingPathComponent:
        @"Library/Application Support/ELANFingerprint/native-catalog-v2.plist"];
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

static NSURL *elanProtectedConfigURL(void) {
    return [[elanCatalogFileURL() URLByDeletingLastPathComponent]
        URLByAppendingPathComponent:@"protected-config.plist" isDirectory:NO];
}

static NSURL *elanUnlockSecretURL(void) {
    return [[elanCatalogFileURL() URLByDeletingLastPathComponent]
        URLByAppendingPathComponent:@".unlock-secret" isDirectory:NO];
}

static NSDictionary *elanLoadProtectedConfig(void) {
    NSMutableDictionary *defaults = [@{
        @"BKUserCfgTouchIDUnlockEnabled": @YES,
        @"BKUserCfgTouchIDIdentificationEnabled": @YES,
        @"BKUserCfgTouchIDLoginEnabled": @YES,
        @"BKUserCfgTouchIDApplePayEnabled": @YES,
    } mutableCopy];
    NSDictionary *saved = [NSDictionary dictionaryWithContentsOfURL:elanProtectedConfigURL()];
    if ([saved isKindOfClass:NSDictionary.class]) {
        for (NSString *key in defaults.allKeys) {
            id val = saved[key];
            if ([val isKindOfClass:NSNumber.class]) defaults[key] = @([val boolValue]);
        }
    }
    return defaults;
}

static void elanSaveProtectedConfig(NSDictionary *config) {
    NSURL *url = elanProtectedConfigURL();
    [[NSFileManager defaultManager] createDirectoryAtURL:[url URLByDeletingLastPathComponent]
                             withIntermediateDirectories:YES
                                              attributes:@{NSFilePosixPermissions: @0700}
                                                   error:nil];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:config
                                                              format:NSPropertyListBinaryFormat_v1_0
                                                             options:0
                                                               error:nil];
    if (data && [data writeToURL:url options:NSDataWritingAtomic error:nil]) {
        chmod(url.path.fileSystemRepresentation, 0600);
    }
}

static void elanEnsureDefaultTouchIDPreferences(BOOL hasEnrolledRecords) {
    if (!hasEnrolledRecords) return;
    CFStringRef purchaseDomain = CFSTR("com.apple.TouchID.preferences");
    CFStringRef purchaseKey = CFSTR("BiometricKit_UseTouchIDForPurchase");
    CFTypeRef existingPurchase = CFPreferencesCopyValue(purchaseKey, purchaseDomain, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
    if (!existingPurchase) {
        CFPreferencesSetValue(purchaseKey, kCFBooleanTrue, purchaseDomain, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
        CFPreferencesSynchronize(purchaseDomain, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
    } else {
        CFRelease(existingPurchase);
    }
    CFStringRef autofillKey = CFSTR("WebKitPreferences.useTouchIDForAutofill");
    CFTypeRef existingAutofill = CFPreferencesCopyValue(autofillKey, kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if (!existingAutofill) {
        CFPreferencesSetValue(autofillKey, kCFBooleanTrue, kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        CFPreferencesSynchronize(kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    } else {
        CFRelease(existingAutofill);
    }
    CFStringRef amsDomain = CFSTR("com.apple.AppleMediaServices");
    CFStringRef amsKey = CFSTR("AMSDeviceBiometricsState");
    CFTypeRef existingAms = CFPreferencesCopyValue(amsKey, amsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if (!existingAms) {
        int one = 1;
        CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &one);
        if (num) {
            CFPreferencesSetValue(amsKey, num, amsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
            CFPreferencesSynchronize(amsDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
            CFRelease(num);
        }
    } else {
        CFRelease(existingAms);
    }
}

static BOOL elanVerifyUserPassword(NSString *candidate) {
    if (!candidate.length || candidate.length > 128) return NO;
    NSError *err = nil;
    ODNode *node = [ODNode nodeWithSession:ODSession.defaultSession type:kODNodeTypeLocalNodes error:&err];
    if (!node) return NO;
    struct passwd *pw = getpwuid(getuid());
    NSString *userName = (pw && pw->pw_name && pw->pw_name[0]) ?
        [NSString stringWithUTF8String:pw->pw_name] : NSUserName();
    ODRecord *record = [node recordWithRecordType:kODRecordTypeUsers name:userName attributes:nil error:&err];
    return record && [record verifyPassword:candidate error:&err];
}

static void elanTrySyncCapturedPassphrase(void) {
    uint8_t buf[128] = {0};
    uint32_t len = 0;
    if (elanCopyDirectPassphrase(buf, &len) == 0 && len > 0 && len <= sizeof(buf)) {
        NSString *candidate = [[NSString alloc] initWithBytes:buf length:len encoding:NSUTF8StringEncoding];
        memset(buf, 0, sizeof(buf));
        if (candidate.length && elanVerifyUserPassword(candidate)) {
            NSURL *url = elanUnlockSecretURL();
            [[NSFileManager defaultManager] createDirectoryAtURL:[url URLByDeletingLastPathComponent]
                                     withIntermediateDirectories:YES
                                                      attributes:@{NSFilePosixPermissions: @0700}
                                                           error:nil];
            NSData *pwData = [candidate dataUsingEncoding:NSUTF8StringEncoding];
            if ([pwData writeToURL:url options:NSDataWritingAtomic error:nil]) {
                chmod(url.path.fileSystemRepresentation, 0600);
                ELAN_SETTINGS_DIAGNOSTIC("unlock-secret-synced", (int)pwData.length);
            }
        }
    } else {
        memset(buf, 0, sizeof(buf));
    }
}

static BOOL elanScreenLocked(void) {
    CFDictionaryRef d = CGSessionCopyCurrentDictionary();
    if (!d) return NO;
    CFTypeRef v = CFDictionaryGetValue(d, CFSTR("CGSSessionScreenIsLocked"));
    BOOL yes = v && CFGetTypeID(v) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)v);
    CFRelease(d);
    return yes;
}

static BOOL elanUnlockEnabledForUser(void) {
    NSDictionary *cfg = elanLoadProtectedConfig();
    return [cfg[@"BKUserCfgTouchIDUnlockEnabled"] boolValue];
}

static BOOL elanPerformLockScreenUnlock(void) {
    if (!elanScreenLocked() || !elanUnlockEnabledForUser()) return NO;
    NSURL *secretURL = elanUnlockSecretURL();
    NSData *pwData = [NSData dataWithContentsOfURL:secretURL];
    if (!pwData.length || pwData.length > 128) {
        elanTrySyncCapturedPassphrase();
        pwData = [NSData dataWithContentsOfURL:secretURL];
    }
    if (!pwData.length || pwData.length > 128) {
        ELAN_SETTINGS_DIAGNOSTIC("unlock-no-secret", 0);
        return NO;
    }
    IOPMAssertionID assertionID = kIOPMNullAssertionID;
    IOPMAssertionDeclareUserActivity(CFSTR("ELAN Touch ID Unlock"), kIOPMUserActiveLocal, &assertionID);
    usleep(80000);
    int status = elanDispatchDirectUnlock((const uint8_t *)pwData.bytes, (uint32_t)pwData.length);
    if (assertionID != kIOPMNullAssertionID) IOPMAssertionRelease(assertionID);
    return status == 0;
}

static void elanStartLockScreenWatcher(void);

static BOOL ELANCoreAuthPeerCurrent(NSXPCConnection *peer, NSData *expectedToken) {
    if (!peer || peer.effectiveUserIdentifier != 501 || ![peer respondsToSelector:@selector(auditToken)]) return NO;
    audit_token_t token = peer.auditToken, selfToken = {};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&selfToken, &count) ||
        count != TASK_AUDIT_TOKEN_COUNT) return NO;
    NSData *actual = [NSData dataWithBytes:&token length:sizeof(token)];
    if (audit_token_to_euid(token) != 501 || audit_token_to_pid(token) <= 1 ||
        !audit_token_to_asid(selfToken) || !audit_token_to_asid(token) ||
        expectedToken.length != sizeof(token) || ![expectedToken isEqual:actual]) return NO;
    unsigned perms = nativePeerPermissions(peer);
    return (perms & (NativePeerRead | NativePeerMatch)) == (NativePeerRead | NativePeerMatch) &&
        !(perms & NativePeerEnroll);
}

static ElanProviderController *ELANEnsureServiceController(id accessory) {
    @synchronized (settingsLock()) {
        ElanProviderController *owner = settingsOwner;
        if (owner && !owner.stopping && owner.session && !owner.session.invalidated) {
            if (accessory && !owner.accessory) owner.accessory = accessory;
            return owner;
        }
        if (sensorClaimedForEnrollment) return nil;
        ELANServiceController *created = [ELANServiceController new];
        SecuritySessionId sid = noSecuritySession;
        SessionAttributeBits attrs = 0;
        if (SessionGetInfo(callerSecuritySession, &sid, &attrs) == errSecSuccess &&
            (attrs & sessionHasGraphicAccess) && sid && sid != UINT32_MAX) {
            created.boundSecuritySession = sid;
        }
        created.broker = -1;
        created.accessory = accessory ?: defaultSensorAccessory();
        created.captureGroup = dispatch_group_create();
        created.captureQueue = dispatch_queue_create("io.hackmac.elan.capture", DISPATCH_QUEUE_SERIAL);
        created.repository = [[ElanFingerprintRepository alloc] initWithFileURL:elanCatalogFileURL()
            user:getuid() pid:0x0c1a width:144 height:64];
        NSError *error = nil;
        if (![created.repository load:&error]) {
            if (![error.domain isEqual:NSOSStatusErrorDomain] || error.code != errSecItemNotFound ||
                ![created.repository createEmpty:&error]) {
                ELAN_SETTINGS_DIAGNOSTIC("catalog-init", (int)error.code);
                return nil;
            }
        }
        created.session = [[ElanFingerprintSession alloc] initWithRepository:created.repository
            publisher:^int(ElanFingerprintCatalog *catalog) {
                if (catalog.user != getuid()) return kIOReturnNotReady;
                elanEnsureDefaultTouchIDPreferences(catalog.records.count != 0);
                NSData *bytes = nativeCatalogIdentityBytes(catalog);
                int syncStatus = elanSyncDirectCatalog((const uint8_t *)bytes.bytes, (uint32_t)catalog.records.count);
                if (syncStatus) ELAN_SETTINGS_DIAGNOSTIC("catalog-sync-warn", syncStatus);
                notify_post("com.apple.BiometricKit.enrollmentChanged");
                return 0;
            } error:&error];
        if (!created.session) {
            ELAN_SETTINGS_DIAGNOSTIC("session-init", (int)error.code);
            return nil;
        }
        elanEnsureDefaultTouchIDPreferences(created.repository.current.records.count != 0);
        capture_timeout_seconds = 35;
        capture_observer = observeCapture;
        settingsOwner = created;
        elanStartLockScreenWatcher();
        return created;
    }
}

void ELANSyncPublishedCatalog(void) {
    ElanProviderController *owner = ELANEnsureServiceController(defaultSensorAccessory());
    if (!owner) return;
    elanTrySyncCapturedPassphrase();
    NSData *bytes = nil;
    uint32_t count = 0;
    @synchronized (owner) {
        ElanFingerprintCatalog *catalog = owner.repository.current;
        if (!catalog) return;
        bytes = nativeCatalogIdentityBytes(catalog);
        count = (uint32_t)catalog.records.count;
    }
    (void)elanSyncDirectCatalog((const uint8_t *)bytes.bytes, count);
}

static int elanLockScreenShouldCancel(void) {
    return cancelled != 0 || !elanScreenLocked() || !elanUnlockEnabledForUser();
}

static void elanStartLockScreenWatcher(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_queue_t q = dispatch_queue_create("io.hackmac.elan.lockwatcher", DISPATCH_QUEUE_SERIAL);
        dispatch_async(q, ^{
            BOOL wasLocked = NO;
            int failures = 0;
            for (;;) {
                @autoreleasepool {
                    if (!elanScreenLocked() || !elanUnlockEnabledForUser()) {
                        wasLocked = NO;
                        failures = 0;
                        usleep(400000);
                        continue;
                    }
                    if (!wasLocked) {
                        wasLocked = YES;
                        failures = 0;
                        // Give coreauthd 600ms to claim the sensor first if it is active.
                        usleep(600000);
                        if (!elanScreenLocked()) continue;
                    }
                    if (failures >= 5) {
                        usleep(500000);
                        continue;
                    }
                    ElanProviderController *owner = settingsOwner;
                    if (!owner || owner.stopping) {
                        usleep(500000);
                        continue;
                    }
                    ElanFingerprintMatcher *matcher = nil;
                    BOOL canClaim = NO;
                    @synchronized (settingsLock()) {
                        @synchronized (owner) {
                            matcher = owner.matcher;
                            if (!owner.busy && !sensorClaimedForEnrollment && matcher.catalog.records.count > 0) {
                                sensorClaimedForEnrollment = YES;
                                owner.busy = YES;
                                canClaim = YES;
                            }
                        }
                    }
                    if (!canClaim) {
                        usleep(300000);
                        continue;
                    }
                    dispatch_group_async(owner.captureGroup, owner.captureQueue, ^{
                        @autoreleasepool {
                            int (*prevCancel)(void) = capture_should_cancel;
                            capture_should_cancel = elanLockScreenShouldCancel;
                            cancelled = 0;
                            BOOL unlocked = NO;
                            if (open_sensor(&sensor) && sensor.pid == 0x0c1a && sensor.w == 144 && sensor.hgt == 64) {
                                NSData *bg = matcher.background ?: elanCachedSettingsBackground;
                                if (bg.length == (size_t)sensor.w * sensor.hgt * 2)
                                    memcpy(sensor.bg, bg.bytes, bg.length);
                                ElanpressFeatures *features = captureAfterRelease(&sensor, 1);
                                if (features && !cancelled && elanScreenLocked()) {
                                    unsigned score = 0;
                                    ElanFingerprintRecord *rec = [matcher bestRecordForFeatures:features score:&score];
                                    wipe(features->kp, features->n * sizeof(ElanpressKeypoint));
                                    elanpress_features_free(features);
                                    if (rec && score >= ELAN_VERIFY_MIN_PAIRS) {
                                        ELAN_SETTINGS_DIAGNOSTIC("lockwatcher-hit", (int)score);
                                        unlocked = elanPerformLockScreenUnlock();
                                    } else {
                                        ELAN_SETTINGS_DIAGNOSTIC("lockwatcher-miss", (int)score);
                                    }
                                } else if (features) {
                                    wipe(features->kp, features->n * sizeof(ElanpressKeypoint));
                                    elanpress_features_free(features);
                                }
                                close_sensor(&sensor);
                            }
                            capture_should_cancel = prevCancel;
                            @synchronized (settingsLock()) {
                                @synchronized (owner) {
                                    owner.busy = NO;
                                    sensorClaimedForEnrollment = NO;
                                }
                            }
                            if (unlocked) {
                                for (int i = 0; i < 20 && elanScreenLocked(); i++) usleep(150000);
                            }
                        }
                    });
                    dispatch_group_wait(owner.captureGroup, dispatch_time(DISPATCH_TIME_NOW, 40 * NSEC_PER_SEC));
                    usleep(250000);
                }
            }
        });
    });
}

static BOOL elanServiceFacadeABICompatible(void) {
    if (!ElanEnrollmentFacadeABICompatible()) return NO;
    const char *(*encoding)(Protocol *, SEL, BOOL, BOOL) = dlsym(RTLD_DEFAULT, "_protocol_getMethodTypeEncoding");
    Protocol *p = objc_getProtocol("BiometricKitXpcProtocol");
    if (!p || !encoding) return NO;
    const char *t1 = encoding(p, sel_registerName("setProtectedConfiguration:user:options:async:client:replyBlock:"), YES, YES);
    const char *t2 = encoding(p, sel_registerName("setSystemProtectedConfiguration:options:async:client:replyBlock:"), YES, YES);
    return t1 && !strcmp(t1, "v56@0:8@\"NSDictionary\"16I24@\"NSDictionary\"28c36Q40@?<v@?i>48") &&
           t2 && !strcmp(t2, "v52@0:8@\"NSDictionary\"16@\"NSDictionary\"24c32Q36@?<v@?i>44");
}

static NSXPCInterface *elanServiceExportedInterface(void) {
    if (!elanServiceFacadeABICompatible()) return nil;
    NSXPCInterface *i = ElanEnrollmentExportedInterface();
    if (!i) return nil;
    NSSet *dictClasses = [NSSet setWithObjects:NSDictionary.class, NSString.class, NSNumber.class, NSData.class, nil];
    SEL setUser = sel_registerName("setProtectedConfiguration:user:options:async:client:replyBlock:");
    SEL setSys = sel_registerName("setSystemProtectedConfiguration:options:async:client:replyBlock:");
    SEL getUUID = sel_registerName("getIdentitiesDatabaseUUIDForUser:client:replyBlock:");
    SEL detectPresence = sel_registerName("detectPresenceWithOptions:async:client:replyBlock:");
    [i setClasses:dictClasses forSelector:setUser argumentIndex:0 ofReply:NO];
    [i setClasses:dictClasses forSelector:setUser argumentIndex:2 ofReply:NO];
    [i setClasses:dictClasses forSelector:setSys argumentIndex:0 ofReply:NO];
    [i setClasses:dictClasses forSelector:setSys argumentIndex:1 ofReply:NO];
    [i setClasses:[NSSet setWithObject:NSUUID.class] forSelector:getUUID argumentIndex:0 ofReply:YES];
    [i setClasses:dictClasses forSelector:detectPresence argumentIndex:0 ofReply:NO];
    return i;
}

static NSArray<NSString *> *serviceReadSelectors(void) {
    return @[@"connect:client:replyBlock:", @"disconnect:replyBlock:", @"registerDelegate:client:replyBlock:",
             @"getDeviceHardwareState:replyBlock:", @"listAccessories:replyBlock:",
             @"getBiometryAvailabilityForUser:client:replyBlock:", @"getMaxIdentityCount:client:replyBlock:",
             @"getFreeIdentityCount:user:client:replyBlock:", @"identities:client:replyBlock:",
             @"getIdentitiesDatabaseHashForUser:client:replyBlock:", @"getIdentitiesDatabaseUUIDForUser:client:replyBlock:",
             @"getBioLockoutStateForUser:client:replyBlock:", @"getIdentityFromUUID:client:replyBlock:",
             @"detectPresenceWithOptions:async:client:replyBlock:", @"isFingerOn:replyBlock:",
             @"cancel:replyBlock:", @"logEventOrCode:",
             @"getProtectedConfigurationForUser:client:replyBlock:", @"getSystemProtectedConfiguration:replyBlock:",
             @"isAriadneSignpostsEnabled:replyBlock:"];
}

static NSArray<NSString *> *serviceSettingsSelectors(void) {
    return @[@"enroll:user:options:async:client:replyBlock:", @"enrollContinue:replyBlock:",
             @"completeEnrollment:replyBlock:", @"pullAlignmentData:replyBlock:",
             @"updateIdentity:options:async:client:replyBlock:", @"removeIdentity:options:async:client:replyBlock:",
             @"removeAllIdentitiesForUser:options:async:client:replyBlock:",
             @"setProtectedConfiguration:user:options:async:client:replyBlock:",
             @"setSystemProtectedConfiguration:options:async:client:replyBlock:",
             @"match:options:async:client:replyBlock:"];
}

@interface ELANServiceProtocolFacade : NSObject
@property(nonatomic, strong) ELANSettingsEnrollmentConnection *target;
@property(nonatomic, weak) NSXPCConnection *peer;
@end

@implementation ELANServiceProtocolFacade
- (void)isAriadneSignpostsEnabled:(uint64_t)client replyBlock:(void (^)(BOOL))reply {
    (void)client;
    reply(NO);
}
- (NSMethodSignature *)protocolSignature:(SEL)selector {
    Protocol *p = objc_getProtocol("BiometricKitXpcProtocol");
    struct objc_method_description d = protocol_getMethodDescription(p, selector, YES, YES);
    if (!d.types) d = protocol_getMethodDescription(p, selector, NO, YES);
    return d.types ? [NSMethodSignature signatureWithObjCTypes:d.types] : nil;
}
- (BOOL)respondsToSelector:(SEL)selector {
    return [self protocolSignature:selector] != nil || [super respondsToSelector:selector];
}
- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector {
    return [self protocolSignature:selector] ?: [super methodSignatureForSelector:selector];
}
- (void)reject:(SEL)selector {
    ELAN_SETTINGS_DIAGNOSTIC("facade-reject", 0);
    fprintf(stderr, "ELAN_SERVICE_FACADE rejected_selector=%s\n", sel_getName(selector));
    [self.peer invalidate];
}
- (BOOL)allows:(SEL)selector {
    NSString *name = NSStringFromSelector(selector);
    if ([serviceReadSelectors() containsObject:name]) return [self.target respondsToSelector:selector];
    if (self.target.isSettingsPeer && [serviceSettingsSelectors() containsObject:name]) {
        return ELANSettingsPeerCurrent(self.peer, self.target.settingsPeerToken) &&
               [self.target respondsToSelector:selector];
    }
    if (self.target.isCoreAuthPeer && [name isEqual:@"match:options:async:client:replyBlock:"]) {
        return ELANCoreAuthPeerCurrent(self.peer, self.target.settingsPeerToken) &&
               [self.target respondsToSelector:selector];
    }
    return NO;
}
- (void)forwardInvocation:(NSInvocation *)invocation {
    if (![self allows:invocation.selector]) { [self reject:invocation.selector]; return; }
    if (invocation.selector == sel_registerName("match:options:async:client:replyBlock:")) {
        __unsafe_unretained id options = nil;
        [invocation getArgument:&options atIndex:3];
        if (![options isKindOfClass:NSDictionary.class]) {
            [self reject:invocation.selector];
            return;
        }
        if (self.target.isSettingsPeer) {
            if ([options[@"BKOptionMatchForUnlock"] boolValue] ||
                ![options[@"BKOptionMatchForExtendEnrollment"] isEqual:@YES] ||
                options[@"BKOptionMatchForCredentialSet"]) {
                [self reject:invocation.selector];
                return;
            }
        } else if (self.target.isCoreAuthPeer) {
            id cred = options[@"BKOptionMatchForCredentialSet"] ?: options[@"BKOptionAuthWithCredentialSet"];
            if ([options[@"BKOptionMatchForExtendEnrollment"] boolValue] ||
                ![cred isKindOfClass:NSData.class] || [cred length] != 16) {
                [self reject:invocation.selector];
                return;
            }
        } else {
            [self reject:invocation.selector];
            return;
        }
    }
    @try {
        [invocation invokeWithTarget:self.target];
    } @catch (NSException *exception) {
        fprintf(stderr, "ELAN_SERVICE_FACADE target_exception=%s selector=%s\n",
                exception.name.UTF8String, sel_getName(invocation.selector));
        [self reject:invocation.selector];
    }
}
- (void)doesNotRecognizeSelector:(SEL)selector { [self reject:selector]; }
@end

@implementation ELANSettingsEnrollmentConnection
- (void)listAccessories:(uint64_t)client replyBlock:(void (^)(int, NSArray *))reply {
    if (!self.sensorPresent()) { reply(0, @[]); return; }
    [super listAccessories:client replyBlock:reply];
}
- (void)getBiometryAvailabilityForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(int, NSInteger))reply {
    (void)client;
    reply(0, user == 501 && !self.controller.stopping && self.sensorPresent() ? 1 : 0);
}
- (void)getIdentitiesDatabaseUUIDForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSUUID *))reply {
    (void)client;
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        NSData *state = (user == 501 && !controller.stopping) ? controller.repository.current.databaseState : nil;
        if (state.length >= 16) {
            uuid_t bytes;
            memcpy(bytes, state.bytes, 16);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            reply([[NSUUID alloc] initWithUUIDBytes:bytes]);
        } else {
            reply(nil);
        }
    }
}
- (void)detectPresenceWithOptions:(NSDictionary *)options async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    (void)options;
    (void)async;
    (void)client;
    reply(self.controller.stopping || !self.sensorPresent() ? 1 : 0);
}
- (void)isFingerOn:(uint64_t)client replyBlock:(void (^)(BOOL))reply {
    (void)client;
    reply(self.matchPresence == 1);
}
- (void)getProtectedConfigurationForUser:(unsigned int)user client:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    (void)client;
    if (self.isSettingsPeer) elanTrySyncCapturedPassphrase();
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanFingerprintCatalog *catalog = (user == 501 && !controller.stopping && (nativePeerPermissions(self.connection) & NativePeerRead))
            ? controller.repository.current : nil;
        if (!catalog) {
            reply(nil);
            return;
        }
        NSDictionary *cfg = elanLoadProtectedConfig();
        BOOL hasRecords = catalog.records.count != 0;
        BOOL unlock = [cfg[@"BKUserCfgTouchIDUnlockEnabled"] boolValue];
        BOOL ident = [cfg[@"BKUserCfgTouchIDIdentificationEnabled"] boolValue];
        BOOL login = [cfg[@"BKUserCfgTouchIDLoginEnabled"] boolValue];
        BOOL applePay = [cfg[@"BKUserCfgTouchIDApplePayEnabled"] boolValue];
        reply(@{
            @"BKUserCfgTouchIDUnlockEnabled": @(unlock),
            @"BKUserCfgEffectiveTouchIDUnlockEnabled": @(unlock && hasRecords),
            @"BKUserCfgTouchIDIdentificationEnabled": @(ident),
            @"BKUserCfgEffectiveTouchIDIdentificationEnabled": @(ident && hasRecords),
            @"BKUserCfgTouchIDLoginEnabled": @(login),
            @"BKUserCfgEffectiveTouchIDLoginEnabled": @(login && hasRecords),
            @"BKUserCfgTouchIDApplePayEnabled": @(applePay),
            @"BKUserCfgEffectiveTouchIDApplePayEnabled": @(applePay && hasRecords),
            @"BKUserCfgAttentionDetectionEnabled": @NO,
            @"BKUserCfgEffectiveAttentionDetectionEnabled": @NO,
            @"BKUserCfgPeriocularMatchEnabled": @NO,
            @"BKUserCfgEffectivePeriocularMatchEnabled": @NO
        });
    }
}
- (void)getSystemProtectedConfiguration:(uint64_t)client replyBlock:(void (^)(NSDictionary *))reply {
    (void)client;
    if (self.controller.stopping || !(nativePeerPermissions(self.connection) & NativePeerRead)) {
        reply(nil);
        return;
    }
    reply(@{
        @"BKSysCfgTouchIDEnabled": @YES,
        @"BKSysCfgTouchIDIdentificationEnabled": @YES,
        @"BKSysCfgTouchIDUnlockEnabled": @YES,
        @"BKSysCfgTouchIDLoginEnabled": @YES,
        @"BKSysCfgTouchIDApplePayEnabled": @YES,
        @"BKSysCfgPeriocularMatchEnabled": @NO
    });
}
- (BOOL)authorizeEnrollment:(ElanNativeEnrollmentRun *)run {
    BOOL ok = self.isSettingsPeer && ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken) &&
        self.sensorPresent() && [super authorizeEnrollment:run];
    if (ok) elanTrySyncCapturedPassphrase();
    return ok;
}
- (void)updateIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async
                client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (!self.isSettingsPeer || !ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken)) {
        reply(kIOReturnNotPrivileged);
        return;
    }
    [super updateIdentity:identity options:options async:async client:client replyBlock:reply];
}
- (void)removeIdentity:(id)identity options:(NSDictionary *)options async:(BOOL)async
                client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (!self.isSettingsPeer || !ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken)) {
        reply(kIOReturnNotPrivileged);
        return;
    }
    [super removeIdentity:identity options:options async:async client:client replyBlock:reply];
}
- (void)removeAllIdentitiesForUser:(unsigned int)user options:(NSDictionary *)options async:(BOOL)async
                            client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (!self.isSettingsPeer || !ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken)) {
        reply(kIOReturnNotPrivileged);
        return;
    }
    [super removeAllIdentitiesForUser:user options:options async:async client:client replyBlock:reply];
}
- (void)setProtectedConfiguration:(NSDictionary *)configuration user:(unsigned int)user options:(NSDictionary *)options
                            async:(BOOL)async client:(uint64_t)client replyBlock:(void (^)(int))reply {
    (void)async;
    if (!self.isSettingsPeer || !ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken) ||
        user != 501 || !(nativePeerPermissions(self.connection) & NativePeerConfigure)) {
        reply(EACCES);
        return;
    }
    if (![configuration isKindOfClass:NSDictionary.class]) {
        reply(EINVAL);
        return;
    }
    NSArray<NSString *> *supportedKeys = @[
        @"BKUserCfgTouchIDUnlockEnabled",
        @"BKUserCfgTouchIDIdentificationEnabled",
        @"BKUserCfgTouchIDLoginEnabled",
        @"BKUserCfgTouchIDApplePayEnabled",
        @"BKUserCfgAttentionDetectionEnabled",
        @"BKUserCfgPeriocularMatchEnabled"
    ];
    BOOL anyEnabled = NO;
    for (id key in configuration) {
        id val = configuration[key];
        if (![key isKindOfClass:NSString.class] || ![supportedKeys containsObject:key] ||
            ![val isKindOfClass:NSNumber.class] || (![val isEqual:@YES] && ![val isEqual:@NO])) {
            reply(EINVAL);
            return;
        }
        if ([val boolValue]) anyEnabled = YES;
    }
    NSData *context = [options isKindOfClass:NSDictionary.class] ? options[@"BKOptionAuthWithCredentialSet"] : nil;
    if (anyEnabled || context != nil) {
        if (![context isKindOfClass:NSData.class] || context.length != 16 ||
            elanCheckDirectEnrollment((const uint8_t *)context.bytes) != 0) {
            reply(EACCES);
            return;
        }
        elanTrySyncCapturedPassphrase();
    }
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        if (controller.stopping || !controller.session || controller.session.invalidated || ![controller sessionIsCurrent]) {
            reply(EIO);
            return;
        }
        NSMutableDictionary *updated = [elanLoadProtectedConfig() mutableCopy];
        if (configuration[@"BKUserCfgTouchIDUnlockEnabled"]) {
            updated[@"BKUserCfgTouchIDUnlockEnabled"] = @([configuration[@"BKUserCfgTouchIDUnlockEnabled"] boolValue]);
        }
        if (configuration[@"BKUserCfgTouchIDLoginEnabled"] && !configuration[@"BKUserCfgTouchIDUnlockEnabled"]) {
            updated[@"BKUserCfgTouchIDLoginEnabled"] = @([configuration[@"BKUserCfgTouchIDLoginEnabled"] boolValue]);
        }
        if (configuration[@"BKUserCfgTouchIDApplePayEnabled"]) {
            updated[@"BKUserCfgTouchIDApplePayEnabled"] = @([configuration[@"BKUserCfgTouchIDApplePayEnabled"] boolValue]);
        }
        if (configuration[@"BKUserCfgTouchIDIdentificationEnabled"] &&
            !configuration[@"BKUserCfgTouchIDUnlockEnabled"] &&
            !configuration[@"BKUserCfgTouchIDLoginEnabled"]) {
            updated[@"BKUserCfgTouchIDIdentificationEnabled"] = @([configuration[@"BKUserCfgTouchIDIdentificationEnabled"] boolValue]);
        } else {
            updated[@"BKUserCfgTouchIDIdentificationEnabled"] = @YES;
        }
        elanSaveProtectedConfig(updated);
        ElanFingerprintCatalog *catalog = controller.repository.current;
        if (catalog && !catalog.identificationEnabled) {
            NSError *error = nil;
            ElanFingerprintCatalog *next = [catalog withIdentificationEnabled:YES];
            if (next) [controller.session commit:next replacing:catalog error:&error];
        }
        notify_post("com.apple.BiometricKit.enrollmentChanged");
        [[self.connection remoteObjectProxyWithErrorHandler:^(NSError *e) { (void)e; }] statusMessage:64 client:client];
        reply(0);
    }
}
- (void)drainCaptureQueuePreemptingMatch:(BOOL)preemptMatch {
    ElanProviderController *owner = self.controller;
    if (!owner) return;
    BOOL shouldWait = NO;
    @synchronized (owner) {
        if (!owner.stopping) {
            if (owner.busy && preemptMatch && !owner.current.enrollment) {
                cancelled = 1;
                [owner.current cancelCurrent];
                shouldWait = YES;
            } else if (!owner.busy || cancelled) {
                shouldWait = YES;
            }
        }
    }
    if (shouldWait && owner.captureGroup)
        dispatch_group_wait(owner.captureGroup, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));
}
- (void)cancel:(uint64_t)client replyBlock:(void (^)(int))reply {
    [self cancelClient:client];
    [self drainCaptureQueuePreemptingMatch:NO];
    reply(0);
}
- (void)disconnect:(uint64_t)client replyBlock:(void (^)(int))reply {
    [self cancelClient:client];
    [self drainCaptureQueuePreemptingMatch:NO];
    reply(0);
}
- (void)reportMatchCaptureEvent:(ElanCaptureEvent)event {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        if (!controller || controller.stopping || !controller.busy || controller.current != self || cancelled) return;
        NSInteger desired = self.matchPresence;
        if (event == ElanCaptureTouchDetected || event == ElanCaptureSampleReady || event == ElanCaptureAwaitRelease)
            desired = 1;
        else if (event == ElanCaptureReady)
            desired = 0;
        if (desired != self.matchPresence && (desired == 0 || desired == 1)) {
            self.matchPresence = desired;
            id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                (void)error;
            }];
            [remote statusMessage:desired ? 63 : 64 client:controller.activeClient];
        }
    }
}
- (void)enroll:(int)type user:(unsigned)user options:(NSDictionary *)options async:(BOOL)async
         client:(uint64_t)client replyBlock:(void (^)(int))reply {
    NSData *context = nativeInitialEnrollmentContext(type, user, getuid(), options);
    ElanProviderController *owner = self.controller;
    if (!context) {
        ELAN_SETTINGS_DIAGNOSTIC("request-shape", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    if (!owner) {
        ELAN_SETTINGS_DIAGNOSTIC("request-owner", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    if (!self.isSettingsPeer || !ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken) ||
        !(nativePeerPermissions(self.connection) & NativePeerEnroll)) {
        ELAN_SETTINGS_DIAGNOSTIC("request-peer", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    [self drainCaptureQueuePreemptingMatch:YES];
    @synchronized (settingsLock()) {
        BOOL ready = NO;
        @synchronized (owner) {
            ready = settingsOwner == owner && !owner.stopping && !owner.busy && [owner sessionIsCurrent];
        }
        if (!ready || sensorClaimedForEnrollment || !self.sensorPresent()) {
            ELAN_SETTINGS_DIAGNOSTIC("request-readiness", kIOReturnNotReady);
            reply(kIOReturnNotReady);
            return;
        }
        int policyStatus = elanCheckDirectEnrollment(context.bytes);
        if (policyStatus) {
            ELAN_SETTINGS_DIAGNOSTIC("request-policy", policyStatus);
            reply(kIOReturnNotPrivileged); return;
        }
        elanTrySyncCapturedPassphrase();
        sensorClaimedForEnrollment = YES;
        BOOL queued = NO;
        ElanPowerObserver *power = [ElanPowerObserver new];
        @try {
            if (![power openDeferringSleep:NO stop:^{
                @synchronized (owner) { cancelled = 1; [owner.current cancelCurrent]; }
            }] || ![[power snapshot][@"ready"] boolValue]) {
                ELAN_SETTINGS_DIAGNOSTIC("power-ready", kIOReturnNotReady);
                reply(kIOReturnNotReady); return;
            }
            cancelled = 0;
            if (!open_sensor(&sensor) || sensor.pid != 0x0c1a || sensor.w != 144 || sensor.hgt != 64) {
                ELAN_SETTINGS_DIAGNOSTIC("sensor-open", kIOReturnNoDevice);
                reply(kIOReturnNoDevice);
                return;
            }
            @synchronized (owner) {
                NSError *error = nil;
                if (!owner.repository.current && ![owner.repository load:&error] &&
                    ![owner.repository createEmpty:&error]) {
                    ELAN_SETTINGS_DIAGNOSTIC("catalog-load", kIOReturnNotReadable);
                    reply(kIOReturnNotReadable);
                    return;
                }
                if (!owner.session || owner.session.invalidated) {
                    owner.session = [[ElanFingerprintSession alloc] initWithRepository:owner.repository
                        publisher:^int(ElanFingerprintCatalog *catalog) {
                            if (catalog.user != getuid()) return kIOReturnNotReady;
                            NSData *bytes = nativeCatalogIdentityBytes(catalog);
                            int syncStatus = elanSyncDirectCatalog((const uint8_t *)bytes.bytes, (uint32_t)catalog.records.count);
                            if (syncStatus) ELAN_SETTINGS_DIAGNOSTIC("catalog-sync-warn", syncStatus);
                            notify_post("com.apple.BiometricKit.enrollmentChanged");
                            return 0;
                        } error:&error];
                }
                if (!owner.session) {
                    ELAN_SETTINGS_DIAGNOSTIC("session-create", kIOReturnNotReady);
                    reply(kIOReturnNotReady); return;
                }
                capture_observer = observeCapture;
                NSData *background = owner.matcher.background ?: elanCachedSettingsBackground;
                if (background.length == (size_t)sensor.w * sensor.hgt * 2)
                    memcpy(sensor.bg, background.bytes, background.length);
                ELAN_SETTINGS_DIAGNOSTIC("backend-enroll", 0);
                [super enroll:type user:user options:options async:async client:client replyBlock:reply];
            }
            dispatch_group_async(owner.captureGroup, owner.captureQueue, ^{
                @synchronized (settingsLock()) {
                    if (owner.matcher.background) elanCachedSettingsBackground = [owner.matcher.background copy];
                    [power close];
                    close_sensor(&sensor);
                    sensorClaimedForEnrollment = NO;
                }
            });
            queued = YES;
        } @finally {
            if (!queued) { [power close]; close_sensor(&sensor); sensorClaimedForEnrollment = NO; }
        }
    }
}
- (void)performCoreAuthMatch:(id)query options:(NSDictionary *)options client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *owner = self.controller;
    id rawContext = [options isKindOfClass:NSDictionary.class] ?
        (options[@"BKOptionMatchForCredentialSet"] ?: options[@"BKOptionAuthWithCredentialSet"]) : nil;
    BOOL contextValid = [rawContext isKindOfClass:NSData.class] && [rawContext length] == 16;
    BOOL unlock = [options[@"BKOptionMatchForUnlock"] boolValue];
    id userFilter = [query isKindOfClass:NSDictionary.class] ? query[@"BKFilterUserID"] : nil;
    BOOL userValid = !userFilter || ([userFilter isKindOfClass:NSNumber.class] && [userFilter isEqual:@501]);
    if (!owner || !contextValid || !userValid || !self.isCoreAuthPeer ||
        !ELANCoreAuthPeerCurrent(self.connection, self.settingsPeerToken)) {
        ELAN_SETTINGS_DIAGNOSTIC("match-peer-reject", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged);
        return;
    }
    NSData *context = [rawContext copy];
    [self drainCaptureQueuePreemptingMatch:YES];
    @synchronized (settingsLock()) {
        ElanFingerprintMatcher *matcher = nil;
        BOOL ready = NO;
        @synchronized (owner) {
            matcher = owner.matcher;
            ready = settingsOwner == owner && !owner.stopping && !owner.busy &&
                nativeIdentificationEnabled(matcher) && [owner sessionIsCurrent];
        }
        if (!ready || sensorClaimedForEnrollment || !self.sensorPresent()) {
            ELAN_SETTINGS_DIAGNOSTIC("match-not-ready", kIOReturnNotReady);
            reply(kIOReturnNotReady);
            return;
        }
        ELANSyncPublishedCatalog();
        sensorClaimedForEnrollment = YES;
        BOOL queued = NO;
        ElanPowerObserver *power = [ElanPowerObserver new];
        @try {
            if (![power openDeferringSleep:NO stop:^{
                @synchronized (owner) { cancelled = 1; [owner.current cancelCurrent]; }
            }] || ![[power snapshot][@"ready"] boolValue]) {
                ELAN_SETTINGS_DIAGNOSTIC("match-power", kIOReturnNotReady);
                reply(kIOReturnNotReady);
                return;
            }
            cancelled = 0;
            if (!open_sensor(&sensor) || sensor.pid != 0x0c1a || sensor.w != 144 || sensor.hgt != 64) {
                ELAN_SETTINGS_DIAGNOSTIC("match-sensor", kIOReturnNoDevice);
                reply(kIOReturnNoDevice);
                return;
            }
            @synchronized (owner) {
                NSData *background = matcher.background ?: elanCachedSettingsBackground;
                if (background.length == (size_t)sensor.w * sensor.hgt * 2)
                    memcpy(sensor.bg, background.bytes, background.length);
                owner.busy = YES;
                owner.current = self;
                owner.activeClient = client;
                self.matchPresence = -1;
            }
            ELAN_SETTINGS_DIAGNOSTIC("match-started", 0);
            reply(0);
            dispatch_group_async(owner.captureGroup, owner.captureQueue, ^{
                @autoreleasepool {
                    void (*previousEvent)(ElanCaptureEvent) = capture_event;
                    int (*previousCancel)(void) = capture_should_cancel;
                    @synchronized (owner) {
                        enrollmentCaptureOwner = self;
                        capture_event = matchCaptureEvent;
                        capture_should_cancel = enrollmentShouldCancel;
                    }
                    @try {
                        const double captureDeadline = capture_milliseconds() + capture_timeout_seconds * 1000.0;
                        for (unsigned attempt = 0; attempt < 5 && !cancelled && !owner.stopping; attempt++) {
                            if (capture_milliseconds() >= captureDeadline) {
                                id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *e) { (void)e; }];
                                [remote statusMessage:68 client:client];
                                break;
                            }
                            ElanpressFeatures *features = captureAfterRelease(&sensor, attempt == 0 ? 1 : 0);
                            if (!features) {
                                if (cancelled || owner.stopping || capture_last_result == ElanCaptureCancelled) break;
                                if (capture_last_result == ElanCaptureImageRejected && attempt + 1 < 5) {
                                    id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *e) { (void)e; }];
                                    [remote statusMessage:78 client:client];
                                    continue;
                                }
                                id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *e) { (void)e; }];
                                [remote statusMessage:(capture_last_result == ElanCaptureTimedOut ? 68 : 66) client:client];
                                break;
                            }
                            unsigned score = 0;
                            ElanFingerprintRecord *record = [matcher bestRecordForFeatures:features score:&score];
                            wipe(features->kp, features->n * sizeof(ElanpressKeypoint));
                            elanpress_features_free(features);
                            BOOL matched = record != nil && score >= ELAN_VERIFY_MIN_PAIRS;
                            BOOL shouldStop = NO;
                            @synchronized (owner) {
                                if (cancelled || owner.stopping || owner.current != self || ![owner sessionIsCurrent] || !record) {
                                    shouldStop = YES;
                                } else {
                                    uuid_t identityBytes;
                                    [record.uuid getUUIDBytes:identityBytes];
                                    uint64_t sequence = ++owner.sequence;
                                    int kstatus = elanSubmitDirectMatch(sequence, identityBytes,
                                        (const uint8_t *)context.bytes, matched ? 1U : 0U);
                                    ELAN_SETTINGS_DIAGNOSTIC(matched ? "match-hit" : "match-miss", (int)score);
                                    id remote = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                                        (void)error;
                                    }];
                                    if (kstatus) {
                                        ELAN_SETTINGS_DIAGNOSTIC("match-kernel-error", kstatus);
                                        [remote statusMessage:66 client:client];
                                        shouldStop = YES;
                                    } else {
                                        if (self.matchPresence == 1) {
                                            self.matchPresence = 0;
                                            [remote statusMessage:64 client:client];
                                        }
                                        NSMutableDictionary *details = [NSMutableDictionary dictionaryWithDictionary:nativeProviderMatchDetails(matched)];
                                        if (matched && (unlock || elanScreenLocked())) details[@"BKMatchDetailUnlocked"] = @YES;
                                        [remote matchResult:matched ? nativeIdentityForRecord(record, 501) : nil
                                                    details:details client:client];
                                        if (matched) {
                                            shouldStop = YES;
                                            if (elanScreenLocked() && elanUnlockEnabledForUser()) {
                                                dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                                                    @autoreleasepool { elanPerformLockScreenUnlock(); }
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                            if (shouldStop) break;
                        }
                    } @finally {
                        @synchronized (owner) {
                            enrollmentCaptureOwner = nil;
                            capture_event = previousEvent;
                            capture_should_cancel = previousCancel;
                            owner.current = nil;
                            owner.activeClient = 0;
                            owner.busy = NO;
                        }
                        @synchronized (settingsLock()) {
                            [power close];
                            close_sensor(&sensor);
                            sensorClaimedForEnrollment = NO;
                        }
                    }
                }
            });
            queued = YES;
        } @finally {
            if (!queued) {
                @synchronized (owner) {
                    if (owner.current == self) {
                        owner.current = nil;
                        owner.activeClient = 0;
                        owner.busy = NO;
                    }
                }
                [power close];
                close_sensor(&sensor);
                sensorClaimedForEnrollment = NO;
            }
        }
    }
}
- (void)match:(id)query options:(NSDictionary *)options async:(BOOL)async
       client:(uint64_t)client replyBlock:(void (^)(int))reply {
    if (self.isCoreAuthPeer && [options isKindOfClass:NSDictionary.class] &&
        (options[@"BKOptionMatchForCredentialSet"] || options[@"BKOptionAuthWithCredentialSet"]) &&
        ![options[@"BKOptionMatchForExtendEnrollment"] boolValue]) {
        [self performCoreAuthMatch:query options:options client:client replyBlock:reply];
        return;
    }
    if (!self.isSettingsPeer || ![options isKindOfClass:NSDictionary.class] ||
        ![options[@"BKOptionMatchForExtendEnrollment"] isEqual:@YES]) {
        ELAN_SETTINGS_DIAGNOSTIC("extend-shape", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    NSUUID *uuid = nativeExtendedEnrollmentUUID(query, options);
    NSData *context = options[@"BKOptionAuthWithCredentialSet"];
    ElanProviderController *owner = self.controller;
    if (!uuid || ![context isKindOfClass:NSData.class] || context.length != 16 || !owner) {
        ELAN_SETTINGS_DIAGNOSTIC("extend-request", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    if (!ELANSettingsPeerCurrent(self.connection, self.settingsPeerToken) ||
        !(nativePeerPermissions(self.connection) & NativePeerEnroll)) {
        ELAN_SETTINGS_DIAGNOSTIC("extend-peer", kIOReturnNotPrivileged);
        reply(kIOReturnNotPrivileged); return;
    }
    [self drainCaptureQueuePreemptingMatch:YES];
    @synchronized (settingsLock()) {
        BOOL ready = NO;
        @synchronized (owner) {
            ready = settingsOwner == owner && !owner.stopping && !owner.busy &&
                owner.session && !owner.session.invalidated && [owner sessionIsCurrent];
        }
        if (!ready || sensorClaimedForEnrollment || !self.sensorPresent()) {
            ELAN_SETTINGS_DIAGNOSTIC("extend-readiness", kIOReturnNotReady);
            reply(kIOReturnNotReady); return;
        }
        int policyStatus = elanCheckDirectEnrollment(context.bytes);
        if (policyStatus) {
            ELAN_SETTINGS_DIAGNOSTIC("extend-policy", policyStatus);
            reply(kIOReturnNotPrivileged); return;
        }
        elanTrySyncCapturedPassphrase();
        sensorClaimedForEnrollment = YES;
        BOOL queued = NO;
        ElanPowerObserver *power = [ElanPowerObserver new];
        @try {
            if (![power openDeferringSleep:NO stop:^{
                @synchronized (owner) { cancelled = 1; [owner.current cancelCurrent]; }
            }] || ![[power snapshot][@"ready"] boolValue]) {
                ELAN_SETTINGS_DIAGNOSTIC("extend-power", kIOReturnNotReady);
                reply(kIOReturnNotReady); return;
            }
            cancelled = 0;
            if (!open_sensor(&sensor) || sensor.pid != 0x0c1a || sensor.w != 144 || sensor.hgt != 64) {
                ELAN_SETTINGS_DIAGNOSTIC("extend-sensor", kIOReturnNoDevice);
                reply(kIOReturnNoDevice); return;
            }
            @synchronized (owner) {
                capture_observer = observeCapture;
                ElanFingerprintRecord *record = [owner.repository.current recordForUUID:uuid];
                NSDictionary *decoded = record ? ElanDecodeTemplate(record.templateData, 0x0c1a, 144, 64) : nil;
                NSData *background = decoded[@"background"] ?: owner.matcher.background ?: elanCachedSettingsBackground;
                if (background.length == (size_t)sensor.w * sensor.hgt * 2)
                    memcpy(sensor.bg, background.bytes, background.length);
                ELAN_SETTINGS_DIAGNOSTIC("backend-extend", 0);
                [super extendEnrollment:query options:options client:client replyBlock:reply];
            }
            dispatch_group_async(owner.captureGroup, owner.captureQueue, ^{
                @synchronized (settingsLock()) {
                    [power close];
                    close_sensor(&sensor);
                    sensorClaimedForEnrollment = NO;
                }
            });
            queued = YES;
        } @finally {
            if (!queued) { [power close]; close_sensor(&sensor); sensorClaimedForEnrollment = NO; }
        }
    }
}
@end

BOOL ELANAcceptSettingsEnrollment(NSXPCConnection *peer, id accessory, BOOL (^present)(void)) {
    unsigned permissions = nativePeerPermissions(peer);
    if (!(permissions & (NativePeerEnroll | NativePeerMatch)) || !accessory || !present) return NO;
    audit_token_t initialToken = peer.auditToken;
    NSData *expectedToken = [NSData dataWithBytes:&initialToken length:sizeof(initialToken)];
    BOOL isSettings = (permissions & NativePeerEnroll) != 0;
    BOOL isCoreAuth = !isSettings && (permissions & NativePeerMatch) != 0;
    if (isSettings) {
        if (!present() || !ELANSettingsPeerCurrent(peer, expectedToken)) return NO;
        io_connect_t channel = IO_OBJECT_NULL;
        if (elanOpenDirectEnrollment(&channel)) return NO;
        IOServiceClose(channel);
        elanTrySyncCapturedPassphrase();
    } else if (isCoreAuth) {
        if (!ELANCoreAuthPeerCurrent(peer, expectedToken)) return NO;
    } else {
        return NO;
    }
    @synchronized (settingsLock()) {
        ElanProviderController *owner = ELANEnsureServiceController(accessory);
        if (!owner) return NO;
        ELANSettingsEnrollmentConnection *server = [ELANSettingsEnrollmentConnection new];
        server.controller = owner;
        server.connection = peer;
        server.settingsPeerToken = expectedToken;
        server.sensorPresent = present;
        server.isSettingsPeer = isSettings;
        server.isCoreAuthPeer = isCoreAuth;
        server.matchPresence = -1;
        peer.exportedInterface = elanServiceExportedInterface();
        peer.remoteObjectInterface = ElanEnrollmentCallbackInterface();
        if (!peer.exportedInterface || !peer.remoteObjectInterface) return NO;
        ELANServiceProtocolFacade *facade = [ELANServiceProtocolFacade new];
        facade.target = server;
        facade.peer = peer;
        peer.exportedObject = facade;
        __weak ELANSettingsEnrollmentConnection *weakServer = server;
        peer.interruptionHandler = ^{
            ELANSettingsEnrollmentConnection *current = weakServer;
            [current cancelCurrent];
            current.settingsPeerToken = nil;
            [current.connection invalidate];
        };
        peer.invalidationHandler = ^{
            [weakServer cancelCurrent];
            weakServer.settingsPeerToken = nil;
            weakServer.connection = nil;
        };
        [peer resume];
        return YES;
    }
}
