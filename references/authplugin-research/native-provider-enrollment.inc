#ifndef ELAN_NATIVE_AUTHORIZATION_CALL
#define ELAN_NATIVE_AUTHORIZATION_CALL(fd, sequence, context) elanProviderAuthorizeEnrollment(fd, sequence, context)
#endif
#ifndef ELAN_NATIVE_AUTHORIZATION_CONTINUE
#define ELAN_NATIVE_AUTHORIZATION_CONTINUE(status) ((status) == 0)
#endif
#ifndef ELAN_NATIVE_COMMIT_RECEIPT
#define ELAN_NATIVE_COMMIT_RECEIPT(record, samples, supplement) ((void)0)
#endif
#ifndef ELAN_NATIVE_CAPTURE_SAMPLE
#define ELAN_NATIVE_CAPTURE_SAMPLE(s, alreadyClear) ((void)(alreadyClear), capture(s))
#endif
#ifndef ELAN_NATIVE_ENROLL_LOG
#define ELAN_NATIVE_ENROLL_LOG(...) ((void)0)
#endif
#ifndef ELAN_NATIVE_CALIBRATED_BACKGROUND
#define ELAN_NATIVE_CALIBRATED_BACKGROUND(bg) ((void)0)
#endif
- (BOOL)isCurrentEnrollment:(ElanNativeEnrollmentRun *)run {
    ElanProviderController *controller = self.controller;
    return run && self.enrollment == run && controller.current == self && controller.activeClient == run.client &&
        controller.busy && !controller.stopping && !cancelled;
}
- (id)enrollmentRemote {
    __weak ElanProviderConnection *weakSelf = self;
    ElanNativeEnrollmentRun *run = self.enrollment;
    return [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        printf("ELAN_PROVIDER enrollment_callback_error=%ld\n", (long)error.code);
        ElanProviderConnection *owner = weakSelf;
        @synchronized (owner.controller) { if (owner.enrollment == run) [owner cancelClient:run.client]; }
    }];
}
- (void)reportEnrollmentTouch:(BOOL)present {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanNativeEnrollmentRun *run = self.enrollment;
        if (![self isCurrentEnrollment:run] || run.presence == present) return;
        run.presence = present;
        [[self enrollmentRemote] statusMessage:present ? 63 : 64 client:run.client];
    }
}
- (void)reportEnrollmentCaptureEvent:(ElanCaptureEvent)event {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanNativeEnrollmentRun *run = self.enrollment;
        if (![self isCurrentEnrollment:run]) return;
        if (event == ElanCaptureAwaitRelease && (run.calibrating || run.presence == 1)) {
            if (run.presence != 1) {
                run.presence = 1;
                [[self enrollmentRemote] statusMessage:63 client:run.client];
            }
            [[self enrollmentRemote] statusMessage:74 client:run.client];
        } else if (event == ElanCaptureReady) {
            [self reportEnrollmentTouch:NO];
        } else if (event == ElanCaptureTouchDetected) {
            [self reportEnrollmentTouch:YES];
        } else if (event == ElanCaptureSampleReady) {
            if (run.presence != 1) {
                run.presence = 1;
                [[self enrollmentRemote] statusMessage:63 client:run.client];
            }
            [[self enrollmentRemote] statusMessage:74 client:run.client];
        } else if (event == ElanCaptureTooShort) {
            [[self enrollmentRemote] statusMessage:78 client:run.client];
        } else if (event == ElanCaptureLowQuality) {
            [[self enrollmentRemote] statusMessage:98 client:run.client];
        }
    }
}
- (BOOL)authorizeEnrollment:(ElanNativeEnrollmentRun *)run {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        if (![self isCurrentEnrollment:run] || !(nativePeerPermissions(self.connection) & NativePeerEnroll) || ![controller sessionIsCurrent]) return NO;
        int status = ELAN_NATIVE_AUTHORIZATION_CALL(controller.broker, ++controller.sequence, run.context.bytes);
        printf("ELAN_PROVIDER enrollment_authorization status=%d\n", status);
        return ELAN_NATIVE_AUTHORIZATION_CONTINUE(status);
    }
}
- (BOOL)waitForEnrollmentContinuation:(ElanNativeEnrollmentRun *)run {
    ElanProviderController *controller = self.controller;
    dispatch_semaphore_t signal = dispatch_semaphore_create(0);
    @synchronized (controller) {
        if (![self isCurrentEnrollment:run]) return NO;
        run.continuation = signal; run.waiting = YES;
        [[self enrollmentRemote] statusMessage:nativeEnrollmentProgress((unsigned)run.draft.sampleCount, (unsigned)run.draft.targetCount)
                                       client:run.client];
    }
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
    while (deadline.timeIntervalSinceNow > 0) {
        BOOL signalled = !dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC));
        @synchronized (controller) {
            if (![self isCurrentEnrollment:run]) return NO;
            if (signalled) return !run.waiting;
        }
    }
    return NO;
}
- (void)enrollContinue:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanNativeEnrollmentRun *run = self.enrollment;
        if (![self isCurrentEnrollment:run] || run.client != client || !run.waiting) { reply(1); return; }
        run.waiting = NO; dispatch_semaphore_signal(run.continuation); reply(0);
    }
}
- (void)completeEnrollment:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        ElanNativeEnrollmentRun *run = self.enrollment;
        if (![self isCurrentEnrollment:run] || run.client != client || !run.draft.ready) { reply(1); return; }
        if (run.waiting) { run.waiting = NO; dispatch_semaphore_signal(run.continuation); }
        reply(0);
    }
}
- (void)pullAlignmentData:(uint64_t)client replyBlock:(void (^)(NSData *))reply { reply(nil); }
- (void)enroll:(int)type user:(unsigned int)user options:(NSDictionary *)options async:(BOOL)async
        client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    NSData *context = nativeInitialEnrollmentContext(type, user, 501, options);
    if (!context || !(nativePeerPermissions(self.connection) & NativePeerEnroll)) { reply(1); return; }
    ElanNativeEnrollmentRun *run = [ElanNativeEnrollmentRun new];
    run.client = client; run.context = context; run.presence = -1;
    @synchronized (controller) {
        if (controller.stopping || controller.busy || !controller.session || controller.session.invalidated ||
            controller.repository.current.records.count >= ElanCatalogMaximumIdentities) { reply(1); return; }
        controller.busy = YES; controller.current = self; controller.activeClient = client; cancelled = 0;
        self.enrollment = run;
    }
    dispatch_group_async(controller.captureGroup, controller.captureQueue, ^{
        @autoreleasepool {
            BOOL accepted = NO, saved = NO, replyAttempted = NO;
            unsigned terminalStatus = 66;
            void (*previousEvent)(ElanCaptureEvent) = capture_event;
            int (*previousCancel)(void) = capture_should_cancel;
            @try {
                if (![self authorizeEnrollment:run]) { replyAttempted = YES; reply(1); return; }
                accepted = YES; replyAttempted = YES; reply(0);
                ElanFingerprintMatcher *matcher = controller.matcher;
                enrollmentCaptureOwner = self; capture_event = enrollmentCaptureEvent; capture_should_cancel = enrollmentShouldCancel;
                run.calibrating = YES;
                BOOL prepared = prepareEnrollmentBackground(&sensor, matcher.background != nil);
                run.calibrating = NO;
                ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=1 prepared=%d capture_result=%u existing_records=%lu",
                    (int)prepared, (unsigned)capture_last_result, (unsigned long)controller.repository.current.records.count);
                if (!prepared) {
                    if (capture_last_result == ElanCaptureTimedOut) terminalStatus = 68;
                    return;
                }
                NSData *background = [NSData dataWithBytes:sensor.bg length:(size_t)sensor.w * sensor.hgt * 2];
                ELAN_NATIVE_CALIBRATED_BACKGROUND(background);
                @synchronized (controller) {
                    if (![self isCurrentEnrollment:run]) return;
                    run.draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:matcher background:background targetCount:MinPrints error:NULL];
                }
                if (!run.draft) return;
                if (![self waitForEnrollmentContinuation:run]) {
                    if (!cancelled && !controller.stopping) terminalStatus = 68;
                    return;
                }
                unsigned retries = 0;
                BOOL sensorAlreadyClear = YES;
                while (!run.draft.ready && !cancelled && !controller.stopping) {
                    ElanpressFeatures *features = ELAN_NATIVE_CAPTURE_SAMPLE(&sensor, sensorAlreadyClear);
                    sensorAlreadyClear = NO;
                    BOOL captured = features != NULL;
                    unsigned score = 0;
                    ElanEnrollmentSampleResult sample = ElanEnrollmentSampleInvalid;
                    @try {
                        @synchronized (controller) {
                            if (features && [self isCurrentEnrollment:run]) sample = [run.draft appendFeatures:features score:&score];
                        }
                    } @finally {
                        if (features) { wipe(features->kp, features->n * sizeof(*features->kp)); elanpress_features_free(features); }
                    }
                    printf("ELAN_PROVIDER enrollment_sample count=%lu result=%u capture=%u score=%u\n",
                        run.draft.sampleCount, sample, capture_last_result, score);
                    ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=2 count=%lu result=%u capture=%u score=%u retries=%u",
                        (unsigned long)run.draft.sampleCount, (unsigned)sample, (unsigned)capture_last_result, score, retries);
                    if (cancelled || controller.stopping) return;
                    if (!captured && capture_last_result != ElanCaptureImageRejected) {
                        if (capture_last_result == ElanCaptureTimedOut) terminalStatus = 68;
                        return;
                    }
                    if (sample == ElanEnrollmentSampleAlreadyEnrolled) {
                        if (run.draft.sampleCount == 0) { terminalStatus = 67; return; }
                        [[self enrollmentRemote] statusMessage:98 client:run.client];
                    } else if (sample == ElanEnrollmentSampleMismatch) {
                        [[self enrollmentRemote] statusMessage:98 client:run.client];
                    }
                    if (sample == ElanEnrollmentSampleAccepted) {
                        retries = 0;
                        if (![self waitForEnrollmentContinuation:run]) {
                            if (!cancelled && !controller.stopping) terminalStatus = 68;
                            return;
                        }
                    } else if (++retries >= 12) {
                        terminalStatus = 67;
                        return;
                    }
                }
                @synchronized (controller) {
                    if (![self authorizeEnrollment:run]) return;
                    NSString *name = [NSString stringWithFormat:@"指纹 %lu", controller.repository.current.records.count + 1];
                    NSError *error = nil;
                    NSUInteger committedSampleCount = run.draft.sampleCount;
                    ElanFingerprintRecord *record = [run.draft commitWithSession:controller.session uuid:NSUUID.UUID name:name error:&error];
                    if (controller.session.invalidated) controller.stopping = YES;
                    if (!record) {
                        printf("ELAN_PROVIDER enrollment_commit_error=%s:%ld\n", error.domain.UTF8String, (long)error.code);
                        ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=3 commit_failed=1 code=%ld", (long)error.code);
                        return;
                    }
                    saved = YES;
                    ELAN_NATIVE_COMMIT_RECEIPT(record, committedSampleCount, NO);
                    printf("ELAN_PROVIDER enrollment_saved uuid=%s count=%lu\n", record.uuid.UUIDString.UTF8String,
                        controller.repository.current.records.count);
                    ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=3 saved=1 total_records=%lu",
                        (unsigned long)controller.repository.current.records.count);
                    id remote = [self enrollmentRemote];
                    self.enrollment = nil; controller.current = nil; controller.activeClient = 0; controller.busy = NO;
                    [remote enrollResult:nativeIdentityForRecord(record, 501) details:@{} client:client];
                }
            } @catch (NSException *exception) {
                printf("ELAN_PROVIDER enrollment_exception=%s\n", exception.name.UTF8String);
                if (!replyAttempted) { replyAttempted = YES; reply(1); }
            } @finally {
                unsigned finalStatus = cancelled ? 99 : terminalStatus;
                @synchronized (controller) {
                    @try {
                        if (accepted && !saved && !controller.session.commitOutcomeUnknown)
                            [[self enrollmentRemote] statusMessage:finalStatus client:client];
                    } @catch (NSException *exception) {
                        printf("ELAN_PROVIDER enrollment_terminal_notification_failed=%s saved=%d\n", exception.name.UTF8String, saved);
                    } @finally {
                    [run.draft cancel]; run.context = nil; run.draft = nil;
                    NSData *background = controller.matcher.background;
                    if (sensor.bg) {
                        if (background) memcpy(sensor.bg, background.bytes, background.length);
                        else memset(sensor.bg, 0, (size_t)sensor.w * sensor.hgt * 2);
                    }
                    enrollmentCaptureOwner = nil; capture_event = previousEvent; capture_should_cancel = previousCancel;
                    self.enrollment = nil; controller.current = nil; controller.activeClient = 0; controller.busy = NO;
                    }
                }
                printf("ELAN_PROVIDER enrollment_end accepted=%d saved=%d cancelled=%d status=%u commit_unknown=%d\n",
                    accepted, saved, cancelled, finalStatus, controller.session.commitOutcomeUnknown);
                ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=4 accepted=%d saved=%d cancelled=%d status=%u",
                    (int)accepted, (int)saved, (int)cancelled, finalStatus);
            }
        }
    });
}

- (void)extendEnrollment:(id)query options:(NSDictionary *)options client:(uint64_t)client replyBlock:(void (^)(int))reply {
    ElanProviderController *controller = self.controller;
    id context = options[@"BKOptionAuthWithCredentialSet"];
    NSUUID *uuid = nativeExtendedEnrollmentUUID(query, options);
    if (!uuid || !(nativePeerPermissions(self.connection) & NativePeerEnroll)) { reply(1); return; }
    ElanNativeEnrollmentRun *run = [ElanNativeEnrollmentRun new];
    run.client = client; run.context = context; run.presence = -1;
    @synchronized (controller) {
        if (controller.stopping || controller.busy || !controller.session || controller.session.invalidated) { reply(1); return; }
        run.supplement = [[ElanFingerprintSupplement alloc] initWithMatcher:controller.matcher uuid:uuid error:NULL];
        if (!run.supplement || run.supplement.sampleCount >= MaxPrints) { reply(1); return; }
        controller.busy = YES; controller.current = self; controller.activeClient = client; cancelled = 0;
        self.enrollment = run;
    }
    dispatch_group_async(controller.captureGroup, controller.captureQueue, ^{
        @autoreleasepool {
            BOOL accepted = NO, replyAttempted = NO;
            unsigned added = 0, retries = 0;
            void (*previousEvent)(ElanCaptureEvent) = capture_event;
            int (*previousCancel)(void) = capture_should_cancel;
            @try {
                if (![self authorizeEnrollment:run]) { replyAttempted = YES; reply(1); return; }
                accepted = YES; replyAttempted = YES; reply(0);
                enrollmentCaptureOwner = self; capture_event = enrollmentCaptureEvent; capture_should_cancel = enrollmentShouldCancel;
                while (!cancelled && !controller.stopping) {
                    if (run.supplement.sampleCount >= MaxPrints) {
                        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
                        while (!cancelled && !controller.stopping && deadline.timeIntervalSinceNow > 0) usleep(100000);
                        return;
                    }
                    ElanpressFeatures *features = ELAN_NATIVE_CAPTURE_SAMPLE(&sensor, NO);
                    if (!features) {
                        if (capture_last_result == ElanCaptureImageRejected && ++retries < 12) continue;
                        return;
                    }
                    unsigned score = 0;
                    ElanEnrollmentSampleResult result = ElanEnrollmentSampleInvalid;
                    NSError *error = nil;
                    @try {
                        @synchronized (controller) {
                            if (![self authorizeEnrollment:run]) return;
                            result = [run.supplement appendFeatures:features toSession:controller.session score:&score error:&error];
                            if (controller.session.invalidated) controller.stopping = YES;
                            if (result == ElanEnrollmentSampleAccepted) {
                                retries = 0; added++;
                                ELAN_NATIVE_COMMIT_RECEIPT(run.supplement.record, run.supplement.sampleCount, YES);
                                [[self enrollmentRemote] matchResult:nativeIdentityForRecord(run.supplement.record, 501) details:@{} client:client];
                            } else if (result == ElanEnrollmentSampleMismatch) {
                                [[self enrollmentRemote] statusMessage:98 client:client];
                            }
                        }
                    } @finally {
                        wipe(features->kp, features->n * sizeof(*features->kp)); elanpress_features_free(features);
                    }
                    printf("ELAN_PROVIDER supplement_sample count=%lu result=%u score=%u error=%s:%ld\n",
                        run.supplement.sampleCount, result, score, error.domain.UTF8String ?: "none", (long)error.code);
                    ELAN_NATIVE_ENROLL_LOG("ELAN_ENROLL stage=5 count=%lu result=%u score=%u retries=%u",
                        (unsigned long)run.supplement.sampleCount, (unsigned)result, score, retries);
                    if (result == ElanEnrollmentSampleInvalid || (result != ElanEnrollmentSampleAccepted && ++retries >= 12)) return;
                }
            } @catch (NSException *exception) {
                printf("ELAN_PROVIDER supplement_exception=%s\n", exception.name.UTF8String);
                if (!replyAttempted) { replyAttempted = YES; reply(1); }
            } @finally {
                @synchronized (controller) {
                    @try {
                        if (accepted && !controller.session.commitOutcomeUnknown)
                            [[self enrollmentRemote] statusMessage:cancelled ? 99 : 66 client:client];
                    } @catch (NSException *exception) {
                        printf("ELAN_PROVIDER supplement_terminal_notification_failed=%s committed_samples=%u\n", exception.name.UTF8String, added);
                    } @finally {
                    run.context = nil; run.supplement = nil;
                    enrollmentCaptureOwner = nil; capture_event = previousEvent; capture_should_cancel = previousCancel;
                    self.enrollment = nil; controller.current = nil; controller.activeClient = 0; controller.busy = NO;
                    }
                }
                printf("ELAN_PROVIDER supplement_end accepted=%d added=%u cancelled=%d commit_unknown=%d\n", accepted, added, cancelled, controller.session.commitOutcomeUnknown);
            }
        }
    });
}
