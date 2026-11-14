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
        if (run.calibrating && event == ElanCaptureAwaitRelease) [self reportEnrollmentTouch:YES];
        else if (event == ElanCaptureReady) [self reportEnrollmentTouch:NO];
        else if (event == ElanCaptureTooShort || event == ElanCaptureLowQuality)
            [[self enrollmentRemote] statusMessage:98 client:run.client];
    }
}
- (BOOL)authorizeEnrollment:(ElanNativeEnrollmentRun *)run {
    ElanProviderController *controller = self.controller;
    @synchronized (controller) {
        if (![self isCurrentEnrollment:run] || !(nativePeerPermissions(self.connection) & NativePeerEnroll) || ![controller sessionIsCurrent]) return NO;
        int status = elanProviderAuthorizeEnrollment(controller.broker, ++controller.sequence, run.context.bytes);
        printf("ELAN_PROVIDER enrollment_authorization status=%d\n", status);
        return status == 0;
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
    id context = options[@"BKOptionAuthWithCredentialSet"];
    if (type != 1 || user != 501 || ![context isKindOfClass:NSData.class] || [context length] != 16 ||
        !(nativePeerPermissions(self.connection) & NativePeerEnroll)) { reply(1); return; }
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
            BOOL accepted = NO, saved = NO;
            void (*previousEvent)(ElanCaptureEvent) = capture_event;
            int (*previousCancel)(void) = capture_should_cancel;
            @try {
                if (![self authorizeEnrollment:run]) { reply(1); return; }
                accepted = YES; reply(0);
                ElanFingerprintMatcher *matcher = controller.matcher;
                enrollmentCaptureOwner = self; capture_event = enrollmentCaptureEvent; capture_should_cancel = enrollmentShouldCancel;
                run.calibrating = YES;
                if (!prepareEnrollmentBackground(&sensor, matcher.background != nil)) return;
                run.calibrating = NO;
                NSData *background = [NSData dataWithBytes:sensor.bg length:(size_t)sensor.w * sensor.hgt * 2];
                @synchronized (controller) {
                    if (![self isCurrentEnrollment:run]) return;
                    run.draft = [[ElanFingerprintEnrollment alloc] initWithMatcher:matcher background:background targetCount:MinPrints error:NULL];
                }
                if (!run.draft || ![self waitForEnrollmentContinuation:run]) return;
                unsigned retries = 0;
                while (!run.draft.ready && !cancelled && !controller.stopping) {
                    ElanpressFeatures *features = capture(&sensor);
                    BOOL captured = features != NULL;
                    unsigned score = 0;
                    ElanEnrollmentSampleResult sample = ElanEnrollmentSampleInvalid;
                    @synchronized (controller) {
                        if (features && [self isCurrentEnrollment:run]) sample = [run.draft appendFeatures:features score:&score];
                    }
                    if (features) { wipe(features->kp, features->n * sizeof(*features->kp)); elanpress_features_free(features); }
                    printf("ELAN_PROVIDER enrollment_sample count=%lu result=%u capture=%u score=%u\n",
                        run.draft.sampleCount, sample, capture_last_result, score);
                    if (cancelled || controller.stopping) return;
                    if (sample == ElanEnrollmentSampleAlreadyEnrolled || (!captured && capture_last_result != ElanCaptureImageRejected)) return;
                    if (sample == ElanEnrollmentSampleAccepted) retries = 0;
                    else if (++retries >= 6) return;
                    if (![self waitForEnrollmentContinuation:run]) return;
                }
                @synchronized (controller) {
                    if (![self authorizeEnrollment:run]) return;
                    NSString *name = [NSString stringWithFormat:@"指纹 %lu", controller.repository.current.records.count + 1];
                    NSError *error = nil;
                    ElanFingerprintRecord *record = [run.draft commitWithSession:controller.session uuid:NSUUID.UUID name:name error:&error];
                    if (controller.session.invalidated) controller.stopping = YES;
                    if (!record) { printf("ELAN_PROVIDER enrollment_commit_error=%s:%ld\n", error.domain.UTF8String, (long)error.code); return; }
                    saved = YES;
                    printf("ELAN_PROVIDER enrollment_saved uuid=%s count=%lu\n", record.uuid.UUIDString.UTF8String,
                        controller.repository.current.records.count);
                    [[self enrollmentRemote] enrollResult:nativeIdentityForRecord(record, 501) details:@{} client:client];
                }
            } @catch (NSException *exception) {
                printf("ELAN_PROVIDER enrollment_exception=%s\n", exception.name.UTF8String);
                if (!accepted) reply(1);
            } @finally {
                @synchronized (controller) {
                    if (accepted && !saved) [[self enrollmentRemote] statusMessage:cancelled ? 99 : 66 client:client];
                    [run.draft cancel]; run.context = nil; run.draft = nil;
                    NSData *background = controller.matcher.background;
                    if (background) memcpy(sensor.bg, background.bytes, background.length);
                    else memset(sensor.bg, 0, (size_t)sensor.w * sensor.hgt * 2);
                    enrollmentCaptureOwner = nil; capture_event = previousEvent; capture_should_cancel = previousCancel;
                    self.enrollment = nil; controller.current = nil; controller.activeClient = 0; controller.busy = NO;
                }
                printf("ELAN_PROVIDER enrollment_end accepted=%d saved=%d cancelled=%d\n", accepted, saved, cancelled);
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
            BOOL accepted = NO;
            unsigned added = 0, retries = 0;
            void (*previousEvent)(ElanCaptureEvent) = capture_event;
            int (*previousCancel)(void) = capture_should_cancel;
            @try {
                if (![self authorizeEnrollment:run]) { reply(1); return; }
                accepted = YES; reply(0);
                enrollmentCaptureOwner = self; capture_event = enrollmentCaptureEvent; capture_should_cancel = enrollmentShouldCancel;
                while (!cancelled && !controller.stopping) {
                    if (run.supplement.sampleCount >= MaxPrints) {
                        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
                        while (!cancelled && !controller.stopping && deadline.timeIntervalSinceNow > 0) usleep(100000);
                        return;
                    }
                    ElanpressFeatures *features = capture(&sensor);
                    if (!features) {
                        if (capture_last_result == ElanCaptureImageRejected && ++retries < 6) continue;
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
                    if (result == ElanEnrollmentSampleInvalid || (result != ElanEnrollmentSampleAccepted && ++retries >= 6)) return;
                }
            } @catch (NSException *exception) {
                printf("ELAN_PROVIDER supplement_exception=%s\n", exception.name.UTF8String);
                if (!accepted) reply(1);
            } @finally {
                @synchronized (controller) {
                    if (accepted) [[self enrollmentRemote] statusMessage:cancelled ? 99 : 66 client:client];
                    run.context = nil; run.supplement = nil;
                    enrollmentCaptureOwner = nil; capture_event = previousEvent; capture_should_cancel = previousCancel;
                    self.enrollment = nil; controller.current = nil; controller.activeClient = 0; controller.busy = NO;
                }
                printf("ELAN_PROVIDER supplement_end accepted=%d added=%u cancelled=%d\n", accepted, added, cancelled);
            }
        }
    });
}
