typedef enum { FixtureGood, FixtureShort, FixtureLowQuality, FixtureIOError,
    FixtureCancelled, FixtureBackground, FixtureBackgroundError, FixtureBackgroundTouch } CaptureFixtureMode;
static CaptureFixtureMode captureFixtureMode;
static unsigned captureFixtureFrames;
static unsigned captureFixtureEvents[ElanCaptureCalibrating + 1];
static unsigned short captureFixturePixels[144 * 64];
static void recordCaptureEvent(ElanCaptureEvent event) { captureFixtureEvents[event]++; }
static void quietCaptureText(const char *text) { (void)text; }
static int fixtureCancelled(void) { return captureFixtureMode == FixtureCancelled && captureFixtureFrames >= 2; }
static int readCaptureFixture(Sensor *s, unsigned short *pixels) {
    unsigned n = ++captureFixtureFrames;
    if (captureFixtureMode == FixtureIOError || (captureFixtureMode == FixtureBackgroundError && n == 5)) return 0;
    if (captureFixtureMode >= FixtureBackground) {
        for (int i = 0; i < s->w * s->hgt; i++) pixels[i] = n <= 3 ? 1000 : 1012;
        if (n == 4) {
            for (int i = 0; i < s->w * s->hgt; i++)
                pixels[i] = captureFixtureMode == FixtureBackgroundTouch ? (i < s->w * s->hgt / 5 ? 3000 : 1000) : 5000;
        }
        return 1;
    }
    if (n <= 4 || (captureFixtureMode == FixtureShort && n >= 6)) {
        memcpy(pixels, s->bg, (size_t)s->w * s->hgt * 2); return 1;
    }
    for (int i = 0; i < s->w * s->hgt; i++)
        pixels[i] = captureFixtureMode == FixtureLowQuality ? 5000 : captureFixturePixels[i];
    usleep(80000);
    return 1;
}
static void resetCaptureFixture(CaptureFixtureMode mode) {
    captureFixtureMode = mode; captureFixtureFrames = 0; cancelled = 0;
    memset(captureFixtureEvents, 0, sizeof(captureFixtureEvents));
}
static int enrollmentCaptureSelfTest(void) {
    Sensor fixture = {.w = 144, .hgt = 64, .pid = 0x0c1a};
    unsigned short background[144 * 64]; fixture.bg = background;
    uint32_t random = 13;
    for (size_t i = 0; i < 144 * 64; i++) {
        background[i] = 1000; random = random * 1664525u + 1013904223u;
        captureFixturePixels[i] = 1000 + (random >> 24) * 32;
    }
    void (*oldEvent)(ElanCaptureEvent) = capture_event;
    void (*oldStatus)(const char *) = capture_status;
    int (*oldCancel)(void) = capture_should_cancel;
    unsigned oldTimeout = capture_timeout_seconds;
    capture_event = recordCaptureEvent; capture_status = quietCaptureText; capture_should_cancel = fixtureCancelled;
    capture_timeout_seconds = 5;
    int passed = 1;
    resetCaptureFixture(FixtureGood);
    ElanpressFeatures *features = captureWithReader(&fixture, readCaptureFixture);
    passed &= features && features->n >= ELANPRESS_MATCH_MIN_PAIRS && capture_last_result == ElanCaptureSucceeded &&
        captureFixtureEvents[ElanCaptureAwaitRelease] == 1 && captureFixtureEvents[ElanCaptureReady] == 1 &&
        captureFixtureEvents[ElanCaptureTouchDetected] == 1 && captureFixtureEvents[ElanCaptureSampleReady] == 1;
    elanpress_features_free(features);
    resetCaptureFixture(FixtureShort);
    features = captureWithReader(&fixture, readCaptureFixture);
    passed &= !features && capture_last_result == ElanCaptureImageRejected && captureFixtureEvents[ElanCaptureTooShort] == 1;
    elanpress_features_free(features);
    resetCaptureFixture(FixtureLowQuality);
    features = captureWithReader(&fixture, readCaptureFixture);
    passed &= !features && capture_last_result == ElanCaptureImageRejected && captureFixtureEvents[ElanCaptureLowQuality] == 1;
    elanpress_features_free(features);
    resetCaptureFixture(FixtureIOError);
    features = captureWithReader(&fixture, readCaptureFixture);
    passed &= !features && capture_last_result == ElanCaptureDeviceError;
    elanpress_features_free(features);
    resetCaptureFixture(FixtureCancelled);
    features = captureWithReader(&fixture, readCaptureFixture);
    passed &= !features && capture_last_result == ElanCaptureCancelled && captureFixtureFrames == 2;
    elanpress_features_free(features);
    resetCaptureFixture(FixtureGood); capture_timeout_seconds = 0;
    features = captureWithReader(&fixture, readCaptureFixture);
    passed &= !features && capture_last_result == ElanCaptureTimedOut && !captureFixtureFrames;
    elanpress_features_free(features); capture_timeout_seconds = 5;
    printf("CAPTURE_EVENTS sample_lift_quality_device_cancel_timeout=%d sensor_opened=0\n", passed);
    resetCaptureFixture(FixtureBackground);
    passed &= prepareEnrollmentBackgroundWithReader(&fixture, 0, 1000, readCaptureFixture) &&
        captureFixtureFrames == 16 && background[0] == 1012 && captureFixtureEvents[ElanCaptureAwaitRelease] == 1;
    for (size_t i = 0; i < 144 * 64; i++) background[i] = 1000;
    resetCaptureFixture(FixtureBackgroundTouch);
    passed &= prepareEnrollmentBackgroundWithReader(&fixture, 1, 1000, readCaptureFixture) &&
        captureFixtureFrames == 16 && background[0] == 1012 && captureFixtureEvents[ElanCaptureAwaitRelease] == 1;
    resetCaptureFixture(FixtureBackgroundError);
    passed &= !prepareEnrollmentBackgroundWithReader(&fixture, 0, 1000, readCaptureFixture) &&
        capture_last_result == ElanCaptureDeviceError && background[0] == 1012;
    resetCaptureFixture(FixtureCancelled);
    passed &= !prepareEnrollmentBackgroundWithReader(&fixture, 1, 1000, readCaptureFixture) &&
        capture_last_result == ElanCaptureCancelled && background[0] == 1012;
    printf("CAPTURE_BACKGROUND factory_mean_checked=1 existing_touch_checked=1 interrupted_sequence_reset=1 previous_preserved_on_failure=1 passed=%d\n", passed);
    capture_event = oldEvent; capture_status = oldStatus; capture_should_cancel = oldCancel;
    capture_timeout_seconds = oldTimeout; cancelled = 0;
    return passed ? 0 : 1;
}
